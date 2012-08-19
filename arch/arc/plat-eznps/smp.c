/*******************************************************************************

  ARC700 Extensions for SMP
  Copyright(c) 2012 EZchip Technologies.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

*******************************************************************************/

#include <linux/smp.h>
#include <linux/interrupt.h>
#include <asm/irq.h>
#include <plat/smp.h>

static char smp_cpuinfo_buf[128];

/*
 *-------------------------------------------------------------------
 * Platform specific callbacks expected by arch SMP code
 *-------------------------------------------------------------------
 */

const char *arc_platform_smp_cpuinfo(void)
{
	sprintf(smp_cpuinfo_buf, "Extn [700-SMP]\t: On\n");

	return smp_cpuinfo_buf;
}

/*
 * After power-up, a non Master CPU needs to wait for Master to kick start it
 *
 * W/o hardware assist, it will busy-spin on a token which is eventually set
 * by Master, preferably from arc_platform_smp_wakeup_cpu(). Once token is
 * available it needs to jump to @first_lines_of_secondary (using inline asm).
 *
 * The XTL H/w module, however allows Master to directly set Other CPU's PC as
 * well as ability to start/stop them. This allows implementing this function
 * as a simple dead stop using "FLAG 1" insn.
 * As a hack for debugging (debugger will single-step over the FLAG insn), we
 * anyways wrap it in a self loop
 *
 * Alert: can NOT use stack here as it has not been determined/setup for CPU.
 *        If it turns out to be elaborate, it's better to code it in assembly
 */
void arc_platform_smp_wait_to_boot(int cpu)
{
	/* Secondary Halts self. Later master will set PC and clear halt bit */
	__asm__ __volatile__(
	"1:		\n"
	"	flag 1	\n"
	"	b 1b	\n");
}

/*
 * Master kick starting another CPU
 */
void arc_platform_smp_wakeup_cpu(int cpu, unsigned long pc)
{
	unsigned long *c_entry = (unsigned long *)CPU_SEC_ENTRY_POINT;
	unsigned long *halt = (unsigned long *)REG_CPU_HALT_CTL;

	/* setup the start PC */
	*c_entry = pc;

	/* Take the cpu out of Halt */
	*halt |= 1 << cpu;

}

/*
 * Any SMP specific init any CPU does when it comes up.
 * Here we setup the CPU to enable Inter-Processor-Interrupts
 * Called for each CPU
 * -Master      : init_IRQ()
 * -Other(s)    : start_kernel_secondary()
 */
void arc_platform_smp_init_cpu(void)
{
	int cpu = smp_processor_id();
	int irq;

	/* Check if CPU is configured for more than 16 interrupts */
	if (NR_IRQS <= 16 || get_hw_config_num_irq() <= 16)
		panic("[eznps] IRQ system can't support IPI\n");

	/* Attach the arch-common IPI ISR to our IPI IRQ */
	for (irq = 0; irq < NR_CPUS; irq++)
	{
		unsigned int tmp;
		/* using edge */
		tmp = read_aux_reg(AUX_ITRIGGER);
		write_aux_reg(AUX_ITRIGGER,
				tmp | (1 << (IPI_IRQS_BASE + irq)));

		if (cpu == 0) {
			int rc;

			rc = smp_ipi_irq_setup(cpu, IPI_IRQS_BASE + irq);
			if (rc)
				panic("IPI IRQ %d reg failed on BOOT cpu\n",
					 irq);
		}
		enable_percpu_irq(IPI_IRQS_BASE + irq, 0);
	}
}

void arc_platform_ipi_send(const struct cpumask *callmap)
{
	unsigned int cpu, this_cpu = smp_processor_id();

	for_each_cpu(cpu, callmap) {
		(*((volatile int*)(REGS_CPU_IPI(this_cpu)))) = (1 << cpu);
		(*((volatile int*)(REGS_CPU_IPI(this_cpu)))) = 0;
	}
}

void arc_platform_ipi_clear(int cpu, int irq)
{
	write_aux_reg(AUX_IPULSE, (1 << irq));
}

