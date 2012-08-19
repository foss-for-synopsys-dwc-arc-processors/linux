/*******************************************************************************

  EZNPS Platform IRQ hookups
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

#include <linux/interrupt.h>
#include <asm/irq.h>
#include <plat/memmap.h>

static void arc_mask_irq(struct irq_data *data)
{
	arch_mask_irq(data->irq);
}

static void arc_unmask_irq(struct irq_data *data)
{
	arch_unmask_irq(data->irq);
}

/*
 * There's no off-chip Interrupt Controller in the FPGA builds
 * Below sufficies a simple model for the on-chip controller, with
 * all interrupts being level triggered.
 */
static struct irq_chip eznps_chip = {
	.irq_mask	= arc_mask_irq,
	.irq_unmask	= arc_unmask_irq,
};

void __init plat_init_IRQ()
{
	int i;

	for (i = 0; i < NR_IRQS; i++)
		irq_set_chip_and_handler(i, &eznps_chip, handle_level_irq);

#ifdef CONFIG_SMP
	irq_set_chip_and_handler(TIMER0_INT, &eznps_chip, handle_percpu_irq);

	for (i = IPI_IRQS_BASE; i < IPI_IRQS_BASE + NR_CPUS; i++) {
		irq_set_percpu_devid(i);
		irq_set_chip_and_handler(i, &eznps_chip, handle_percpu_irq);
	}
#endif

	/*
	 * SMP Hack because UART IRQ hardwired to cpu0 (boot-cpu) but if the
	 * request_irq() comes from any other CPU, the low level IRQ unamsking
	 * essential for getting Interrupts won't be enabled on cpu0, locking
	 * up the UART state machine.
	 */
#ifdef CONFIG_SMP
	arch_unmask_irq(UART0_IRQ);
#endif
}
