/*******************************************************************************

  EZNPS Platform support code
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

#include <linux/types.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/console.h>
#include <linux/if_ether.h>
#include <linux/socket.h>
#include <asm/serial.h>
#include <plat/irq.h>
#include <plat/memmap.h>

/*----------------------- Platform Devices -----------------------------*/

#ifdef CONFIG_SERIAL_8250
#include <asm/io.h>
#include <linux/serial_8250.h>

static void arc_mem32_serial_out(struct uart_port *p, int offset, int value)
{
	offset =  offset << p->regshift;
	__raw_writel(value, p->membase + offset);
}

static unsigned int arc_mem32_serial_in(struct uart_port *p, int offset)
{
	offset = offset << p->regshift;
	return __raw_readl(p->membase + offset);
}

static struct plat_serial8250_port uart8250_data[] __initdata = {
	{
		.type = PORT_16550A,
		.irq = UART0_IRQ,
		.uartclk = CONFIG_ARC_PLAT_CLK,
		.flags = (UPF_FIXED_TYPE | UPF_SKIP_TEST) ,
		.membase = (void __iomem *)UART0_BASE,
#ifdef CONFIG_NPS_NSIM_VIRT_PERIP
		.iotype = UPIO_MEM,
#else
		.iotype = UPIO_MEM32,
		.regshift = 2,
		/* asm-generic/io.h always assume LE */
		.serial_out = arc_mem32_serial_out,
		.serial_in = arc_mem32_serial_in,
#endif
	},
	{ },
};

static struct platform_device arc_uart8250_dev __initdata = {
	.name = "serial8250",
	.id = PLAT8250_DEV_PLATFORM,
	.dev = {
		.platform_data = uart8250_data,
	}
};

#ifdef CONFIG_EARLY_PRINTK
static void __init prom_putchar(unsigned char c)
{
	void __iomem *base = (void __iomem *)(UART0_BASE);
	int timeout = 0xfff, i;

	/* check LSR TX_EMPTY bit */
	do {
#ifdef CONFIG_NPS_NSIM_VIRT_PERIP
		if (__raw_readb(base + 0x5) & 0x20)
#else
		if (__raw_readl(base + (0x5<<2)) & 0x20)
#endif
			break;
		/* slow down */
		for (i = 100; i > 0; i--)
			__asm__ __volatile__("nop");
	} while (--timeout);

#ifdef CONFIG_NPS_NSIM_VIRT_PERIP
	__raw_writeb(c, base + 0x00);
#else
	__raw_writel(c, base + 0x00);
#endif
	wmb();
}

static void __init
early_console_write(struct console *con, const char *s, unsigned n)
{
	while (n-- && *s) {
		if (*s == '\n')
			prom_putchar('\r');
		prom_putchar(*s);
		s++;
	}
}

static struct console early_console __initdata = {
	.name   = "early",
	.write  = early_console_write,
	.flags  = CON_PRINTBUFFER | CON_BOOT,
	.index  = -1
};
#endif	/* CONFIG_EARLY_PRINTK */
#endif	/* CONFIG_SERIAL_8250 */

/*
 * Early Platform Initialization called from setup_arch()
 */
void __init arc_platform_early_init(void)
{
	pr_info("[plat-eznps]: registering early dev resources\n");

#ifdef CONFIG_SERIAL_8250
#ifdef CONFIG_EARLY_PRINTK
	/* TBD: early_platform_add_devices */
	register_console(&early_console);
#endif	/* CONFIG_EARLY_PRINTK */

	/*
	 * This is to make sure that arc uart would be preferred console
	 * despite one/more of following:
	 *   -command line lacked "console=ttyS0" or
	 *   -CONFIG_VT_CONSOLE was enabled (for no reason whatsoever)
	 * Note that this needs to be done after above early console is reg,
	 * otherwise the early console never gets a chance to run.
	 */
	add_preferred_console("ttyS", 0, "115200");
#endif	/* CONFIG_SERIAL_8250 */
}


static struct platform_device *arc_devs[] __initdata = {
#if defined(CONFIG_SERIAL_8250)
	&arc_uart8250_dev,
#endif
};

int __init eznps_plat_init(void)
{
	pr_info("[plat-eznps]: registering device resources\n");

	platform_add_devices(arc_devs, ARRAY_SIZE(arc_devs));

	return 0;
}
arch_initcall(eznps_plat_init);

#ifdef CONFIG_EZNPS_NET
static int __init mac_addr_setup(char *mac)
{
	extern struct sockaddr mac_addr;

	int i, h, l;

	for (i = 0; i < ETH_ALEN; i++) {
		if (i != ETH_ALEN-1 && *(mac + 2) != ':')
			return 1;

		h = hex_to_bin(*mac++);
		if (h == -1)
			return 1;

		l = hex_to_bin(*mac++);
		if (l == -1)
			return 1;

		mac++;
		mac_addr.sa_data[i] = (h << 4) + l;
	}

	return 0;
}

__setup("mac=", mac_addr_setup);

static int  __init add_eznet(void)
{
	struct platform_device *pd;

	pd = platform_device_register_simple("eth", 0, NULL, 0);
	if (IS_ERR(pd))
		pr_err("Fail\n");

	return IS_ERR(pd) ? PTR_ERR(pd) : 0;
}
device_initcall(add_eznet);
#endif /* CONFIG_EZNPS_NET */
