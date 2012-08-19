/*******************************************************************************

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

#ifndef __PLAT_IRQ_H
#define __PLAT_IRQ_H

#ifdef CONFIG_SMP
#define NR_IRQS 32
#else
#define NR_IRQS 16
#endif

#define TIMER0_INT      3
#define TIMER1_INT      4

#define UART0_IRQ       5

#ifdef CONFIG_SMP
#define IPI_IRQS_BASE	9
#endif

#endif
