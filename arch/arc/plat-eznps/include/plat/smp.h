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

#ifndef __PLAT_ARCFPGA_SMP_H
#define __PLAT_ARCFPGA_SMP_H

#ifdef CONFIG_SMP

#include <linux/types.h>
#include <asm/arcregs.h>

#define CPU_SEC_ENTRY_POINT		0xFFFFFFFC
#define CPU_REGS_BASE			0xC0002000
#define CPU_REGS_IPI_BASE		(CPU_REGS_BASE + 0xC0)
#define REGS_CPU_IPI(cpu)		(CPU_REGS_IPI_BASE+(cpu*4))
#define REG_CPU_RST_CTL			(CPU_REGS_BASE+0x14)
#define REG_CPU_HALT_CTL		(CPU_REGS_BASE+0x18)

#endif	/* CONFIG_SMP */

#endif
