/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __ARC_ASM_CACHECTL_H
#define __ARC_ASM_CACHECTL_H

/*
 * ARC ABI flags defined for Android's finegrained cacheflush requirements
 */
#define CF_I_INV	0x0002
#define CF_D_FLUSH	0x0010
#define CF_D_FLUSH_INV	0x0020
#define CF_D_INV        0x0040
#define CF_D_L1   0x10000   /* Operation with L1$ */
#define CF_D_L2   0x20000   /* Operation with L2$ */
#define CF_D_PHY  0x40000   /* cache_flush syscall operates with phy addresses */

#define CF_DEFAULT	(CF_I_INV | CF_D_FLUSH)

/*
 * Standard flags expected by cacheflush system call users
 */
#define ICACHE	CF_I_INV
#define DCACHE	CF_D_FLUSH
#define BCACHE	(CF_I_INV | CF_D_FLUSH)

#endif
