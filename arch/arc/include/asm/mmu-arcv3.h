/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * MMUv6 hardware page walked
 * This file contains the TLB access registers and commands
 */

#ifndef _ASM_ARC_MMUV6_H
#define _ASM_ARC_MMUV6_H

#ifndef __ASSEMBLY__

static void inline mmu_setup_asid(struct mm_struct *mm, unsigned long asid)
{
}

static void inline mmu_setup_pgd(struct mm_struct *mm, pgd_t *pgd)
{
}

#endif

#endif
