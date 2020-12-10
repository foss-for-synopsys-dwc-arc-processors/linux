/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * MMUv6 hardware page walked
 * This file contains the TLB access registers and commands
 */

#ifndef _ASM_ARC_MMUV6_H
#define _ASM_ARC_MMUV6_H

#define ARC_REG_MMU_CTRL	0x468
#define ARC_REG_MMU_RTP0	0x460
#define ARC_REG_MMU_RTP1	0x462
#define ARC_REG_MMU_TTBC	0x469
#define ARC_REG_MMU_FAULT_STS	0x46b
#define ARC_REG_MMU_MEM_ATTR	0x46a

#define ARC_REG_MMU_TLB_CMD	0x465
#define ARC_REG_MMU_TLB_DATA0	0x466
#define ARC_REG_MMU_TLB_DATA1	0x467

#ifndef __ASSEMBLY__

static void inline mmu_setup_asid(struct mm_struct *mm, unsigned long asid)
{
}

static void inline mmu_setup_pgd(struct mm_struct *mm, pgd_t *pgd)
{
}

#endif

#endif
