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

#include <linux/sched/mm.h>

static void inline mmu_setup_asid(struct mm_struct *mm, unsigned long asid)
{
#ifdef CONFIG_64BIT
	unsigned long rtp0 = (asid << 48) | __pa(mm->pgd);

	BUG_ON(__pa(mm->pgd) >> 48);
	write_aux_64(ARC_REG_MMU_RTP0, rtp0);

#else
#error "Need to implement 2 SR ops"
#endif
}

static void inline mmu_setup_pgd(struct mm_struct *mm, pgd_t *pgd)
{
	/*
	 * Only called by switch_mm() which apriori calls get_new_mmu_context()
	 * which unconditionally calls mmu_setup_asid() to set the ASID
	 * Since on this MMU both ASID and pgd are in same register, we program
	 * both there and do nothing here.
	 */
}

#endif

#endif
