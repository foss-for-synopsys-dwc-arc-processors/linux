/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004, 2007-2010, 2011-2012, 2019-20 Synopsys, Inc. (www.synopsys.com)
 *
 * MMUv3 (arc700) / MMUv4 (archs) are software page walked and software managed.
 * This file contains the TLB access registers and commands
 */

#ifndef _ASM_ARC_MMU_ARCV2_H
#define _ASM_ARC_MMU_ARCV2_H

/*
 * TLB Management regs
 */
#ifdef CONFIG_ARC_MMU_V3
#define ARC_REG_TLBPD0		0x405
#define ARC_REG_TLBPD1		0x406
#define ARC_REG_TLBPD1HI	0	/* Dummy: allows common code */
#define ARC_REG_TLBINDEX	0x407
#define ARC_REG_TLBCOMMAND	0x408
#define ARC_REG_PID		0x409
#define ARC_REG_SCRATCH_DATA0	0x418
#else
#define ARC_REG_TLBPD0		0x460
#define ARC_REG_TLBPD1		0x461
#define ARC_REG_TLBPD1HI	0x463
#define ARC_REG_TLBINDEX	0x464
#define ARC_REG_TLBCOMMAND	0x465
#define ARC_REG_PID		0x468
#define ARC_REG_SCRATCH_DATA0	0x46c
#endif

/* Bits in MMU PID reg */
#define __TLB_ENABLE		(1 << 31)
#define __PROG_ENABLE		(1 << 30)
#define MMU_ENABLE		(__TLB_ENABLE | __PROG_ENABLE)

/* Bits in TLB Index reg */
#define TLB_LKUP_ERR		0x80000000

#ifdef CONFIG_ARC_MMU_V3
#define TLB_DUP_ERR		(TLB_LKUP_ERR | 0x00000001)
#else
#define TLB_DUP_ERR		(TLB_LKUP_ERR | 0x40000000)
#endif

/*
 * TLB Commands
 */
#define TLBWrite    		0x1
#define TLBRead     		0x2
#define TLBGetIndex 		0x3
#define TLBProbe    		0x4
#define TLBWriteNI		0x5  /* write JTLB without inv uTLBs */
#define TLBIVUTLB		0x6  /* explicitly inv uTLBs */

#ifdef CONFIG_ARC_MMU_V4
#define TLBInsertEntry		0x7
#define TLBDeleteEntry		0x8
#endif

/* Mask/helpers for pte flags in TLB PDs */
#define PTE_BITS_IN_PD0		(_PAGE_GLOBAL | _PAGE_PRESENT | _PAGE_HW_SZ)
#define PTE_BITS_RWX		(_PAGE_EXECUTE | _PAGE_WRITE | _PAGE_READ)

#ifdef CONFIG_ARC_HAS_PAE40
#define PTE_BITS_NON_RWX_IN_PD1	(0xff00000000 | PAGE_MASK | _PAGE_CACHEABLE)
#else
#define PTE_BITS_NON_RWX_IN_PD1	(PAGE_MASK | _PAGE_CACHEABLE)
#endif

#ifndef __ASSEMBLY__

extern int pae40_exist_but_not_enab(void);

static inline int is_pae40_enabled(void)
{
	return IS_ENABLED(CONFIG_ARC_HAS_PAE40);
}

static void inline mmu_setup_asid(struct mm_struct *mm, unsigned long asid)
{
	write_aux_reg(ARC_REG_PID, asid | MMU_ENABLE);
}

static void inline mmu_setup_pgd(struct mm_struct *mm, void *pgd)
{
	/* PGD cached in MMU reg to avoid 3 mem lookups: task->mm->pgd */
#ifdef CONFIG_ISA_ARCV2
	write_aux_reg(ARC_REG_SCRATCH_DATA0, (unsigned int)pgd);
#endif
}

#endif

#endif
