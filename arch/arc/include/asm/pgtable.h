/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 */

#ifndef _ASM_ARC_PGTABLE_H
#define _ASM_ARC_PGTABLE_H

#include <linux/bits.h>

#include <asm/pgtable-levels.h>

#ifndef CONFIG_ARC_MMU_V6
#include <asm/pgtable-bits-arcv2.h>
#else
#include <asm/pgtable-bits-arcv3.h>
#endif

#include <asm/page.h>
#include <asm/mmu.h>

/*
 * Number of entries a user land program use.
 * TASK_SIZE is the maximum vaddr that can be used by a userland program.
 */
#define	USER_PTRS_PER_PGD	(TASK_SIZE / PGDIR_SIZE)

#ifndef __ASSEMBLY__

extern char empty_zero_page[PAGE_SIZE];
#define ZERO_PAGE(vaddr)	(virt_to_page(empty_zero_page))

extern pgd_t swapper_pg_dir[] __page_aligned_bss;
extern pud_t swapper_pud[] __page_aligned_bss;
extern pmd_t swapper_pmd[] __page_aligned_bss;

/* to cope with aliasing VIPT cache */
#define HAVE_ARCH_UNMAPPED_AREA

#endif /* __ASSEMBLY__ */

#endif
