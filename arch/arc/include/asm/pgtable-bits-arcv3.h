/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 Synopsys, Inc. (www.synopsys.com)
 */


#ifndef _ASM_ARC_PGTABLE_BITS_ARCV3_H
#define _ASM_ARC_PGTABLE_BITS_ARCV3_H

#include <linux/sizes.h>

#define _PAGE_VALID		(_UL(1) <<  0)
#define _PAGE_LINK		(_UL(1) <<  1)
#define _PAGE_MEMATTR_MASK	(_UL(7) <<  2)
#define _PAGE_MEMATTR(idx)	((idx) << 2)

/* PAGE_USER is only relevant for data r/w accesses  */
#define _PAGE_AP_U_N_K		(_UL(1) <<  6)  /* 1: User + Kernel, 0: Kernel only) */
#define _PAGE_AP_READONLY	(_UL(1) <<  7)  /* 1: Read only, 0: Read + Write) */

#define __SHR_OUTER		2
#define __SHR_INNER		3
#define _PAGE_SHARED_OUTER	(_UL(__SHR_OUTER) <<  8)  /* Outer Shareable */
#define _PAGE_SHARED_INNER	(_UL(__SHR_INNER) <<  8)  /* Inner Shareable */

#define _PAGE_ACCESSED		(_UL(1) << 10)  /* software managed, exception if clear */
#define _PAGE_NOTGLOBAL		(_UL(1) << 11)  /* ASID */

#define _PAGE_DIRTY		(_UL(1) << 51)  /* software managed */
#define _PAGE_NOTEXEC_K		(_UL(1) << 53)  /* Execute User */
#define _PAGE_NOTEXEC_U		(_UL(1) << 54)  /* Execute Kernel */

#define _PAGE_SPECIAL		(_UL(1) << 55)

/* TBD: revisit if this needs to be standalone for PROT_NONE */
#define _PAGE_PRESENT		_PAGE_VALID

/*
 * PAGE_LINK indicates to hw walker to keep going down.
 *  - Set for all intermediate Table Descriptors (pgd, pud, pmd)
 *  - Set for last level Table descriptor (ptr) pointing to 4KB page frame
 *  - Not set for "Block descriptors", where intermediate levels point to
 *    bigger page frames.
 */

#define _PAGE_TABLE		(_PAGE_VALID | _PAGE_LINK)

#define MEMATTR_NORMAL		0x69
#define MEMATTR_UNCACHED	0x01
#define MEMATTR_VOLATILE	0x00 /* Uncached + No Early Write Ack + Strict Ordering */

#define MEMATTR_IDX_NORMAL	0
#define MEMATTR_IDX_UNCACHED	1
#define MEMATTR_IDX_VOLATILE	2

/* Read is always set since AP is specified as RO; !RO == R+W */
#define _PAGE_BASE	(_PAGE_VALID        | _PAGE_LINK      |	\
			 _PAGE_AP_READONLY  | 			\
			 _PAGE_NOTEXEC_U    | _PAGE_NOTEXEC_K |	\
			 _PAGE_AP_U_N_K     | _PAGE_NOTGLOBAL |	\
			 _PAGE_ACCESSED     |			\
			 _PAGE_SHARED_INNER |			\
			 _PAGE_MEMATTR(MEMATTR_IDX_NORMAL))

/* Exec implies Read since Read is always set */
#define _PAGE_RW	(_PAGE_BASE & ~_PAGE_AP_READONLY)
#define _PAGE_RX	(_PAGE_BASE & ~_PAGE_NOTEXEC_U)
#define _PAGE_RWX	(_PAGE_BASE & ~_PAGE_AP_READONLY  & ~_PAGE_NOTEXEC_U)

/* TBD: kernel is RWX by default, split it to code/data */
#define _PAGE_KERNEL	(_PAGE_TABLE        |			\
			 /* writable */				\
			 _PAGE_NOTEXEC_U    | 	/* exec k */	\
			 /* AP kernel only  |      global */	\
			 _PAGE_ACCESSED     |			\
			 _PAGE_SHARED_INNER |			\
			 _PAGE_MEMATTR(MEMATTR_IDX_NORMAL))

#define PAGE_NONE	__pgprot(_PAGE_BASE)	/* TBD */
#define PAGE_TABLE	__pgprot(_PAGE_TABLE)
#define PAGE_KERNEL	__pgprot(_PAGE_KERNEL)
#define PAGE_KERNEL_BLK	__pgprot(_PAGE_KERNEL & ~_PAGE_LINK)

#define PAGE_R		__pgprot(_PAGE_BASE)
#define PAGE_RW		__pgprot(_PAGE_RW)
#define PAGE_RX		__pgprot(_PAGE_RX)
#define PAGE_RWX	__pgprot(_PAGE_RWX)

	/* xwr */
#define __P000		PAGE_NONE
#define __P001		PAGE_R
#define __P010		PAGE_R
#define __P011		PAGE_R
#define __P100		PAGE_RX
#define __P101		PAGE_RX
#define __P110		PAGE_RX
#define __P111		PAGE_RX

#define __S000		PAGE_NONE
#define __S001		PAGE_R
#define __S010		PAGE_RW
#define __S011		PAGE_RW
#define __S100		PAGE_RX
#define __S101		PAGE_RX
#define __S110		PAGE_RWX
#define __S111		PAGE_RWX

#ifndef __ASSEMBLY__

#define pgprot_noncached(prot)	__pgprot((pgprot_val(prot) & ~_PAGE_MEMATTR_MASK) | \
					  _PAGE_MEMATTR(MEMATTR_IDX_UNCACHED))

#define pte_write(pte)		(!(pte_val(pte) & _PAGE_AP_READONLY))
#define pte_dirty(pte)		(pte_val(pte) & _PAGE_DIRTY)
#define pte_young(pte)		(pte_val(pte) & _PAGE_ACCESSED)
#define pte_special(pte) 	(pte_val(pte) & _PAGE_SPECIAL)

#define PTE_BIT_FUNC(fn, op) \
	static inline pte_t pte_##fn(pte_t pte) { pte_val(pte) op; return pte; }

PTE_BIT_FUNC(wrprotect,	|=  (_PAGE_AP_READONLY));
PTE_BIT_FUNC(mkwrite,	&= ~(_PAGE_AP_READONLY));
PTE_BIT_FUNC(mkclean,	&= ~(_PAGE_DIRTY));
PTE_BIT_FUNC(mkdirty,	|=  (_PAGE_DIRTY));
PTE_BIT_FUNC(mkold,	&= ~(_PAGE_ACCESSED));
PTE_BIT_FUNC(mkyoung,	|=  (_PAGE_ACCESSED));
PTE_BIT_FUNC(mkspecial,	|=  (_PAGE_SPECIAL));

static inline pte_t pte_modify(pte_t pte, pgprot_t newprot)
{
	// TBD: PAGE_CHG_MASK
	return __pte((pte_val(pte) & _PAGE_SPECIAL) | pgprot_val(newprot));
}

static inline void set_pte_at(struct mm_struct *mm, unsigned long addr,
			      pte_t *ptep, pte_t pteval)
{
	set_pte(ptep, pteval);
}

/*
 * Encode and decode a swap entry
 *
 * Format of swap PTE:
 *	bits 0-1:	_PAGE_VALID (must be zero)
 *	bits 2-7:	swap type
 *	bits 8-57:	swap offset
 *	bit  58:	PROT_NONE (must be zero)
 *
 * Note: swap bits needed even if !CONFIG_SWAP
 */
#define __SWP_TYPE_SHIFT	2
#define __SWP_TYPE_BITS		6
#define __SWP_OFFSET_BITS	50
#define __SWP_TYPE_MASK		((1UL << __SWP_TYPE_BITS) - 1)
#define __SWP_OFFSET_SHIFT	(__SWP_TYPE_BITS + __SWP_TYPE_SHIFT)
#define __SWP_OFFSET_MASK	((1UL << __SWP_OFFSET_BITS) - 1)

#define __swp_type(x)		(((x).val >> __SWP_TYPE_SHIFT) & __SWP_TYPE_MASK)
#define __swp_offset(x)		(((x).val >> __SWP_OFFSET_SHIFT) & __SWP_OFFSET_MASK)
#define __swp_entry(type,offset) ((swp_entry_t) { ((type) << __SWP_TYPE_SHIFT) | ((offset) << __SWP_OFFSET_SHIFT) })

#define __pte_to_swp_entry(pte)	((swp_entry_t) { pte_val(pte) })
#define __swp_entry_to_pte(swp)	((pte_t) { (swp).val })

void update_mmu_cache(struct vm_area_struct *vma, unsigned long address,
		      pte_t *ptep);

#endif /* __ASSEMBLY__ */

#endif
