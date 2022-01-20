/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 */
#ifndef __ASM_ARC_PAGE_H
#define __ASM_ARC_PAGE_H

#include <linux/const.h>

/* PAGE_SHIFT determines the page size */
#if defined(CONFIG_ARC_PAGE_SIZE_4K)
#define PAGE_SHIFT 12
#elif defined(CONFIG_ARC_PAGE_SIZE_16K)
#define PAGE_SHIFT 14
#elif defined(CONFIG_ARC_PAGE_SIZE_64K)
#define PAGE_SHIFT 16
#else
/*
 * Default 8k
 * done this way (instead of under CONFIG_ARC_PAGE_SIZE_8K) because adhoc
 * user code (busybox appletlib.h) expects PAGE_SHIFT to be defined w/o
 * using the correct uClibc header and in their build our autoconf.h is
 * not available
 */
#define PAGE_SHIFT 13
#endif

#define PAGE_SIZE	_BITUL(PAGE_SHIFT)	/* Default 8K */

/*
 * TODO: Only one kernel-user split for each MMU currently supported.
 */
#if defined(CONFIG_ARC_MMU_V6_48)
#define PAGE_OFFSET	_AC(0xffff000000000000, UL)
#elif defined(CONFIG_ARC_MMU_V6_52)
#define PAGE_OFFSET	_AC(0xfff0000000000000, UL)
#else
#define PAGE_OFFSET	_AC(0x80000000, UL)	/* Kernel starts at 2G onwrds */
#endif

#define PAGE_MASK	(~(PAGE_SIZE-1))

#ifdef __ASSEMBLY__
#define __pgprot(x)	(x)
#else

#define clear_page(paddr)		memset((paddr), 0, PAGE_SIZE)
#define copy_page(to, from)		memcpy((to), (from), PAGE_SIZE)

struct vm_area_struct;
struct page;

#define __HAVE_ARCH_COPY_USER_HIGHPAGE

void copy_user_highpage(struct page *to, struct page *from,
			unsigned long u_vaddr, struct vm_area_struct *vma);
void clear_user_page(void *to, unsigned long u_vaddr, struct page *page);

typedef struct {
#ifndef CONFIG_ARC_MMU_V6
	unsigned long pgd;
#else
	unsigned long long pgd;
#endif
} pgd_t;

#define pgd_val(x)	((x).pgd)
#define __pgd(x)	((pgd_t) { (x) })

#if CONFIG_PGTABLE_LEVELS > 3

typedef struct {
#ifndef CONFIG_ARC_MMU_V6
	unsigned long pud;
#else
	unsigned long long pud;
#endif
} pud_t;

#define pud_val(x)      	((x).pud)
#define __pud(x)        	((pud_t) { (x) })

#endif

#if CONFIG_PGTABLE_LEVELS > 2

typedef struct {
#ifndef CONFIG_ARC_MMU_V6
	unsigned long pmd;
#else
	unsigned long long pmd;
#endif
} pmd_t;

#define pmd_val(x)	((x).pmd)
#define __pmd(x)	((pmd_t) { (x) })

#endif

typedef struct {
#if !defined(CONFIG_ARC_MMU_V6) && !defined(CONFIG_ARC_HAS_PAE40)
	unsigned long pte;
#else
	unsigned long long pte;
#endif
} pte_t;

#define pte_val(x)	((x).pte)
#define __pte(x)	((pte_t) { (x) })

typedef struct {
#ifndef CONFIG_ARC_MMU_V6
	unsigned long long pgprot;
#else
	unsigned long long pgprot;
#endif
} pgprot_t;

#define pgprot_val(x)	((x).pgprot)
#define __pgprot(x)	((pgprot_t) { (x) })
#define pte_pgprot(x)	__pgprot(pte_val(x))

typedef struct page *pgtable_t;

/*
 * Use virt_to_pfn with caution:
 * If used in pte or paddr related macros, it could cause truncation
 * in PAE40 builds
 * As a rule of thumb, only use it in helpers starting with virt_
 * You have been warned !
 */
#define virt_to_pfn(kaddr)	PFN_DOWN(__pa(kaddr))

#define ARCH_PFN_OFFSET		PFN_DOWN(CONFIG_LINUX_RAM_BASE)

#ifdef CONFIG_FLATMEM
#define pfn_valid(pfn)		(((pfn) - ARCH_PFN_OFFSET) < max_mapnr)
#endif

#ifdef CONFIG_64BIT

#define __pa(vaddr)  		((unsigned long)(vaddr) - \
				PAGE_OFFSET + \
				CONFIG_LINUX_LINK_BASE)
#define __va(paddr)  		((void *)((unsigned long)(paddr) - \
				CONFIG_LINUX_LINK_BASE + \
				PAGE_OFFSET))

#else /* V2 and Compact */

/*
 * __pa, __va, virt_to_page (ALERT: deprecated, don't use them)
 *
 * These macros have historically been misnamed
 * virt here means link-address/program-address as embedded in object code.
 * And for ARC, link-addr = physical address
 */
#define __pa(vaddr)		((unsigned long)(vaddr))
#define __va(paddr)		((void *)((unsigned long)(paddr)))
#endif /* CONFIG_64BIT */

#define virt_to_page(kaddr)	pfn_to_page(virt_to_pfn(kaddr))
#define virt_addr_valid(kaddr)  pfn_valid(virt_to_pfn(kaddr))

/* Default Permissions for stack/heaps pages (Non Executable) */
#define VM_DATA_DEFAULT_FLAGS   (VM_READ | VM_WRITE | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)

#define WANT_PAGE_VIRTUAL   1

#include <asm-generic/memory_model.h>   /* page_to_pfn, pfn_to_page */
#include <asm-generic/getorder.h>

#endif /* !__ASSEMBLY__ */

#endif
