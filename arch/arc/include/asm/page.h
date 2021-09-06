/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 */
#ifndef __ASM_ARC_PAGE_H
#define __ASM_ARC_PAGE_H

#include <uapi/asm/page.h>

#ifndef __ASSEMBLY__

#define clear_page(paddr)		memset((paddr), 0, PAGE_SIZE)
#define copy_page(to, from)		memcpy((to), (from), PAGE_SIZE)

struct vm_area_struct;
struct page;

#define __HAVE_ARCH_COPY_USER_HIGHPAGE

void copy_user_highpage(struct page *to, struct page *from,
			unsigned long u_vaddr, struct vm_area_struct *vma);
void clear_user_page(void *to, unsigned long u_vaddr, struct page *page);

typedef struct {
	unsigned long pgd;
} pgd_t;

#define pgd_val(x)	((x).pgd)
#define __pgd(x)	((pgd_t) { (x) })

#if CONFIG_PGTABLE_LEVELS > 3

typedef struct {
	unsigned long pud;
} pud_t;

#define pud_val(x)      	((x).pud)
#define __pud(x)        	((pud_t) { (x) })

#endif

#if CONFIG_PGTABLE_LEVELS > 2

typedef struct {
	unsigned long pmd;
} pmd_t;

#define pmd_val(x)	((x).pmd)
#define __pmd(x)	((pmd_t) { (x) })

#endif

typedef struct {
#ifdef CONFIG_ARC_HAS_PAE40
	unsigned long long pte;
#else
	unsigned long pte;
#endif
} pte_t;

#define pte_val(x)	((x).pte)
#define __pte(x)	((pte_t) { (x) })

typedef struct {
	unsigned long pgprot;
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

#ifdef CONFIG_ISA_ARCV3

#define __pa(vaddr)  		((unsigned long)(vaddr) - \
				PAGE_OFFSET + CONFIG_LINUX_RAM_BASE)
#define __va(paddr)  		((void *)((unsigned long)(paddr) - \
				CONFIG_LINUX_RAM_BASE + PAGE_OFFSET))

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

#endif /* CONFIG_ISA_ARCV3 */

#define virt_to_page(kaddr)	pfn_to_page(virt_to_pfn(kaddr))
#define virt_addr_valid(kaddr)  pfn_valid(virt_to_pfn(kaddr))

/* Default Permissions for stack/heaps pages (Non Executable) */
#define VM_DATA_DEFAULT_FLAGS   (VM_READ | VM_WRITE | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)

#define WANT_PAGE_VIRTUAL   1

#include <asm-generic/memory_model.h>   /* page_to_pfn, pfn_to_page */
#include <asm-generic/getorder.h>

#endif /* !__ASSEMBLY__ */

#endif
