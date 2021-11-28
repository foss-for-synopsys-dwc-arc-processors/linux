/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015 Synopsys, Inc. (www.synopsys.com)
 */

#ifndef _ASM_HIGHMEM_H
#define _ASM_HIGHMEM_H

#ifdef CONFIG_HIGHMEM

#include <asm/page.h>
#include <asm/kmap_types.h>
#include <asm/fixmap.h>

#define KM_TYPE_NR		((FIXADDR_SIZE >> PAGE_SHIFT)/NR_CPUS)

/* start after fixmap area */
#define PKMAP_BASE		(FIXADDR_START + FIXADDR_SIZE)
#define PKMAP_SIZE		PGDIR_SIZE
#define LAST_PKMAP		(PKMAP_SIZE >> PAGE_SHIFT)
#define LAST_PKMAP_MASK		(LAST_PKMAP - 1)
#define PKMAP_ADDR(nr)		(PKMAP_BASE + ((nr) << PAGE_SHIFT))
#define PKMAP_NR(virt)		(((virt) - PKMAP_BASE) >> PAGE_SHIFT)

#define kmap_prot		PAGE_KERNEL


#include <asm/cacheflush.h>

extern void *kmap(struct page *page);
extern void *kmap_high(struct page *page);
extern void *kmap_atomic(struct page *page);
extern void __kunmap_atomic(void *kvaddr);
extern void kunmap_high(struct page *page);

extern void kmap_init(void);

static inline void flush_cache_kmaps(void)
{
	flush_cache_all();
}

static inline void kunmap(struct page *page)
{
	BUG_ON(in_interrupt());
	if (!PageHighMem(page))
		return;
	kunmap_high(page);
}


#endif

#endif
