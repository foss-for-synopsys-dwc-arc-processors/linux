/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015 Synopsys, Inc. (www.synopsys.com)
 */

#ifndef _ASM_HIGHMEM_H
#define _ASM_HIGHMEM_H

#ifdef CONFIG_HIGHMEM

#include <asm/page.h>
#include <asm/kmap_size.h>
#include <asm/fixmap.h>


#define PKMAP_BASE	(FIXADDR_START + FIXADDR_SIZE)

#define FIX_KMAP_SLOTS		(KM_MAX_IDX * NR_CPUS)
#define FIX_KMAP_BEGIN		(0UL)
#define FIX_KMAP_END		((FIX_KMAP_BEGIN + FIX_KMAP_SLOTS) - 1)

/*
 * This should be converted to the asm-generic version, but of course this
 * is needlessly different from all other architectures. Sigh - tglx
 */
#define __fix_to_virt(x)	(FIXADDR_TOP - ((x) << PAGE_SHIFT))
#define __virt_to_fix(x)	(((FIXADDR_TOP - ((x) & PAGE_MASK))) >> PAGE_SHIFT)

/* start after fixmap area */
#define PKMAP_SIZE		PGDIR_SIZE
#define LAST_PKMAP		(PKMAP_SIZE >> PAGE_SHIFT)
#define LAST_PKMAP_MASK		(LAST_PKMAP - 1)
#define PKMAP_ADDR(nr)		(PKMAP_BASE + ((nr) << PAGE_SHIFT))
#define PKMAP_NR(virt)		(((virt) - PKMAP_BASE) >> PAGE_SHIFT)

#include <asm/cacheflush.h>

extern void kmap_init(void);

#define arch_kmap_local_post_unmap(vaddr)			\
	local_flush_tlb_kernel_range(vaddr, vaddr + PAGE_SIZE)

static inline void flush_cache_kmaps(void)
{
	flush_cache_all();
}
#endif

#endif
