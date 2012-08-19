/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  vineetg: May 2011: for Non-aliasing VIPT D-cache following can be NOPs
 *   -flush_cache_dup_mm (fork)
 *   -likewise for flush_cache_mm (exit/execve)
 *   -likewise for flush_cache_{range,page} (munmap, exit, COW-break)
 *
 *  vineetg: April 2008
 *   -Added a critical CacheLine flush to copy_to_user_page( ) which
 *     was causing gdbserver to not setup breakpoints consistently
 */

#ifndef _ASM_CACHEFLUSH_H
#define _ASM_CACHEFLUSH_H

#define flush_dcache_mmap_lock(mapping)		do { } while (0)
#define flush_dcache_mmap_unlock(mapping)	do { } while (0)

#define flush_cache_vmap(start, end)		flush_cache_all()
#define flush_cache_vunmap(start, end)		flush_cache_all()

/* NOPS for VIPT Cache with non-aliasing D$ configurations only */

/* called during fork */
#define flush_cache_dup_mm(mm)

/* called during execve/exit */
#define flush_cache_mm(mm)

/* flush_cache_range( ): Flush the Cache lines for @u_vstart .. @u_vend
 * 1) Called when a range of user-space V-P mappings are torn-down:
 *     because of munmap() or exit().
 * 2) For VIPT, Non-aliasing D-Cache, flush_cache_range() can be a NOP.
 *    For now, ARC Linux doesn't support such ARC700 hardware configs, hence
 *    it can safely be a NOP
 *    If and when we do, this would have to be properly implemented
 *      -ASID doesn't have any role to play here
 *      -don't flush the entire I/D$, but iterate thru mappings, and
 *        for v-pages with backing phy-frame, flush the page from cache.
 *
 */
#define flush_cache_range(mm, u_vstart, u_vend)

/* flush_cache_page( ): Flush Cache-lines for @u_vaddr mapped to @pfn
 * Cousin of flush_cache_range( ) called mainly during page fault handling
 * COW etc. Again per above, for now it can be a NOP.
 */
#define flush_cache_page(vma, u_vaddr, pfn)

#ifdef CONFIG_ARC_CACHE

#ifdef CONFIG_SMP
#ifndef CONFIG_ARC_HAS_COH_CACHES
#error "Caching not yet supported in SMP"
#error "remove CONFIG_ARC_HAS_ICACHE and CONFIG_ARC_HAS_DCACHE"
#endif
#endif

extern void flush_cache_all(void);

#else

#define flush_cache_all()	do { } while (0)

#endif /* CONFIG_ARC_CACHE */

#ifdef CONFIG_ARC_HAS_ICACHE
extern void flush_icache_range_vaddr(unsigned long paddr, unsigned long u_vaddr,
				     int len);
extern void flush_icache_all(void);
extern void flush_icache_range(unsigned long start, unsigned long end);
extern void flush_icache_page(struct vm_area_struct *vma, struct page *page);

#else

#define flush_icache_all()			do { } while (0)
#define flush_icache_range(start, end)		do { } while (0)
#define flush_icache_range_vaddr(p, uv, len)	do { } while (0)
#define flush_icache_page(vma, page)		do { } while (0)

#endif /*CONFIG_ARC_HAS_ICACHE */

#define ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE 1

#ifdef CONFIG_ARC_HAS_DCACHE

extern void flush_dcache_page(struct page *page);
extern void flush_dcache_range(unsigned long start, unsigned long end);

extern void flush_dcache_all(void);
extern void inv_dcache_all(void);
extern void flush_and_inv_dcache_range(unsigned long start, unsigned long end);
extern void inv_dcache_range(unsigned long start, unsigned long end);
void flush_and_inv_dcache_all(void);

#define dma_cache_wback_inv(start, sz) flush_and_inv_dcache_range(start,  \
								  start + sz)
#define dma_cache_wback(start, sz)     flush_dcache_range(start, start + sz)
#define dma_cache_inv(start, sz)       inv_dcache_range(start, start + sz)

#else

#define flush_dcache_range(start, end)		do { } while (0)
#define flush_dcache_page(page)			do { } while (0)
#define flush_dcache_all(start, size)		do { } while (0)
#define inv_dcache_all()			do { } while (0)
#define inv_dcache_range(start, size)		do { } while (0)
#define flush_and_inv_dcache_all()		do { } while (0)
#define flush_and_inv_dcache_range(start, end)	do { } while (0)

#define dma_cache_wback_inv(start, size)	do { } while (0)
#define dma_cache_wback(start, size)		do { } while (0)
#define dma_cache_inv(start, size)		do { } while (0)
#endif /*CONFIG_ARC_HAS_DCACHE */

/*
 * Copy user data from/to a page which is mapped into a different
 * processes address space.  Really, we want to allow our "user
 * space" model to handle this.
 */
#define copy_to_user_page(vma, page, vaddr, dst, src, len)		\
do {									\
	memcpy(dst, src, len);						\
	if (vma->vm_flags & VM_EXEC)					\
	    flush_icache_range_vaddr((unsigned long)(dst), vaddr, len);	\
} while (0)

#define copy_from_user_page(vma, page, vaddr, dst, src, len)		\
do {									\
	memcpy(dst, src, len);						\
} while (0)

#include <asm/arcregs.h>
extern struct cpuinfo_arc cpuinfo_arc700[];

/*
 * On SMP systems, when the scheduler does migration-cost autodetection,
 * it needs a way to flush as much of the CPU's caches as possible.
 *
 * TODO: fill this in!
 */
static inline void sched_cacheflush(void)
{
}

#endif
