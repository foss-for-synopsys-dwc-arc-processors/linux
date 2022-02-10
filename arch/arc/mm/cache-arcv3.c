// SPDX-License-Identifier: GPL-2.0-only

#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/syscalls.h>

#include <asm/cacheflush.h>
#include <asm/setup.h>

unsigned long perip_base = 0xf0000000;
unsigned long perip_end = 0xffffffff;

static struct cpuinfo_arc_cache {
	unsigned int sz_k, line_len, alias;
} ic, dc;

int arc_cache_mumbojumbo(int c, char *buf, int len)
{
	struct cpuinfo_arc_cache *p_ic = &ic, *p_dc = &dc;
	struct bcr_cache ibcr, dbcr;
	int assoc, n = 0;

	READ_BCR(ARC_REG_IC_BCR, ibcr);
	if (!ibcr.ver)
		goto dc_chk;

	BUG_ON(ibcr.ver < 4);
	assoc = 1 << ibcr.config;	/* 1,2,4,8 */
	p_ic->line_len = 8 << ibcr.line_len;
	p_ic->sz_k = 1 << (ibcr.sz - 1);
	p_ic->alias = p_ic->sz_k/assoc/TO_KB(PAGE_SIZE);

	n += scnprintf(buf + n, len - n,
		       "I-Cache\t\t: %uK, %dway/set, %uB Line, VIPT%s%s\n",
		       p_ic->sz_k, assoc, p_ic->line_len,
		       p_ic->alias > 1 ? " aliasing" : "",
		       IS_USED_CFG(CONFIG_ARC_HAS_ICACHE));

dc_chk:
	READ_BCR(ARC_REG_DC_BCR, dbcr);
	if (!dbcr.ver)
		goto slc_chk;

	BUG_ON(dbcr.ver < 4);
	assoc = 1 << dbcr.config;	/* 1,2,4,8 */
	p_dc->line_len = 16 << dbcr.line_len;
	p_dc->sz_k = 1 << (dbcr.sz - 1);

	n += scnprintf(buf + n, len - n,
		       "D-Cache\t\t: %uK, %dway/set, %uB Line, PIPT%s\n",
		       p_dc->sz_k, assoc, p_dc->line_len,
		       IS_USED_CFG(CONFIG_ARC_HAS_DCACHE));

slc_chk:
	return n;
}

void __ref arc_cache_init(void)
{

}

SYSCALL_DEFINE3(cacheflush, unsigned long, start, unsigned long, sz, unsigned long, flags)
{
	return 0;
}

void dma_cache_wback_inv(phys_addr_t start, unsigned long sz)
{
}
EXPORT_SYMBOL(dma_cache_wback_inv);

void dma_cache_inv(phys_addr_t start, unsigned long sz)
{
}
EXPORT_SYMBOL(dma_cache_inv);

void dma_cache_wback(phys_addr_t start, unsigned long sz)
{
}
EXPORT_SYMBOL(dma_cache_wback);

void copy_user_highpage(struct page *to, struct page *from,
	unsigned long u_vaddr, struct vm_area_struct *vma)
{
	void *kfrom = kmap_atomic(from);
	void *kto = kmap_atomic(to);

	clear_bit(PG_dc_clean, &to->flags);
	clear_bit(PG_dc_clean, &from->flags);

	copy_page(kto, kfrom);

	kunmap_atomic(kto);
	kunmap_atomic(kfrom);
}

void clear_user_page(void *to, unsigned long u_vaddr, struct page *page)
{
	clear_page(to);
	clear_bit(PG_dc_clean, &page->flags);
}

void flush_dcache_page(struct page *page)
{
	clear_bit(PG_dc_clean, &page->flags);
}

void flush_icache_range(unsigned long kstart, unsigned long kend)
{
}

void __sync_icache_dcache(phys_addr_t paddr, unsigned long vaddr, int len)
{
}

void __flush_dcache_page(phys_addr_t paddr, unsigned long vaddr)
{
}

void __inv_icache_page(phys_addr_t paddr, unsigned long vaddr)
{
}
