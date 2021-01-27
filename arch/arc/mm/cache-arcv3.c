// SPDX-License-Identifier: GPL-2.0-only

#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/syscalls.h>

#include <asm/cacheflush.h>
#include <asm/setup.h>

unsigned long perip_base = 0xf0000000;
unsigned long perip_end = 0xffffffff;

static struct cpuinfo_arc_cache {
	unsigned int sz_k, line_len, colors;
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
	p_ic->colors = p_ic->sz_k/assoc/TO_KB(PAGE_SIZE);

	n += scnprintf(buf + n, len - n,
		       "I-Cache\t\t: %uK, %dway/set, %uB Line, VIPT%s%s\n",
		       p_ic->sz_k, assoc, p_ic->line_len,
		       p_ic->colors > 1 ? " aliasing" : "",
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

#define OP_INV		0x1
#define OP_FLUSH	0x2
#define OP_FLUSH_N_INV	0x3

static inline void __dc_op_before(const int op)
{
	const unsigned int ctl = ARC_REG_DC_CTRL;
	unsigned int val = read_aux_reg(ctl);

	if (op == OP_INV) {
		val &= ~DC_CTRL_INV_MODE_FLUSH;
	}

	/*
	 *  op		DC_CTL.RGN_OP	DC_CTRL.IM
	 * Flush              0           n/a
	 * Inv                1            0
	 * Flush-n-Inv        1            1
	 */
	val &= ~DC_CTRL_RGN_OP_MSK;
	if (op & OP_INV)
		val |= DC_CTRL_RGN_OP_INV;

	write_aux_reg(ctl, val);
}

static inline void __dc_op_after(const int op)
{
	if (op & OP_FLUSH) {
		const unsigned int ctl = ARC_REG_DC_CTRL;
		unsigned int reg;

		/* flush / flush-n-inv both wait */
		while ((reg = read_aux_reg(ctl)) & DC_CTRL_FLUSH_STATUS)
			;

		/* Switch back to default Invalidate mode */
		if (op == OP_FLUSH)
			write_aux_reg(ctl, reg | DC_CTRL_INV_MODE_FLUSH);
	}
}

static void __flush_dcache_range(phys_addr_t paddr, unsigned long vaddr, int len, const int op)
{
	unsigned long end;

	end = paddr + len + L1_CACHE_BYTES - 1;

        __dc_op_before(op);

        write_aux_64(ARC_REG_DC_ENDR, end);
        write_aux_64(ARC_REG_DC_STARTR, paddr);

        __dc_op_after(op);
}

/*
 * Note:
 *    - This function would never straddle the MMU page
 */
static void __inv_icache_range(phys_addr_t paddr, unsigned long vaddr, int len)
{
        unsigned long start, end;

        /*
         * I$ is VIPT.
         * For aliasing config, vaddr is needed to index and paddr to match tag
         * for non-aliasing paddr suffices for both
         */
        if (likely(ic.colors > 1)) {
                write_aux_64(ARC_REG_IC_PTAG, paddr);
                start = vaddr;
        } else {
                start = paddr;
        }

        /*
         * ENDR is exclusive so needs to point past the end of the last line
         * being flushed. To do this unconditionally add line size - 1
         */
	end = start + len + L1_CACHE_BYTES - 1;

	/* ENDR needs to be set ahead of START */
        write_aux_64(ARC_REG_IC_ENDR, end);

        start &= ~0x3;
        write_aux_64(ARC_REG_IC_IVIR, start);
}

void __sync_icache_dcache(phys_addr_t paddr, unsigned long vaddr, int len)
{
	unsigned long flags;

	local_irq_save(flags);

        __flush_dcache_range(paddr, vaddr, len, OP_FLUSH_N_INV);
        __inv_icache_range(paddr, vaddr, len);

	local_irq_restore(flags);
}

SYSCALL_DEFINE3(cacheflush, unsigned long, start, unsigned long, sz, unsigned long, flags)
{
	return 0;
}

void dma_cache_wback_inv(phys_addr_t start, unsigned long sz)
{
	__flush_dcache_range(start, start, sz, OP_FLUSH_N_INV);
}
EXPORT_SYMBOL(dma_cache_wback_inv);

void dma_cache_inv(phys_addr_t start, unsigned long sz)
{
	__flush_dcache_range(start, start, sz, OP_INV);
}
EXPORT_SYMBOL(dma_cache_inv);

void dma_cache_wback(phys_addr_t start, unsigned long sz)
{
	__flush_dcache_range(start, start, sz, OP_FLUSH);
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

void set_pte_at(struct mm_struct *mm, unsigned long vaddr, pte_t *ptep, pte_t pte)
{
	if (pte_present(pte) && pte_exec(pte)) {

		struct page *page = pte_page(pte);
		int dirty;

		dirty = !test_and_set_bit(PG_dc_clean, &page->flags);
		if (dirty) {
			phys_addr_t paddr = pte_val(pte) & PAGE_MASK;
			__sync_icache_dcache(paddr, vaddr & PAGE_MASK, PAGE_SIZE);
		}
	}

	set_pte(ptep, pte);
}

/*
 * Make I/D Caches consistent for kernel code (modules, kprobes, kgdb)
 */
void flush_icache_range(unsigned long kvaddr, unsigned long kvend)
{
	unsigned int tot_sz = kvend - kvaddr;

	BUG_ON((kvaddr < VMALLOC_START) || (kvend > VMALLOC_END));

	while (tot_sz > 0) {
		unsigned int off, sz;
		unsigned long paddr, pfn;

		off = kvaddr % PAGE_SIZE;
		pfn = vmalloc_to_pfn((void *)kvaddr);
		paddr = (pfn << PAGE_SHIFT) + off;
		sz = min_t(unsigned int, tot_sz, PAGE_SIZE - off);
		__sync_icache_dcache(paddr, kvaddr, sz);
		kvaddr += sz;
		tot_sz -= sz;
	}
}
