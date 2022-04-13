// SPDX-License-Identifier: GPL-2.0-only

#include <linux/mm.h>
#include <linux/types.h>

#include <asm/arcregs.h>
#include <asm/mmu_context.h>
#include <asm/mmu.h>
#include <asm/setup.h>
#include <asm/fixmap.h>

/* A copy of the ASID from the PID reg is kept in asid_cache */
DEFINE_PER_CPU(unsigned int, asid_cache) = MM_CTXT_FIRST_CYCLE;

static struct cpuinfo_arc_mmu {
	unsigned int pg_sz_k;
} mmuinfo;

volatile int arc_debug_tlb_flush_mm_nuke = 0;

int arc_mmu_mumbojumbo(int c, char *buf, int len)
{
	const unsigned int mmu_version = 0x10;
	unsigned int lookups, pg_sz_k, ntlb, u_dtlb, u_itlb;
	char *variant_nm[] = { "MMU32", "MMU48", "MMU48", "MMU48", "MMU52" };
	struct bcr_mmu_6 mmu6;
	int n = 0;

	READ_BCR(ARC_REG_MMU_BCR, mmu6);
	if (mmu6.ver != mmu_version) {
		panic("Bad version of MMUv6 %#x (expected %#x)\n",
		      mmu6.ver, mmu_version);
		return 0;
	}

	if (mmu6.variant == 0) {
		lookups = 3;	/* 3 levels */
		pg_sz_k = 4;	/* 4KB */
	} else if (mmu6.variant == 1) {
		lookups = 4;	/* 4 levels */
		pg_sz_k = 4;	/* 4KB */
	} else if (mmu6.variant == 2) {
		lookups = 4;	/* 4 levels */
		pg_sz_k = 16;	/* 16KB */
	} else if (mmu6.variant == 3) {
		lookups = 3;	/* 3 levels */
		pg_sz_k = 64;	/* 64KB */
	} else if (mmu6.variant == 4) {
		lookups = 3;	/* 3 levels */
		pg_sz_k = 64;	/* 64KB */
	} else {
		panic("MMUv6 variant %d is no supported\n", mmu6.variant);
		return 0;
	}

	if (lookups != CONFIG_PGTABLE_LEVELS) {
		panic("MMUv6 levels (%u) does not match configuration (%d)\n",
		      lookups, CONFIG_PGTABLE_LEVELS);
		return 0;
	}


	u_dtlb = 2 << mmu6.u_dtlb;  /* 8, 16 */
	u_itlb = 2 << mmu6.u_itlb;  /* 4, 8, 16 */
	ntlb = 256 << mmu6.n_tlb;    /* Fixed 4w */

	n += scnprintf(buf + n, len - n,
		      "MMU [v%x]\t: %s hwalk %d levels, %dk PAGE, JTLB %d uD/I %d/%d\n",
		       mmu6.ver, variant_nm[mmu6.variant], lookups,
		       pg_sz_k, ntlb, u_dtlb, u_itlb);

	n += scnprintf(buf + n, len - n,
		       "\t\t tlb_flush_mm %s\n",
		       arc_debug_tlb_flush_mm_nuke ? "flushes TLB" : "Incr ASID");

	mmuinfo.pg_sz_k = pg_sz_k;

	return n;
}

static inline void arc_mmu_rtp_set(unsigned int rtp_num, phys_addr_t addr,
				   unsigned long asid)
{
#if defined(CONFIG_ARC_MMU_V6_32)
	unsigned int aux_lo, aux_hi;
	u32 val_lo, val_hi;

	aux_lo = rtp_num ? ARC_REG_MMU_RTP1_LO : ARC_REG_MMU_RTP0_LO;
	aux_hi = rtp_num ? ARC_REG_MMU_RTP1_HI : ARC_REG_MMU_RTP0_HI;

	/* TODO: read hi addr only for PAE case */
	val_lo = addr & 0xffffffff;
	val_hi = (asid << 8) | (((u64) addr >> 32) & 0xf);

	write_aux_reg(aux_lo, val_lo);
	write_aux_reg(aux_hi, val_hi);
#else /* CONFIG_ARC_MMU_V6_32 */
	unsigned int aux;
	u64 val;
/*
 * FIXME: Only 48-bit phy addresses supported for MMUv52 for now.
 * See arch/arc/include/asm/pgtable-levels.h:276
 */
	BUG_ON(addr >> 48);

	aux = rtp_num ? ARC_REG_MMU_RTP1 : ARC_REG_MMU_RTP0;

	val = addr;
#if defined(CONFIG_ARC_MMU_V6_52)
	val >>= 4;
#endif
	val |= (u64) asid << 48;

	write_aux_64(aux, val);
#endif /* CONFIG_ARC_MMU_V6_32 */
}

static inline phys_addr_t arc_mmu_rtp_get_addr(unsigned int rtp_num)
{
	phys_addr_t addr;

#if defined(CONFIG_ARC_MMU_V6_32)
	unsigned int aux_lo, aux_hi;

	aux_lo = rtp_num ? ARC_REG_MMU_RTP1_LO : ARC_REG_MMU_RTP0_LO;
	aux_hi = rtp_num ? ARC_REG_MMU_RTP1_HI : ARC_REG_MMU_RTP0_HI;

	addr = read_aux_reg(aux_lo);
	addr |= ((u64) read_aux_reg(aux_hi) & 0xf) << 32;
#else
	unsigned int aux;

	aux = rtp_num ? ARC_REG_MMU_RTP1 : ARC_REG_MMU_RTP0;

	addr = read_aux_64(aux);
#if defined(CONFIG_ARC_MMU_V6_52)
	addr <<= 4;
#endif
#endif /* CONFIG_ARC_MMU_V6_32 */

	return addr;
}

/*
 * At this point we mapped kernel code (PAGE_OFFSET to _end) in head.S.
 * Assumes we have PGD and PUD
 * TODO: assumes 4 levels, implement properly using p*d_addr_end loops
 */
static pmd_t fixmap_pmd[PTRS_PER_PMD] __page_aligned_bss;
static pte_t fixmap_pte[PTRS_PER_PTE] __page_aligned_bss;
void __init early_fixmap_init(void)
{
	unsigned long addr;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	/* Make sure fixmap fits in one PMD. */
	BUILD_BUG_ON(pmd_index(FIXADDR_START) != \
		     pmd_index(FIXADDR_START + FIXADDR_SIZE));

	/* FIXADDR space must not overlap early mapping. */
	BUILD_BUG_ON(FIXADDR_START >= PAGE_OFFSET && \
		     FIXADDR_START < PAGE_OFFSET + EARLY_MAP_SIZE);

	addr = FIXADDR_START;

	pgd = (pgd_t *) __va(arc_mmu_rtp_get_addr(1));
	pgd += pgd_index(addr);
	if (pgd_none(*pgd) || !pgd_present(*pgd))
		return;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || !p4d_present(*p4d))
		return;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || !pud_present(*pud))
		set_pud(pud, pfn_pud(virt_to_pfn(fixmap_pmd), PAGE_TABLE));

	pmd = pmd_offset(pud, addr);
	if (!pmd_none(*pmd) || pmd_present(*pmd))
		return;

	set_pmd(pmd, pfn_pmd(virt_to_pfn(fixmap_pte), PAGE_TABLE));
}

/*
 * Just to new pgd.
 */
void early_fixmap_shutdown(void)
{
	unsigned long addr;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;

	addr = FIXADDR_START;

	pgd = (pgd_t *) __va(arc_mmu_rtp_get_addr(1));
	pgd += pgd_index(addr);
	if (pgd_none(*pgd) || !pgd_present(*pgd))
		return;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || !p4d_present(*p4d))
		return;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || !pud_present(*pud))
		set_pud(pud, pfn_pud(virt_to_pfn(fixmap_pmd), PAGE_TABLE));
}

void __set_fixmap(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot)
{
	unsigned long addr;
	pte_t *pte;

	addr = __fix_to_virt(idx);

	BUG_ON(idx >= __end_of_fixed_addresses);

	pte = fixmap_pte + pte_index(addr);
	if (!pte_none(*pte) || pte_present(*pte))
		return;

	set_pte(pte, pfn_pte(PFN_DOWN(phys), prot));
}

/*
 * Map the kernel code/data into page tables for a given @mm
 *
 * Assumes
 *  - pgd, pud and pmd are already allocated
 *  - pud is wired up to pgd and pmd to pud
 *
 * TODO: assumes 4 levels, implement properly using p*d_addr_end loops
 */
int arc_map_kernel_in_mm(struct mm_struct *mm)
{
	unsigned long addr = PAGE_OFFSET;
	unsigned long end = PAGE_OFFSET + PUD_SIZE;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || !pgd_present(*pgd))
		return 1;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || !p4d_present(*p4d))
		return 1;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || !pud_present(*pud))
		return 1;

	do {
		pgprot_t prot = PAGE_KERNEL_BLK;

		pmd = pmd_offset(pud, addr);
		if (!pmd_none(*pmd) || pmd_present(*pmd))
			return 1;

		set_pmd(pmd, pfn_pmd(virt_to_pfn(addr), prot));
		addr = pmd_addr_end(addr, end);
	}
	while (addr != end);

	return 0;
}

void arc_paging_init(void)
{
#if CONFIG_PGTABLE_LEVELS == 4
	unsigned int idx;

	idx = pgd_index(PAGE_OFFSET);
	swapper_pg_dir[idx] = pfn_pgd(virt_to_pfn(swapper_pud), PAGE_TABLE);
	ptw_flush(&swapper_pg_dir[idx]);

	idx = pud_index(PAGE_OFFSET);
	swapper_pud[idx] = pfn_pud(virt_to_pfn(swapper_pmd), PAGE_TABLE);
	ptw_flush(&swapper_pud[idx]);
#elif CONFIG_PGTABLE_LEVELS == 3
	unsigned int idx;

	idx = pgd_index(PAGE_OFFSET);
	swapper_pg_dir[idx] = pfn_pgd(virt_to_pfn(swapper_pmd), PAGE_TABLE);
	ptw_flush(&swapper_pg_dir[idx]);
#endif

	arc_map_kernel_in_mm(&init_mm);

	arc_mmu_rtp_set(0, 0, 0);
	arc_mmu_rtp_set(1, __pa(swapper_pg_dir), 0);
}

void arc_mmu_init(void)
{
	u64 memattr;

	/*
	 * Make sure that early mapping does not need more then one struct
	 * per level (pgd/pud/pmd).
	 */
	/* It is always true when PAGE_OFFSET is aligned to pmd. */
	BUILD_BUG_ON(pmd_index(PAGE_OFFSET) != 0);
	/* And size of early mapping is lower then PUD. */
	BUILD_BUG_ON(EARLY_MAP_SIZE > PUD_SIZE);

	if (mmuinfo.pg_sz_k != TO_KB(PAGE_SIZE))
		panic("MMU pg size != PAGE_SIZE (%luk)\n", TO_KB(PAGE_SIZE));

	if ((unsigned long)_end - PAGE_OFFSET > PUD_SIZE)
		panic("kernel doesn't fit in PUD (%lu Mb)\n", TO_MB(PUD_SIZE));

	write_aux_reg(ARC_REG_MMU_TTBC, MMU_TTBC);

	memattr = MEMATTR_NORMAL << (MEMATTR_IDX_NORMAL * 8);
	memattr |= MEMATTR_UNCACHED << (MEMATTR_IDX_UNCACHED * 8);
	memattr |= MEMATTR_VOLATILE << (MEMATTR_IDX_VOLATILE * 8);

#if defined(CONFIG_64BIT)
	write_aux_64(ARC_REG_MMU_MEM_ATTR, memattr);
#else
	write_aux_reg(ARC_REG_MMU_MEM_ATTR_LO, memattr & 0xffffffff);
	write_aux_reg(ARC_REG_MMU_MEM_ATTR_HI, memattr >> 32);
#endif
	arc_paging_init();

	write_aux_reg(ARC_REG_MMU_CTRL, 0x7);

	early_fixmap_shutdown();
}

void update_mmu_cache(struct vm_area_struct *vma, unsigned long vaddr_unaligned,
		      pte_t *ptep)
{

}

noinline void mmu_setup_asid(struct mm_struct *mm, unsigned long asid)
{
	arc_mmu_rtp_set(0, __pa(mm->pgd), asid);
}

void arch_exit_mmap(struct mm_struct *mm)
{
	/*
	 * mmput() -> exit_mmap() -> arch_exit_mmap() is called during
	 * execve(old_mm) as well as exit().
	 * Only for exit() is the fallback pgd needed
	 */
	if (current->mm != NULL)
		return;

	arc_mmu_rtp_set(0, 0, 0);
}

noinline void local_flush_tlb_all(void)
{
	write_aux_reg(ARC_REG_MMU_TLB_CMD, 1);
}

noinline void local_flush_tlb_mm(struct mm_struct *mm)
{
	if (arc_debug_tlb_flush_mm_nuke) {
		local_flush_tlb_all();
		return;
	}

	/*
	 * Small optimisation courtesy IA64
	 * flush_mm called during fork,exit,munmap etc, multiple times as well.
	 * Only for fork( ) do we need to move parent to a new MMU ctxt,
	 * all other cases are NOPs, hence this check.
	 */
	if (atomic_read(&mm->mm_users) == 0)
		return;

	/*
	 * - Move to a new ASID, but only if the mm is still wired in
	 *   (Android Binder ended up calling this for vma->mm != tsk->mm,
	 *    causing h/w - s/w ASID to get out of sync)
	 * - Also get_new_mmu_context() new implementation allocates a new
	 *   ASID only if it is not allocated already - so unallocate first
	 */
	destroy_context(mm);
	if (current->mm == mm)
		get_new_mmu_context(mm);
}

void local_flush_tlb_range(struct vm_area_struct *vma, unsigned long start,
			   unsigned long end)
{
	local_flush_tlb_all();
}

void local_flush_tlb_kernel_range(unsigned long start, unsigned long end)
{
	local_flush_tlb_all();
}

void local_flush_tlb_page(struct vm_area_struct *vma, unsigned long page)
{
	local_flush_tlb_all();
}

#ifdef CONFIG_SMP

struct tlb_args {
	struct vm_area_struct *ta_vma;
	unsigned long ta_start;
	unsigned long ta_end;
};

static inline void ipi_flush_tlb_page(void *arg)
{
	struct tlb_args *ta = arg;

	local_flush_tlb_page(ta->ta_vma, ta->ta_start);
}

static inline void ipi_flush_tlb_range(void *arg)
{
	struct tlb_args *ta = arg;

	local_flush_tlb_range(ta->ta_vma, ta->ta_start, ta->ta_end);
}

static inline void ipi_flush_tlb_kernel_range(void *arg)
{
	struct tlb_args *ta = (struct tlb_args *)arg;

	local_flush_tlb_kernel_range(ta->ta_start, ta->ta_end);
}

void flush_tlb_all(void)
{
	on_each_cpu((smp_call_func_t)local_flush_tlb_all, NULL, 1);
}

void flush_tlb_mm(struct mm_struct *mm)
{
	on_each_cpu_mask(mm_cpumask(mm), (smp_call_func_t)local_flush_tlb_mm,
			 mm, 1);
}

void flush_tlb_page(struct vm_area_struct *vma, unsigned long uaddr)
{
	struct tlb_args ta = {
		.ta_vma = vma,
		.ta_start = uaddr
	};

	on_each_cpu_mask(mm_cpumask(vma->vm_mm), ipi_flush_tlb_page, &ta, 1);
}

void flush_tlb_range(struct vm_area_struct *vma, unsigned long start,
		     unsigned long end)
{
	struct tlb_args ta = {
		.ta_vma = vma,
		.ta_start = start,
		.ta_end = end
	};

	on_each_cpu_mask(mm_cpumask(vma->vm_mm), ipi_flush_tlb_range, &ta, 1);
}

void flush_tlb_kernel_range(unsigned long start, unsigned long end)
{
	struct tlb_args ta = {
		.ta_start = start,
		.ta_end = end
	};

	on_each_cpu(ipi_flush_tlb_kernel_range, &ta, 1);
}
#endif

void do_tlb_overlap_fault(unsigned long cause, unsigned long address,
			  struct pt_regs *regs)
{
}
