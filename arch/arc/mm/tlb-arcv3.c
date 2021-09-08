// SPDX-License-Identifier: GPL-2.0-only

#include <linux/mm.h>

#include <asm/arcregs.h>
#include <asm/mmu_context.h>
#include <asm/mmu.h>
#include <asm/setup.h>

/* A copy of the ASID from the PID reg is kept in asid_cache */
DEFINE_PER_CPU(unsigned int, asid_cache) = MM_CTXT_FIRST_CYCLE;

static struct cpuinfo_arc_mmu {
	unsigned int pg_sz_k;
} mmuinfo;

volatile int arc_debug_tlb_flush_mm_nuke = 0;

int arc_mmu_mumbojumbo(int c, char *buf, int len)
{
	unsigned int lookups, pg_sz_k, ntlb, u_dtlb, u_itlb;
	char *variant_nm[] = { "MMU32", "MMU48", "MMU48", "MMU48", "MMU52" };
	struct bcr_mmu_6 mmu6;
	int n= 0;

	READ_BCR(ARC_REG_MMU_BCR, mmu6);
	if (!mmu6.ver) {
		panic("MMU not detected\n");
		return 0;
	} else if (!mmu6.ver) {
		panic("Only MMU48 supported currently\n");
		return 0;
	}

	lookups = 4;	/* 4 levels */
	if (mmu6.variant == 1) {
		pg_sz_k = 4;	/* 4KB */
	} else if (mmu6.variant == 2) {
		pg_sz_k = 16;	/* 16KB */
	} else {
		panic("Only MMU48 4K/16K supported currently\n");
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

/*
 * Map the kernel code/data into page tables for a given @mm
 *
 * Assumes
 *  - pgd, pud and pmd are already allocated
 *  - pud is wired up to pgd and pmd to pud
 *
 * TODO: assumes 4 levels, implement properly using p*d_addr_end loops
 */
int noinline arc_map_kernel_in_mm(struct mm_struct *mm)
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
	unsigned int idx;

	idx = pgd_index(PAGE_OFFSET);
	swapper_pg_dir[idx] = pfn_pgd(virt_to_pfn(swapper_pud), PAGE_TABLE);
	ptw_flush(&swapper_pg_dir[idx]);

	idx = pud_index(PAGE_OFFSET);
	swapper_pud[idx] = pfn_pud(virt_to_pfn(swapper_pmd), PAGE_TABLE);
	ptw_flush(&swapper_pud[idx]);

	arc_map_kernel_in_mm(&init_mm);

	write_aux_64(ARC_REG_MMU_RTP0, 0);
	write_aux_64(ARC_REG_MMU_RTP1, __pa(swapper_pg_dir));
}

void arc_mmu_init(void)
{
	struct mmu_mem_attr {
		u8 attr[8];
	} memattr;

	if (mmuinfo.pg_sz_k != TO_KB(PAGE_SIZE))
		panic("MMU pg size != PAGE_SIZE (%luk)\n", TO_KB(PAGE_SIZE));

	if (CONFIG_PGTABLE_LEVELS != 4)
		panic("CONFIG_PGTABLE_LEVELS !=4 not supported\n");

	if ((unsigned long)_end - PAGE_OFFSET > PUD_SIZE)
		panic("kernel doesn't fit in PUD (%lu Mb)\n", TO_MB(PUD_SIZE));

	write_aux_reg(ARC_REG_MMU_TTBC, MMU_TTBC);

	memattr.attr[MEMATTR_IDX_NORMAL] = MEMATTR_NORMAL;
	memattr.attr[MEMATTR_IDX_UNCACHED] = MEMATTR_UNCACHED;
	memattr.attr[MEMATTR_IDX_VOLATILE] = MEMATTR_VOLATILE;

	WRITE_AUX64(ARC_REG_MMU_MEM_ATTR, memattr);

	arc_paging_init();

	write_aux_reg(ARC_REG_MMU_CTRL, 0x7);
}

void update_mmu_cache(struct vm_area_struct *vma, unsigned long vaddr_unaligned,
		      pte_t *ptep)
{

}

noinline void mmu_setup_asid(struct mm_struct *mm, unsigned long asid)
{
#ifdef CONFIG_64BIT
	unsigned long rtp0 = (asid << 48) | __pa(mm->pgd);

	BUG_ON(__pa(mm->pgd) >> 48);
	write_aux_64(ARC_REG_MMU_RTP0, rtp0);

#else
#error "Need to implement 2 SR ops"
#endif
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

	/*
	 * set the kernel page tables to allow kernel to run
	 * since task paging tree will be nuked right after
	 */
	write_aux_64(ARC_REG_MMU_RTP0, 0);
}

noinline void local_flush_tlb_all(void)
{
	unsigned long flags;

	/* TBD: this might not be needed */
	local_irq_save(flags);
	write_aux_reg(ARC_REG_MMU_TLB_CMD, 1);
	local_irq_restore(flags);
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
