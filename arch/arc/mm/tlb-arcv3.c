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

int arc_mmu_mumbojumbo(int c, char *buf, int len)
{
	unsigned int lookups, pg_sz_k, ntlb, u_dtlb, u_itlb;
	char *variant_nm[] = { "MMU32", "MMU48", "MMU52" };
	struct bcr_mmu_6 mmu6;
	int n = 0;

	READ_BCR(ARC_REG_MMU_BCR, mmu6);
	if (!mmu6.ver) {
		panic("MMU not detected\n");
		return 0;
	} else if (!mmu6.ver) {
		panic("Only MMU48 supported currently\n");
		return 0;
	}

	lookups = 4;	/* 4 levels */
	pg_sz_k = 4;	/* 4KB */

	u_dtlb = 2 << mmu6.u_dtlb;  /* 8, 16 */
	u_itlb = 2 << mmu6.u_itlb;  /* 4, 8, 16 */
	ntlb = 256 << mmu6.n_tlb;    /* Fixed 4w */

	n += scnprintf(buf + n, len - n,
		      "MMU [v%x]\t: %s hwalk %d levels, %dk PAGE, JTLB %d uD/I %d/%d\n",
		       mmu6.ver, variant_nm[mmu6.variant], lookups,
		       pg_sz_k, ntlb, u_dtlb, u_itlb);

	mmuinfo.pg_sz_k = pg_sz_k;

	return n;
}

void arc_mmu_init(void)
{
	struct mmu_ttbc {
		u32 t0sz:5, t0sh:2, t0c:1, res0:7, a1:1,
		    t1sz:5, t1sh:2, t1c:1, res1:8;
	} ttbc;

	struct mmu_mem_attr {
		u8 attr[8];
	} memattr;

	if (mmuinfo.pg_sz_k != TO_KB(PAGE_SIZE))
		panic("MMU pg size != PAGE_SIZE (%luk)\n", TO_KB(PAGE_SIZE));

	arc_paging_init();

	ttbc.t0sz = 16;
	ttbc.t1sz = 16;	/* Not relevant since kernel linked under 4GB hits T0SZ */
	ttbc.t0sh = __SHR_INNER;
	ttbc.t1sh = __SHR_INNER;
	ttbc.t0c = 1;
	ttbc.t1c = 1;
	ttbc.a1 = 0;  /* ASID used is from MMU_RTP0 */

	WRITE_AUX(ARC_REG_MMU_TTBC, ttbc);

	memattr.attr[MEMATTR_IDX_NORMAL] = MEMATTR_NORMAL;
	memattr.attr[MEMATTR_IDX_UNCACHED] = MEMATTR_UNCACHED;
	memattr.attr[MEMATTR_IDX_VOLATILE] = MEMATTR_VOLATILE;

	WRITE_AUX64(ARC_REG_MMU_MEM_ATTR, memattr);

	write_aux_64(ARC_REG_MMU_RTP0, __pa(swapper_pg_dir));
	write_aux_64(ARC_REG_MMU_RTP1, 0);	/* to catch bugs */

	write_aux_reg(ARC_REG_MMU_CTRL, 0x7);
}

void update_mmu_cache(struct vm_area_struct *vma, unsigned long vaddr_unaligned,
		      pte_t *ptep)
{

}

noinline void local_flush_tlb_all(void)
{
}

noinline void local_flush_tlb_mm(struct mm_struct *mm)
{
}

void local_flush_tlb_range(struct vm_area_struct *vma, unsigned long start,
			   unsigned long end)
{
}

void local_flush_tlb_kernel_range(unsigned long start, unsigned long end)
{
}

void local_flush_tlb_page(struct vm_area_struct *vma, unsigned long page)
{
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
