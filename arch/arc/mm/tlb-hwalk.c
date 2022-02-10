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
	int n= 0;

	READ_BCR(ARC_REG_MMU_BCR, mmu6);
	if (!mmu6.ver)
		return n;

	if (mmu6.variant == 0) {	/* MMUv32 */
		lookups = 3;
		pg_sz_k = 4;
	}

	u_dtlb = 2 << mmu6.u_dtlb;  /* 8, 16 */
	u_itlb = 2 << mmu6.u_itlb;  /* 4, 8, 16 */
	ntlb = 256 << mmu6.n_tlb;    /* Fixed 4w */

	n += scnprintf(buf + n, len - n,
		      "MMU [v%x] \t\t: %s hwalk %d levels, %dk PAGE, JTLB %d uD/I %d/%d\n",
		       mmu6.ver, variant_nm[mmu6.variant], lookups,
		       pg_sz_k, ntlb, u_dtlb, u_itlb);

	mmuinfo.pg_sz_k = pg_sz_k;

	return n;
}

void arc_mmu_init(void)
{
	return;
	if (mmuinfo.pg_sz_k != TO_KB(PAGE_SIZE))
		panic("MMU pg size != PAGE_SIZE (%luk)\n", TO_KB(PAGE_SIZE));
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
