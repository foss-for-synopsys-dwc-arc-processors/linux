/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ARC CPU startup Code
 *
 * Copyright (C) 2004, 2007-2010, 2011-2012, 2021 Synopsys, Inc. (www.synopsys.com)
 *
 * Vineetg: Dec 2007
 *  -Check if we are running on Simulator or on real hardware
 *      to skip certain things during boot on simulator
 */

#include <linux/linkage.h>
#include <asm/asm-offsets.h>
#include <asm/entry.h>
#include <asm/arcregs.h>
#include <asm/cache.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/pgtable-levels.h>
#include <asm/mmu.h>
#include <asm/dsp-impl.h>
#include <asm/irqflags.h>

#ifndef PUD_SHIFT
#define PUD_SHIFT PGDIR_SHIFT
#endif

; Build page table entry.
;
; In:
;	tbl - register with pointer to table level
;	addr - address for which the table entry is building
;	value - address to be set in entry
;	entry, tmp - temporal registers
;	ptrs - constant with number of pointers per table level
;	shift - constant with table level shift
;	prot - entry protection bits
;
; Out:
;       entry - address of new entry
;       tmp - clobbered
.macro BUILD_PAGE_TABLE_ENTRY, tbl, addr, value, entry, tmp, ptrs, shift, prot
	; Calculate offset for entry
	LSRR	\entry, \addr, \shift
	ANDR	\entry, \entry, (\ptrs - 1)
	ADD3R	\entry, \tbl, \entry

	; Store allocated PUD to PGD with PAGE_TABLE prot. bits
#ifdef CONFIG_64BIT
#if ARC_VADDR_BITS == 64
#error "ARC_VADDR_BITS == 64 is not implemented for 64-bit"
#endif
	mov 	\tmp, 1
	ASLR	\tmp, \tmp, ARC_VADDR_BITS
	SUBR	\tmp, \tmp, 1
	ANDR	\tmp, \tmp, \value
	ORR	\tmp, \tmp, \prot
	STR	\tmp, \entry

#else

#if ARC_VADDR_BITS != 32
#error "ARC_VADDR_BITS != 32 is not implemented for 32-bit"
#endif
	mov 	\tmp, \value
	ORR	\tmp, \tmp, (\prot & 0xffffffff)
	STR	\tmp, \entry
	ADDR	\entry, \entry, 4
	mov	\tmp, (\prot >> 32)
	STR	\tmp, \entry

#endif

#ifdef CONFIG_ARC_PTW_UNCACHED
	SRR	\entry, [ARC_REG_DC_IVDL]
#endif
.endm

; Build simple page table (PGD + PUD for 4K, + PMD for 16K).
;
; In:
;	link_addr - start link address
;	phy_addr - start physical address
;	link_end - end link address
;	pgd - pointer to pgd array
;	pud - pointer to pud array
;	pmd - pointer to pmd array
;	cur, tmp - temporal registers
;
; Out:
;       All registers are clobbered.
.macro BUILD_PAGE_TABLE, link_addr, phy_addr, link_end, pgd, pud, pmd, cur, tmp

#if defined(CONFIG_ARC_MMU_V6_48) && defined(CONFIG_ARC_PAGE_SIZE_4K)

; Two-level page table, PGD + PUD
#define BUILD_PGD_ENTRY BUILD_PAGE_TABLE_ENTRY \pgd, \link_addr, \pud, \cur, \tmp, PTRS_PER_PGD, PGDIR_SHIFT, PAGE_KERNEL_RWX
#define BUILD_PUD_ENTRY BUILD_PAGE_TABLE_ENTRY \pud, \link_addr, \phy_addr, \cur, \tmp, PTRS_PER_PUD, PUD_SHIFT, PAGE_KERNEL_BLK_RWX
#define BUILD_PMD_ENTRY
#define ENTRY_SIZE	PUD_SIZE
#define ENTRY_LABEL	.Lbuild_pud_entry\@

#elif defined(CONFIG_ARC_MMU_V6_48) && defined(CONFIG_ARC_PAGE_SIZE_16K)

; Three-level page table, PGD + PUD + PMD
#define BUILD_PGD_ENTRY BUILD_PAGE_TABLE_ENTRY \pgd, \link_addr, \pud, \cur, \tmp, PTRS_PER_PGD, PGDIR_SHIFT, PAGE_KERNEL_RWX
#define BUILD_PUD_ENTRY BUILD_PAGE_TABLE_ENTRY \pud, \link_addr, \pmd, \cur, \tmp, PTRS_PER_PUD, PUD_SHIFT, PAGE_KERNEL_RWX
#define BUILD_PMD_ENTRY BUILD_PAGE_TABLE_ENTRY \pmd, \link_addr, \phy_addr, \cur, \tmp, PTRS_PER_PMD, PMD_SHIFT, PAGE_KERNEL_BLK_RWX
#define ENTRY_SIZE	PMD_SIZE
#define ENTRY_LABEL	.Lbuild_pmd_entry\@

#elif defined(CONFIG_ARC_MMU_V6_48) && defined(CONFIG_ARC_PAGE_SIZE_64K) || defined(CONFIG_ARC_MMU_V6_52) || defined(CONFIG_ARC_MMU_V6_32)

; Two-level page table, PGD + PMD
#define BUILD_PGD_ENTRY BUILD_PAGE_TABLE_ENTRY \pgd, \link_addr, \pmd, \cur, \tmp, PTRS_PER_PGD, PGDIR_SHIFT, PAGE_KERNEL_RWX
#define BUILD_PUD_ENTRY
#define BUILD_PMD_ENTRY BUILD_PAGE_TABLE_ENTRY \pmd, \link_addr, \phy_addr, \cur, \tmp, PTRS_PER_PMD, PMD_SHIFT, PAGE_KERNEL_BLK_RWX
#define ENTRY_SIZE	PMD_SIZE
#define ENTRY_LABEL	.Lbuild_pmd_entry\@

#endif

.Lbuild_pgd_entry\@:
	BUILD_PGD_ENTRY

.Lbuild_pud_entry\@:
	BUILD_PUD_ENTRY

.Lbuild_pmd_entry\@:
	BUILD_PMD_ENTRY

	; Increment phy and link addresses
	ADDR	\phy_addr, \phy_addr, ENTRY_SIZE
	ADDR	\link_addr, \link_addr, ENTRY_SIZE

	; All link addresses are in
	CMPR	\link_end, \link_addr
	ble	.Lbuild_end\@
	b	ENTRY_LABEL
.Lbuild_end\@:
#undef BUILD_PGD_ENTRY
#undef BUILD_PUD_ENTRY
#undef BUILD_PMD_ENTRY
#undef ENTRY_SIZE
#undef ENTRY_LABEL
.endm

; Create page table with 1:1 mapping in given table pointers.
; Addresses are mapped from CONFIG_LINUX_LINK_BASE to .Lmmu_enabled label.
;
; In:
;	tbl_pg_dir - symbol address for pg_dir table
;	tbl_pud/pmd - same for pud/pmd
; Out:
;	Clobbers r3-r11
.macro CREATE_PAGING_1to1, tbl_pg_dir, tbl_pud, tbl_pmd
	; r0, r1 and r2 are used as uboot args

	; First initialize 1:1 page table, so we can enable MMU when using
	; phy addresses. We need to map from start to .Lmmu_enabled (label
	; where we switch to virtual map).

	MOVI    r10, PAGE_OFFSET
	MOVI    r11, CONFIG_LINUX_LINK_BASE
	; link_addr <- CONFIG_LINUX_LINK_BASE
	MOVI    r3, CONFIG_LINUX_LINK_BASE
	; phy_addr <- CONFIG_LINUX_LINK_BASE
	MOVR	r4, r3

	; link_end <- __pa(.Lmmu_enabled)
	; link_end <- .Lmmu_enabled - PAGE_OFFSET + CONFIG_LINUX_LINK_BASE
#ifdef CONFIG_SMP
	MOVA	r5, .Lmmu_enabled
	MOVA	r6, .Lmmu_enabled_secondary
	MAXR	r5, r5, r6
#else
	MOVA	r5, .Lmmu_enabled
#endif
	SUBR	r5, r5, r10
	ADDR	r5, r5, r11

	; pgd <- __pa(tbl_pg_dir)
	MOVA	r6, \tbl_pg_dir
	SUBR	r6, r6, r10
	ADDR	r6, r6, r11

	; pud <- __pa(tbl_pud)
	MOVA	r7, \tbl_pud
	SUBR	r7, r7, r10
	ADDR	r7, r7, r11

	; pmd <- __pa(tbl_pmd)
	MOVA	r8, \tbl_pmd
	SUBR	r8, r8, r10
	ADDR	r8, r8, r11

	BUILD_PAGE_TABLE r3, r4, r5, r6, r7, r8, r9, r10
.endm

; Create page table with virt to phy mapping in given addresses.
; Addresses are mapped from CONFIG_LINUX_LINK_BASE to _end symbol.
;
; In:
;	tbl_pg_dir - symbol address for pg_dir table
;	tbl_pud/pmd - same for pud/pmd
; Out:
;	Clobbers r3-r10
.macro CREATE_PAGING_VtoP, tbl_pg_dir, tbl_pud, tbl_pmd
	; link_addr <- PAGE_OFFSET
	MOVI    r3, PAGE_OFFSET
	; phy_addr <- CONFIG_LINUX_LINK_BASE
	MOVI	r4, CONFIG_LINUX_LINK_BASE
	; link_end <- EARLY_MAP_SIZE , see processor.h
	MOVI	r5, (PAGE_OFFSET + EARLY_MAP_SIZE)

	; pgd <- __pa(tbl_pg_dir)
	MOVA	r6, \tbl_pg_dir
	SUBR	r6, r6, r3
	ADDR	r6, r6, r4

	; pud <- __pa(tbl_pud)
	MOVA	r7, \tbl_pud
	SUBR	r7, r7, r3
	ADDR	r7, r7, r4

	; pmd <- __pa(tbl_pmd)
	MOVA	r8, \tbl_pmd
	SUBR	r8, r8, r3
	ADDR	r8, r8, r4

	BUILD_PAGE_TABLE r3, r4, r5, r6, r7, r8, r9, r10
.endm

; Enable MMU and jump into virtual address space.
;
; In:
;	tbl_rtp0 - virtual address of pg_dir of 1:1 mapping
;	tbl_rtp1 - virtual address of pg_dir of V:P mapping
; Out:
;	Clobbers r4, r10, r11
.macro CPU_ENABLE_MMU, tbl_rtp0, tbl_rtp1
	MOVI	r10, PAGE_OFFSET
	MOVI	r11, CONFIG_LINUX_LINK_BASE
	; RTP0: 1:1 mapping in __pa(tbl_rtp0)
	MOVA	r4, \tbl_rtp0
	SUBR	r4, r4, r10
	ADDR	r4, r4, r11
#if defined(CONFIG_ARC_MMU_V6_52)
	LSRR	r4, r4, 4
#endif
	SRR	r4, [ARC_REG_MMU_RTP0]

	; RTP1: real link to phy mapping in __pa(tbl_rtp1)
	MOVA	r4, \tbl_rtp1
	SUBR	r4, r4, r10
	ADDR	r4, r4, r11
#if defined(CONFIG_ARC_MMU_V6_52)
	LSRR	r4, r4, 4
#endif
	SRR	r4, [ARC_REG_MMU_RTP1]

	sr	MMU_TTBC, [ARC_REG_MMU_TTBC]
	; MEMATTR_NORMAL is used in PAGE_KERNEL_BLK
	mov 	r4, MEMATTR_NORMAL
	ASLR	r4, r4, (8 * MEMATTR_IDX_NORMAL)
	SRR	r4, [ARC_REG_MMU_MEM_ATTR]
	; MMU_CTRL = (EN | KU | WX)
	mov	r4, 0x7
	sr	r4, [ARC_REG_MMU_CTRL]

	; Jump from phy to link address
	MOVA	r4, @.Lfirst_virt_addr\@
	j	[r4]
.Lfirst_virt_addr\@:
	; flush caches
	mov	r4, 0x1
#ifdef CONFIG_ARC_HAS_ICACHE
	sr	r4, [ARC_REG_DC_IVDC]
#endif
#ifdef CONFIG_ARC_HAS_DCACHE
	sr	r4, [ARC_REG_IC_IVIC]
#endif
	mov	r4, 0x0
	SRR	r4, [ARC_REG_MMU_RTP0]
.endm

; Early setup:
;	 - Setup vector table
;	 - Configure hardware prefetcher
;	 - Enable/disable L1 caches
;	 - Set invalidate mode flush bit for DC
;	 - Enable/disable unaligned access
;
; Out:
;	Clobbers r5
.macro CPU_EARLY_SETUP

	; Setting up Vector Table
#ifdef CONFIG_64BIT
	MOVA	r5, @_int_vec_base_lds
	srl	r5, [AUX_INTR_VEC_BASE]
#else
	sr	@_int_vec_base_lds, [AUX_INTR_VEC_BASE]
#endif

#ifdef CONFIG_ARC_HWPF
        lr      r5, [ARC_REG_HW_PF_CTRL]
        or      r5, r5, 1
        sr      r5, [ARC_REG_HW_PF_CTRL]
#endif

	; Disable I-cache/D-cache if kernel so configured
	lr	r5, [ARC_REG_IC_BCR]
	breq    r5, 0, 1f		; I$ doesn't exist
	lr	r5, [ARC_REG_IC_CTRL]
#ifdef CONFIG_ARC_HAS_ICACHE
	bclr	r5, r5, 0		; 0 - Enable, 1 is Disable
#else
	bset	r5, r5, 0		; I$ exists, but is not used
#endif
	sr	r5, [ARC_REG_IC_CTRL]

1:
	lr	r5, [ARC_REG_DC_BCR]
	breq    r5, 0, 1f		; D$ doesn't exist
	lr	r5, [ARC_REG_DC_CTRL]
	or	r5, r5, DC_CTRL_INV_MODE_FLUSH	; wback+Invalidate
#ifdef CONFIG_ARC_HAS_DCACHE
	bclr	r5, r5, 0		; Enable
#else
	bset	r5, r5, 0		; Disable
#endif
	sr	r5, [ARC_REG_DC_CTRL]

1:

#ifndef CONFIG_ISA_ARCOMPACT
	; Unaligned access is disabled at reset, so re-enable early as
	; gcc 7.3.1 (ARC GNU 2018.03) onwards generates unaligned access
	; by default
	lr	r5, [status32]
#ifdef CONFIG_ARC_USE_UNALIGNED_MEM_ACCESS
	bset	r5, r5, STATUS_AD_BIT
#else
	; Although disabled at reset, bootloader might have enabled it
	bclr	r5, r5, STATUS_AD_BIT
#endif
	kflag	r5

#ifdef CONFIG_ARC_LPB_DISABLE
	lr	r5, [ARC_REG_LPB_BUILD]
	breq    r5, 0, 1f		; LPB doesn't exist
	mov	r5, 1
	sr	r5, [ARC_REG_LPB_CTRL]
1:
#endif /* CONFIG_ARC_LPB_DISABLE */

	/* On HSDK, CCMs need to remapped super early */
#ifdef CONFIG_ARC_SOC_HSDK
	mov	r6, 0x60000000
	lr	r5, [ARC_REG_ICCM_BUILD]
	breq	r5, 0, 1f
	sr	r6, [ARC_REG_AUX_ICCM]
1:
	lr	r5, [ARC_REG_DCCM_BUILD]
	breq	r5, 0, 2f
	sr	r6, [ARC_REG_AUX_DCCM]
2:
#endif	/* CONFIG_ARC_SOC_HSDK */

#endif	/* CONFIG_ISA_ARCV2 */

	; Config DSP_CTRL properly, so kernel may use integer multiply,
	; multiply-accumulate, and divide operations
	DSP_EARLY_INIT
.endm

	.section .init.text, "ax",@progbits

;----------------------------------------------------------------
; Default Reset Handler (jumped into from Reset vector)
; - Don't clobber r0,r1,r2 as they might have u-boot provided args
; - Platforms can override this weak version if needed
;----------------------------------------------------------------
WEAK(res_service)
	b	stext
END(res_service)


; Secondary CPU wait for main loop
;
; In:
;	r0 - CPU Id
;	blink - pointer to first_lines_of_secondary
; Out:
;	Clobbers r0, r1, r2, r3 (uBoot args are parsed by main CPU)
#ifdef CONFIG_SMP
ENTRY(arc_platform_smp_wait_to_boot)
#ifdef CONFIG_ARC_SMP_HALT_ON_RESET
	j	blink
#endif

	; __pa(arc_platform_wake_flag) since MMU is not enabled
	MOVA	r1, @arc_platform_wake_flag
#ifdef CONFIG_ISA_ARCV3
	MOVI    r2, PAGE_OFFSET
	MOVI    r3, CONFIG_LINUX_LINK_BASE
	SUBR	r1, r1, r2
	ADDR	r1, r1, r3
#endif
.Lsmp_wait:
#ifdef CONFIG_ISA_ARCOMPACT
	ld	r2, [r1]
#else
	ld.di	r2, [r1]
#endif
	cmp	r2, r0
	bne	.Lsmp_wait

#ifdef CONFIG_ISA_ARCV3
	; At this point swapper_pg_dir already contains proper V:P mapping.
	; But we still need to have 1:1 mapping to enable MMU.
	CREATE_PAGING_1to1 @early_pg_dir, @early_pud, @early_pmd
	CPU_ENABLE_MMU @early_pg_dir, @swapper_pg_dir
.Lmmu_enabled_secondary:

	MOVA	r1, @arc_platform_wake_flag
#endif

	mov	r0, 0
#ifdef CONFIG_ISA_ARCOMPACT
	st	r0, [r1]
#else
	st.di	r0, [r1]
#endif
	j	[blink]
END(arc_platform_smp_wait_to_boot)
#endif

;----------------------------------------------------------------
; Kernel Entry point
;----------------------------------------------------------------
ENTRY(stext)

	CPU_EARLY_SETUP

#ifdef CONFIG_SMP
	GET_CPU_ID  r5
	cmp	r5, 0
	mov.nz	r0, r5
	bz	.Lmaster_proceed

	; Non-Masters wait for Master to boot enough and bring them up
	; when they resume, tail-call to entry point
	MOVA	blink, @first_lines_of_secondary
	b	arc_platform_smp_wait_to_boot

.Lmaster_proceed:
#endif

#ifdef CONFIG_ISA_ARCV3
	; Create 1:1 mapping in swappers, because it is needed up until
	; .Lfirst_virt_addr. After this CPU uses V:P mapping from early
	; arrays and we can fill swappers with proper mapping.
	CREATE_PAGING_1to1 @swapper_pg_dir, @swapper_pud, @swapper_pmd
	CREATE_PAGING_VtoP @early_pg_dir, @early_pud, @early_pmd
	CPU_ENABLE_MMU @swapper_pg_dir, @early_pg_dir
.Lmmu_enabled:
#endif

	; Clear BSS before updating any globals
	MOVA	r5, __bss_start
	MOVA	r7, __bss_stop
	SUBR	r6, r7, r5
#ifndef CONFIG_ARC_LACKS_ZOL
	lsr.f	lp_count, r6, 2
	lpnz	1f
	st.ab   0, [r5, 4]
1:
#else
	; don't need LSRL: BSS size can't be more than 4GB
	lsr	r6, r6, 3
1:
	ST64.ab	0, r5, 8
	DBNZR	r6, 1b
#endif

	; Uboot - kernel ABI
	;    r0 = [0] No uboot interaction, [1] cmdline in r2, [2] DTB in r2
	;    r1 = magic number (always zero as of now)
	;    r2 = pointer to uboot provided cmdline or external DTB in mem
	; These are handled later in handle_uboot_args()
	MOVA	r4, @uboot_tag
	st	r0, [r4]
	MOVA	r4, @uboot_magic
	st	r1, [r4]
	MOVA	r4, @uboot_arg
	st	r2, [r4]

	; setup "current" tsk and optionally cache it in dedicated r25
	MOVA	r9, @init_task
	SET_CURR_TASK_ON_CPU  r9, r0	; r9 = tsk, r0 = scratch

	; setup stack (fp, sp)
	MOVR	fp, 0

	; tsk->thread_info is really a PAGE, whose bottom hoists stack
	GET_TSK_STACK_BASE r9, sp	; r9 = tsk, sp = stack base(output)

	b	start_kernel	; "C" entry point
END(stext)

#ifdef CONFIG_SMP
;----------------------------------------------------------------
;     First lines of code run by secondary before jumping to 'C'
;----------------------------------------------------------------
	.section .text, "ax",@progbits
ENTRY(first_lines_of_secondary)
	; setup per-cpu idle task as "current" on this CPU
	MOVA	r0, @secondary_idle_tsk
	LDR	r0, r0
	SET_CURR_TASK_ON_CPU  r0, r1

	; setup stack (fp, sp)
	mov	fp, 0

	; set it's stack base to tsk->thread_info bottom
	GET_TSK_STACK_BASE r0, sp

	b	start_kernel_secondary
END(first_lines_of_secondary)
#endif
