/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ARC CPU startup Code
 *
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
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
#include <asm/irqflags.h>

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
	mov 	\tmp, 1
	ASLR	\tmp, \tmp, ARC_VADDR_BITS
	SUBR	\tmp, \tmp, 1
	ANDR	\tmp, \tmp, \value
	ORR	\tmp, \tmp, \prot
	STR	\tmp, \entry
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
;	cur, tmp - temporal registers
;
; Out:
;       All registers are clobbered.
.macro BUILD_PAGE_TABLE, link_addr, phy_addr, link_end, pgd, pud, pmd, cur, tmp

.Lbuild_pgd_entry\@:
	BUILD_PAGE_TABLE_ENTRY \pgd, \link_addr, \pud, \cur, \tmp, PTRS_PER_PGD, PGDIR_SHIFT, PAGE_KERNEL

.Lbuild_pud_entry\@:
	BUILD_PAGE_TABLE_ENTRY \pud, \link_addr, \pmd, \cur, \tmp, PTRS_PER_PUD, PUD_SHIFT, PAGE_KERNEL

.Lbuild_pmd_entry\@:
	BUILD_PAGE_TABLE_ENTRY \pmd, \link_addr, \phy_addr, \cur, \tmp, PTRS_PER_PMD, PMD_SHIFT, PAGE_KERNEL_BLK

	; Increment phy and link addresses
	ADDR	\phy_addr, \phy_addr, PMD_SIZE
	ADDR	\link_addr, \link_addr, PMD_SIZE

	; All link addresses are in
	CMPR	\link_end, \link_addr
	ble	.Lbuild_end\@

	; Check if we need to allocate new PMD
	LSRR	\tmp, \link_addr, PMD_SHIFT
	ANDR	\tmp, \tmp, (PTRS_PER_PMD - 1)
	CMPR	\tmp, 0
	bne	.Lbuild_pmd_entry\@

	; Allocate new PMD
	ADDR	\pmd, \pmd, PAGE_SIZE
	; Check if we need to allocate new PUD
	MOVR	\cur, \link_addr
	SUBR	\tmp, \link_addr, PMD_SIZE
	XORR	\tmp, \tmp, \cur
	BBIT1R	\tmp, PUD_SHIFT, .Lbuild_pud_entry\@

	; Allocate new PUD
	ADDR	\pud, \pud, PAGE_SIZE
	b	.Lbuild_pgd_entry\@
.Lbuild_end\@:
.endm

; Create two MMU maps (link -> phy and phy -> phy)
; phy -> phy is needed to have correct mapings right after MMU is enabled
; and we still using phy instruction and data addresses.
.macro CPU_EARLY_PAGING
	; r0, r1 and r2 are used as uboot args

	; First initialize 1:1 page table, so we can enable MMU when using
	; phy addresses. We need to map from start to .Lmmu_enabled (label
	; where we switch to virtual map).

	MOVI    r10, PAGE_OFFSET
	MOVI    r11, CONFIG_LINUX_LINK_BASE
	; link_addr <- __pa(stext)
	MOVA    r3, stext
	SUBR	r3, r3, r10
	ADDR	r3, r3, r11
	; phy_addr <- __pa(stext)
	MOVR	r4, r3
	; link_end <- __pa(.Lmmu_enabled)
	; link_end <- .Lmmu_enabled - PAGE_OFFSET + CONFIG_LINUX_LINK_BASE
	MOVA	r5, .Lmmu_enabled
	SUBR	r5, r5, r10
	ADDR	r5, r5, r11

	; pgd <- __pa(swapper_pg_dir)
	MOVA	r6, @swapper_pg_dir
	SUBR	r6, r6, r10
	ADDR	r6, r6, r11

	; pud <- __pa(swapper_pud)
	MOVA	r7, @swapper_pud
	SUBR	r7, r7, r10
	ADDR	r7, r7, r11

	; pmd <- __pa(swapper_pmd)
	MOVA	r8, @swapper_pmd
	SUBR	r8, r8, r10
	ADDR	r8, r8, r11

	BUILD_PAGE_TABLE r3, r4, r5, r6, r7, r8, r9, r10

	; link_addr <- PAGE_OFFSET
	MOVI    r3, PAGE_OFFSET
	; phy_addr <- CONFIG_LINUX_LINK_BASE
	MOVI	r4, CONFIG_LINUX_LINK_BASE
	; link_end <- _end , see vmlinux.ld.S
	MOVA	r5, _end

	; pgd <- __pa(early_pg_dir)
	MOVA	r6, @early_pg_dir
	SUBR	r6, r6, r3
	ADDR	r6, r6, r4

	; pud <- __pa(early_pud)
	MOVA	r7, @early_pud
	SUBR	r7, r7, r3
	ADDR	r7, r7, r4

	; pmd <- __pa(early_pmd)
	MOVA	r8, @early_pmd
	SUBR	r8, r8, r3
	ADDR	r8, r8, r4

	BUILD_PAGE_TABLE r3, r4, r5, r6, r7, r8, r9, r10
.endm


; Enable MMU and jump into virtual address space.
.macro CPU_ENABLE_MMU
	MOVI	r10, PAGE_OFFSET
	MOVI	r11, CONFIG_LINUX_LINK_BASE
	; RTP0: 1:1 mapping in __pa(swapper_pg_dir)
	MOVA	r4, @swapper_pg_dir
	SUBR	r4, r4, r10
	ADDR	r4, r4, r11
	SRR	r4, [ARC_REG_MMU_RTP0]
	; RTP1: real link to phy mapping in __pa(early_pg_dir)
	MOVA	r4, @early_pg_dir
	SUBR	r4, r4, r10
	ADDR	r4, r4, r11
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
#endif
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

	; TODO: Need to wait until paging init
#ifdef CONFIG_ISA_ARCV3
	CPU_ENABLE_MMU
#endif
	; Non-Masters wait for Master to boot enough and bring them up
	; when they resume, tail-call to entry point
	MOVA	blink, @first_lines_of_secondary
	b	arc_platform_smp_wait_to_boot

.Lmaster_proceed:
#endif

#ifdef CONFIG_ISA_ARCV3
	CPU_EARLY_PAGING
	CPU_ENABLE_MMU
	; here we can enable mmu for SMP
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
	STR	r0, r4
	MOVA	r4, @uboot_magic
	STR	r1, r4
	MOVA	r4, @uboot_arg
	STR	r2, r4

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
	MOVR	fp, 0

	; set it's stack base to tsk->thread_info bottom
	GET_TSK_STACK_BASE r0, sp

	b	start_kernel_secondary
END(first_lines_of_secondary)
#endif
