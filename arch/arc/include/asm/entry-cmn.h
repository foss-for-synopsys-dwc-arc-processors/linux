/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ASM_ARC_ENTRY_CMN_H
#define __ASM_ARC_ENTRY_CMN_H

#include <asm/asm-offsets.h>
#include <asm/dsp-impl.h>
#include <asm/irqflags-arcv2.h>
#include <asm/thread_info.h>	/* For THREAD_SIZE */

/*
 * Interrupt/Exception stack layout (pt_regs) for ARCv2
 *   (End of struct aligned to end of page [unless nested])
 *
 *  INTERRUPT                          EXCEPTION
 *
 *    manual    ---------------------  manual
 *              |      orig_r0      |
 *              |      event/ECR    |
 *              |      bta          |
 *              |      gp           |
 *              |      fp           |
 *              |      sp           |
 *              |      r12          |
 *              |      r30          |
 *              |      r58          |
 *              |      r59          |
 *  hw autosave ---------------------
 *    optional  |      r0           |
 *              |      r1           |
 *              ~                   ~
 *              |      r9           |
 *              |      r10          |
 *              |      r11          |
 *              |      blink        |
 *              |      lpe          |
 *              |      lps          |
 *              |      lpc          |
 *              |      ei base      |
 *              |      ldi base     |
 *              |      jli base     |
 *              ---------------------
 *  hw autosave |       pc / eret   |
 *   mandatory  | stat32 / erstatus |
 *              ---------------------
 */

/*------------------------------------------------------------------------*/
.macro INTERRUPT_PROLOGUE

	; Before jumping to Interrupt Vector, hardware micro-ops did following:
	;   1. SP auto-switched to kernel mode stack
	;   2. STATUS32.Z flag set if in U mode at time of interrupt (U:1,K:0)
	;   3. Auto save: (mandatory) Push PC and STAT32 on stack
	;                 hardware does even if CONFIG_ARC_IRQ_NO_AUTOSAVE
	;  4a. Auto save: (optional) r0-r11, blink, LPE,LPS,LPC, JLI,LDI,EI
	;
	; Now
	;  4b. If Auto-save (optional) not enabled in hw, manually save them
	;   5. Manually save: r12,r30, sp,fp,gp, ACCL pair
	;
	; At the end, SP points to pt_regs

#ifdef CONFIG_ARC_IRQ_NO_AUTOSAVE
	; carve pt_regs on stack (case #3), PC/STAT32 already on stack
	SUBR	sp, sp, SZ_PT_REGS - 2*REGSZ

	__SAVE_REGFILE_HARD
#else
	; carve pt_regs on stack (case #4), which grew partially already
	SUBR	sp, sp, PT_r0
#endif

	__SAVE_REGFILE_SOFT
.endm

/*------------------------------------------------------------------------*/
.macro EXCEPTION_PROLOGUE_KEEP_AE

	; Before jumping to Exception Vector, hardware micro-ops did following:
	;   1. SP auto-switched to kernel mode stack
	;   2. STATUS32.Z flag set if in U mode at time of exception (U:1,K:0)
	;
	; Now manually save rest of reg file
	; At the end, SP points to pt_regs

	SUBR	sp, sp, SZ_PT_REGS	; carve space for pt_regs

	; _HARD saves r10 clobbered by _SOFT as scratch hence comes first

	__SAVE_REGFILE_HARD
	__SAVE_REGFILE_SOFT

	STR	r0, sp, 0	; pt_regs->orig_r0

	LRR	r10, [eret]
	lr	r11, [erstatus]
	STR2	r10, r11, sp, PT_ret

	lr	r10, [ecr]
	LRR	r11, [erbta]
	STR2	r10, r11, sp, PT_event

	; OUTPUT: r10 has ECR expected by EV_Trap
.endm

.macro EXCEPTION_PROLOGUE

	EXCEPTION_PROLOGUE_KEEP_AE	; return ECR in r10

	LRR  r0, [efa]
	MOVR r1, sp

	FAKE_RET_FROM_EXCPN		; clobbers r9
.endm

/*------------------------------------------------------------------------
 * This macro saves the registers manually which would normally be autosaved
 * by hardware on taken interrupts. It is used by
 *   - exception handlers (which don't have autosave)
 *   - interrupt autosave disabled due to CONFIG_ARC_IRQ_NO_AUTOSAVE
 */
.macro __SAVE_REGFILE_HARD

	STR2	r0,  r1,  sp, PT_r0
	STR2	r2,  r3,  sp, PT_r2
	STR2	r4,  r5,  sp, PT_r4
	STR2	r6,  r7,  sp, PT_r6
	STR2	r8,  r9,  sp, PT_r8
	STR2	r10, r11, sp, PT_r10
#ifdef CONFIG_ISA_ARCV3
	STR2	r12, r13, sp, PT_r12
#endif

	STR	blink, sp, PT_blink

#ifndef CONFIG_ARC_LACKS_ZOL
	LRR	r10, [lp_end]
	LRR	r11, [lp_start]
	STR2	r10, r11, sp, PT_lpe

	STR	lp_count, sp, PT_lpc
#endif

	; skip JLI, LDI, EI for now
.endm

/*------------------------------------------------------------------------
 * This macros saves a bunch of other registers which can't be autosaved for
 * various reasons:
 *   - r12: the last caller saved scratch reg since hardware saves in pairs so r0-r11
 *   - r30: free reg, used by gcc as scratch
 *   - ACCL/ACCH pair when they exist
 */
.macro __SAVE_REGFILE_SOFT

	STR	fp,  sp, PT_fp		; r27
	STR	gp, sp, PT_gp

	/* ARCv3: r12 autosaved, r26 is callee-saved (not gp) */
#ifdef CONFIG_ISA_ARCV2
	STR	r30, sp, PT_r30
	STR	r12, sp, PT_r12
#endif

	; Saving pt_regs->sp correctly requires some extra work due to the way
	; Auto stack switch works
	;  - U mode: retrieve it from AUX_USER_SP
	;  - K mode: add the offset from current SP where H/w starts auto push
	;
	; 1. Utilize the fact that Z bit is set if Intr taken in U mode
	; 2. Upon entry SP is always saved (for any inspection, unwinding etc),
	;    but on return, restored only if U mode

	LRR	r10, [AUX_USER_SP]	; U mode SP

	MOVR.nz	r10, sp
	ADD2R.nz r10, r10, SZ_PT_REGS/4	; K mode SP

	STR	r10, sp, PT_sp		; pt_regs->sp

#ifdef CONFIG_ARC_HAS_ACCL_REGS
#ifdef CONFIG_ARC_CPU_HS6X
	STR	r58, sp, PT_r58		; r59 is reserved for ARC64
#else
	STR2	r58, r59, sp, PT_r58
#endif
#endif

#ifdef CONFIG_ARC_CURR_IN_REG
	GET_CURR_TASK_ON_CPU	gp
#endif

	/* clobbers r10, r11 registers pair */
	DSP_SAVE_REGFILE_IRQ
.endm

/*------------------------------------------------------------------------*/
.macro __RESTORE_REGFILE_SOFT

	LDR	fp,  sp, PT_fp
	LDR	gp, sp, PT_gp

#ifdef CONFIG_ISA_ARCV2
	LDR	r30, sp, PT_r30
	LDR	r12, sp, PT_r12
#endif

	; Restore SP (into AUX_USER_SP) only if returning to U mode
	;  - for K mode, it will be implicitly restored as stack is unwound
	;  - Z flag set on K is inverse of what hardware does on interrupt entry
	;    but that doesn't really matter
	bz	1f

	LDR	r10, sp, PT_sp		; pt_regs->sp
	SRR	r10, [AUX_USER_SP]
1:

	/* clobbers r10, r11 registers pair */
	DSP_RESTORE_REGFILE_IRQ

#ifdef CONFIG_ARC_HAS_ACCL_REGS
#ifdef CONFIG_ARC_CPU_HS6X
	LDR	r58, sp, PT_r58
#else
	LDR2	r58, r59, sp, PT_r58
#endif
#endif
.endm

/*------------------------------------------------------------------------*/
.macro __RESTORE_REGFILE_HARD

	LDR	blink, sp, PT_blink

#ifndef CONFIG_ARC_LACKS_ZOL
	LDR2	r10, r11, sp, PT_lpe
	SRR	r10, [lp_end]
	SRR	r11, [lp_start]

	LDR	r10, sp, PT_lpc		; lp_count can't be target of LD
	MOVR	lp_count, r10
#endif

	LDR2	r0,  r1,  sp, PT_r0
	LDR2	r2,  r3,  sp, PT_r2
	LDR2	r4,  r5,  sp, PT_r4
	LDR2	r6,  r7,  sp, PT_r6
	LDR2	r8,  r9,  sp, PT_r8
	LDR2	r10, r11, sp, PT_r10
#ifdef CONFIG_ISA_ARCV3
	LDR2	r12, r13, sp, PT_r12
#endif
.endm


/*------------------------------------------------------------------------*/
.macro INTERRUPT_EPILOGUE

	; INPUT: r0 has STAT32 of calling context
	; INPUT: Z flag set if returning to K mode

	; _SOFT clobbers r10 restored by _HARD hence the order

	__RESTORE_REGFILE_SOFT

#ifdef CONFIG_ARC_IRQ_NO_AUTOSAVE
	__RESTORE_REGFILE_HARD

	; SP points to PC/STAT32: hw restores them despite NO_AUTOSAVE
	ADDR	sp, sp, SZ_PT_REGS - 2*REGSZ
#else
	ADDR	sp, sp, PT_r0
#endif

.endm

/*------------------------------------------------------------------------*/
.macro EXCEPTION_EPILOGUE

	; INPUT: r0 has STAT32 of calling context

	btst	r0, STATUS_U_BIT	; Z flag set if K, used in restoring SP

	LDR	r10, sp, PT_bta
	SRR	r10, [erbta]

	LDR2	r10, r11, sp, PT_ret
	SRR	r10, [eret]
	sr	r11, [erstatus]

	__RESTORE_REGFILE_SOFT
	__RESTORE_REGFILE_HARD

	ADDR	sp, sp, SZ_PT_REGS
.endm

.macro FAKE_RET_FROM_EXCPN
	lr      r9, [status32]
	bclr    r9, r9, STATUS_AE_BIT
	bset    r9, r9, STATUS_IE_BIT
	kflag   r9
.endm

/* Get thread_info of "current" tsk */
.macro GET_CURR_THR_INFO_FROM_SP  reg
	BMSKNR \reg, sp, THREAD_SHIFT - 1
.endm

/* Get CPU-ID of this core */
.macro  GET_CPU_ID  reg
	lr  \reg, [identity]
	xbfu \reg, \reg, 0xE8	/* 00111    01000 */
				/* M = 8-1  N = 8 */
.endm

#endif
