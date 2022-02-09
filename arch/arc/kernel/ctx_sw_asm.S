/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 *
 * Vineetg: Aug 2009
 *  -Moved core context switch macro out of entry.S into this file.
 *  -This is the more "natural" hand written assembler
 */

#include <linux/linkage.h>
#include <asm/entry.h>       /* For the SAVE_* macros */

; IN
;  - r0: prev task (also current)
;  - r1: next task
; OUT
;  - r0: prev task (so r0 not touched)

	.section .sched.text,"ax",@progbits
ENTRY_CFI(__switch_to)

	/* save kernel stack frame regs of @prev task */
	PUSHR	blink
	CFI_DEF_CFA_OFFSET 4
	CFI_OFFSET r31, -4

	PUSHR	fp
	CFI_DEF_CFA_OFFSET 8
	CFI_OFFSET r27, -8

	MOVR	fp, sp
	CFI_DEF_CFA_REGISTER r27

	/* kernel mode callee regs of @prev */
	SAVE_CALLEE_SAVED_KERNEL

	/*
	 * save final SP to @prev->thread_info.ksp
	 * @prev is "current" so thread_info derived from SP
	 */
	GET_CURR_THR_INFO_FROM_SP  r10
	STR	sp,  r10, THREAD_INFO_KSP

	/* update @next in _current_task[] and GP register caching it */
	SET_CURR_TASK_ON_CPU  r1, r10

	/* load SP from @next->thread_info.ksp */
	LDR	r10, r1, TASK_THREAD_INFO
	LDR	sp,  r10, THREAD_INFO_KSP

	/* restore callee regs, stack frame regs of @next */
	RESTORE_CALLEE_SAVED_KERNEL

	POPR	fp
	CFI_RESTORE r27
	CFI_DEF_CFA r28, 4

	POPR	blink
	CFI_RESTORE r31
	CFI_DEF_CFA_OFFSET 0

	j      [blink]
END_CFI(__switch_to)
