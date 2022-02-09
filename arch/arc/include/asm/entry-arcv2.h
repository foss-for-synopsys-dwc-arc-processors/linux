/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ASM_ARC_ENTRY_ARCV2_H
#define __ASM_ARC_ENTRY_ARCV2_H

#include <asm/entry-cmn.h>

.macro SAVE_ABI_CALLEE_REGS
	push	r13
	push	r14
	push	r15
	push	r16
	push	r17
	push	r18
	push	r19
	push	r20
	push	r21
	push	r22
	push	r23
	push	r24
	push	r25
.endm

.macro RESTORE_ABI_CALLEE_REGS
	pop	r25
	pop	r24
	pop	r23
	pop	r22
	pop	r21
	pop	r20
	pop	r19
	pop	r18
	pop	r17
	pop	r16
	pop	r15
	pop	r14
	pop	r13
.endm

#endif
