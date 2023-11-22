/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Function tracing support for ARC
 *
 * Copyright (C) 2023 Synopsys, Inc. (www.synopsys.com)
 */

#include <linux/linkage.h>
#include <asm-generic/export.h>

; ftrace placeholder, just return to caller
ENTRY(ftrace_stub)
	j_s	[blink]
ENDPROC(ftrace_stub)

.macro SAVE_ABI
	push	blink
.endm

.macro LOAD_ABI
	pop	blink
.endm

.macro SAVE_ABI_RET
	push	r0
	push	r1
.endm

.macro LOAD_ABI_RET
	pop	r1
	pop	r0
.endm

; r0 has the frompc (targets parent ip)
; blink has the selfpc (target ip)
ENTRY(_mcount)

#ifdef CONFIG_FUNCTION_GRAPH_TRACER

	; *ftrace_graph_return != ftrace_stub
	ld	r3, [ftrace_graph_return]
	brne	r3, @ftrace_stub, @do_ftrace_graph_caller
	; *ftrace_graph_entry != *ftrace_graph_entry_stub
	ld	r3, [ftrace_graph_entry]
	brne	r3, @ftrace_graph_entry_stub, @do_ftrace_graph_caller

#endif

	; *ftrace_trace_function != ftrace_stub
	ld	r2, [ftrace_trace_function]
	brne	r2, @ftrace_stub, @do_trace
	; Return
	j_s	[blink]

ENDPROC(_mcount)

#ifdef CONFIG_FUNCTION_GRAPH_TRACER

; Return to the actual caller
ENTRY(return_to_handler)
	; Save return value (if any) from handled routine
	SAVE_ABI_RET
	; Will return true blink on r0
	jl	ftrace_return_to_handler
	mov	r2, r0
	LOAD_ABI_RET
	j	[r2]

ENDPROC(return_to_handler)

do_ftrace_graph_caller:
	; ABI does not allow us to infer blink location
	; ARC GCC port inserts into r1 the delta between the pushed blink and
	; the sp at call time
	; We perform calculation before any push (sp change) happens
	add	r0, r1, sp
	SAVE_ABI
	sub	r0, r0, 4
	mov	r1, blink
	jl	prepare_ftrace_return
	LOAD_ABI
	j_s	[blink]
#endif

do_trace:
	SAVE_ABI
	mov	r1, r0
	mov	r0, blink
	jl	[r2]
	; load ABI state and jump to blink (in stack)
	LOAD_ABI
	j_s	[blink]

EXPORT_SYMBOL(_mcount)
