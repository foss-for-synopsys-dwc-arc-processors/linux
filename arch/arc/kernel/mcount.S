/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Function tracing support for ARC
 *
 * Copyright (C) 2023 Synopsys, Inc. (www.synopsys.com)
 */

#include <linux/linkage.h>
#include <asm-generic/export.h>
#include <asm/assembler.h>

; ftrace placeholder, just return to caller
ENTRY(ftrace_stub)
	j_s	[blink]
ENDPROC(ftrace_stub)

.macro SAVE_ABI
	PUSHR	blink
	PUSHR	fp
.endm

.macro LOAD_ABI
	POPR	fp
	POPR	blink
.endm

.macro SAVE_ABI_RET
	PUSHR	r0
	PUSHR	r1
.endm

.macro LOAD_ABI_RET
	POPR	r1
	POPR	r0
.endm

; r0 has the frompc (targets parent ip)
; blink has the selfpc (target ip)
ENTRY(_mcount)

#ifdef CONFIG_FUNCTION_GRAPH_TRACER

	; *ftrace_graph_return != ftrace_stub
	MOVA	r3, ftrace_graph_return
	LDR	r3, r3
	MOVA	r4, @ftrace_stub
	brne	r3, r4, @do_ftrace_graph_caller
	; *ftrace_graph_entry != *ftrace_graph_entry_stub
	MOVA	r3, @ftrace_graph_entry
	LDR	r3, r3
	MOVA	r4, @ftrace_graph_entry_stub
	brne	r3, r4, @do_ftrace_graph_caller

#endif

	; *ftrace_trace_function != ftrace_stub
	MOVA	r2, ftrace_trace_function
	LDR	r2, r2
	MOVA	r3, @ftrace_stub
	brne	r2, r3, @do_trace
	; Return
	j_s	[blink]

ENDPROC(_mcount)

#ifdef CONFIG_FUNCTION_GRAPH_TRACER

; Return to the actual caller
ENTRY(return_to_handler)
	; Save return value (if any) from handled routine
	SAVE_ABI_RET
	; Will return true blink on r0
	MOVA	r0, @ftrace_return_to_handler
	jl	[r0]
	MOVR	r2, r0
	LOAD_ABI_RET
	j	[r2]

ENDPROC(return_to_handler)

do_ftrace_graph_caller:

#ifndef CONFIG_ISA_ARCV3
	; ABI does not allow us to infer blink location
	; ARC GCC port inserts into r1 the delta between the pushed blink and
	; the sp at call time
	; We perform calculation before any push (sp change) happens
	ADDR	r0, r1, sp
	SAVE_ABI
	SUBR	r0, r0, REGSZASM
#else
	SAVE_ABI
	ADDR	r0, fp, REGSZASM
#endif

	MOVR	r1, blink
	MOVA	r2, @prepare_ftrace_return
	jl	[r2]
	LOAD_ABI
	j_s	[blink]
#endif

do_trace:
	SAVE_ABI
	MOVR	r1, r0
	MOVR	r0, blink
	jl	[r2]
	; load ABI state and jump to blink (in stack)
	LOAD_ABI
	j_s	[blink]

EXPORT_SYMBOL(_mcount)
