/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Function tracing support for ARC
 *
 * Copyright (C) 2023 Synopsys, Inc. (www.synopsys.com)
 */


#include <linux/init.h>
#include <linux/linkage.h>
#include <asm-generic/export.h>
#include <asm/asm-macro-64-bit.h>

.text
; ftrace placeholder, just return to caller
ENTRY(ftrace_stub)
    j_s     [blink]
ENDPROC(ftrace_stub)

; save ABI necessary registers
.macro SAVE_ABI
    PUSHR  blink
    PUSHR  fp
.endm

.macro LOAD_ABI
    POPR fp
    POPR blink
.endm

.macro SAVE_ABI_RET
    PUSHR  r0
    PUSHR  r1
    PUSHR  blink
.endm

.macro LOAD_ABI_RET
    POPR blink
    POPR r1
    POPR r0
.endm

#ifdef CONFIG_FUNCTION_GRAPH_TRACER

; Return to the actual caller
ENTRY(return_to_handler)
    ; Save return value (if any) from handled routine
    SAVE_ABI_RET

    ; Will return true blink on r0
    MOVA  r0, @ftrace_return_to_handler
    jl    [r0]

    MOVR r2, r0

    LOAD_ABI_RET

    j [r2]

ENDPROC(return_to_handler)
#endif

; r0 has the frompc (targets parent ip)
; blink has the selfpc (target ip)
ENTRY(_mcount)

#ifdef CONFIG_FUNCTION_GRAPH_TRACER

    ; *ftrace_graph_return != ftrace_stub
    MOVA  r3, ftrace_graph_return
    LD64  r3, r3
    MOVA  r4, @ftrace_stub
    brne  r3, r4, @do_ftrace_graph_caller

    ; *ftrace_graph_entry != *ftrace_graph_entry_stub
    MOVA  r3, @ftrace_graph_entry
    LD64  r3, r3
    MOVA  r4, @ftrace_graph_entry_stub
    brne  r3, r4, @do_ftrace_graph_caller

#endif

    ; *ftrace_trace_function != ftrace_stub
    MOVA r2, ftrace_trace_function
    LD64 r2, r2

    MOVA r3, @ftrace_stub
    brne r2, r3, @do_trace

    ; Return
    j_s  [blink]

ENDPROC(_mcount)

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
do_ftrace_graph_caller:

SAVE_ABI

    ADDR r0, fp, 8
    MOVR  r1, blink

    MOVA  r2, @prepare_ftrace_return
    jl    [r2]

LOAD_ABI

    j_s  [blink]
#endif

do_trace:
SAVE_ABI
    MOVR r1, r0
    MOVR r0, blink

    jl   [r2]

LOAD_ABI
    j_s   [blink]
