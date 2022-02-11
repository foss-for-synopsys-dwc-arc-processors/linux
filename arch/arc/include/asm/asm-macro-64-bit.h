/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
/*
 * Copyright (C) 2021 Synopsys, Inc. (www.synopsys.com)
 *
 * Author: Vineet Gupta <vgupta@synopsys.com>
 *
 * pseudo-mnemonics for ALU/Memory instructions for ARC64 ISA
 */

.irp    cc,,.hi,.nz
.macro MOVR\cc d, s
        movl\cc   \d, \s
.endm
.endr

.macro MOVA d, sym
	movhl	\d, \sym
	orl	\d, \d, \sym@u32
.endm

.macro MOVI d, imm
	movhl	\d, (\imm >> 32)
	orl	\d, \d, \imm@u32
.endm

.irp    aa,,.as,.aw
.macro LDR\aa d, s, off=0
	ldl\aa \d, [\s, \off]
.endm
.endr

.irp    aa,.ab,.as
.macro STR\aa d, s, off=0
	; workaround assembler barfing for ST r, [@symb, 0]
	.if \off == 0
		stl\aa \d, [\s]
	.else
		stl\aa \d, [\s, \off]
	.endif
.endm
.endr

.macro STR d, s, off=0
	.if \off == 0
		stl \d, [\s]
	.else
		.if \off > 256
			STR.as \d, \s, \off / 8
		.else
			stl    \d, [\s, \off]
		.endif
	.endif
.endm

.macro PUSHR r
	pushl   \r
.endm

.macro POPR r
	popl    \r
.endm

.macro LRR d, aux
	lrl     \d, \aux
.endm

.macro SRR d, aux
	srl      \d, \aux
.endm

.irp    cc,,.nz
.macro ADDR\cc d, s, v
	addl\cc  \d, \s, \v
.endm
.endr

.irp    cc,,.nz
.macro ADD2R\cc d, s, v
	add2l\cc \d, \s, \v
.endm
.endr

.macro ADD3R d, s, v
	add3l \d, \s, \v
.endm

.macro SUBR d, s, v
	subl     \d, \s, \v
.endm

.macro BMSKNR d, s, v
	bmsknl   \d, \s, \v
.endm

.macro LSRR d, s, v
	lsrl	\d, \s, \v
.endm

.macro ASLR d, s, v
	asll \d, \s, \v
.endm

.macro ANDR d, s, v
	andl \d, \s, \v
.endm

.macro ORR, d, s, v
	orl \d, \s, \v
.endm

.macro XORR d, s, v
	xorl \d, \s, \v
.endm

.irp    cc,ne,eq
.macro BRR\cc d, s, lbl
	br\cc\()l  \d, \s, \lbl
.endm
.endr

.macro CMPR op1, op2
	cmpl \op1, \op2
.endm

.macro BBIT0R d, s, lbl
	bbit0l \d, \s, \lbl
.endm

.macro BBIT1R d, s, lbl
	bbit1l \d, \s, \lbl
.endm

/*
 * Abstraction for 64-bit load/store
 *  - ARC64 Baseline STL/LDL instructions
 */

.irp xx,,.ab
.macro ST64\xx d, s, off=0
	stl\xx	\d, [\s, \off]
.endm
.endr

.irp xx,,.ab
.macro LD64\xx d, s, off=0
	ldl\xx	\d, [\s, \off]
.endm
.endr

/*
 * load/store register pair
 *  - currently ll128 not supported
 */

.macro STR2 de, do, s, off=0
	STR.as	\de, \s, \off / REGSZ
	STR.as	\do, \s, (\off + REGSZ) / REGSZ
.endm

.macro LDR2 de, do, s, off=0
	LDR	\de, \s, \off
	LDR	\do, \s, \off + REGSZ
.endm
