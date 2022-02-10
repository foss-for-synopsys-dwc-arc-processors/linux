/* SPDX-License-Identifier: GPL-2.0-only */

.irp    cc,,.hi,.nz
.macro MOVR\cc d, s
        movl\cc   \d, \s
.endm
.endr

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

.macro SUBR d, s, v
	subl     \d, \s, \v
.endm

.macro BMSKNR d, s, v
	bmsknl   \d, \s, \v
.endm

.macro LSRR d, s, v
	lsrl	\d, \s, \v
.endm

.irp    cc,ne,eq
.macro BRR\cc d, s, lbl
	br\cc\()l  \d, \s, \lbl
.endm
.endr

/*
 * Abstraction for 64-bit load/store
 *   - ARC64 Baseline STL/LDL instructions
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
