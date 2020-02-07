/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2014-15 Synopsys, Inc. (www.synopsys.com)
 */

#include <linux/linkage.h>
#include <asm/cache.h>
#include <asm/assembler.h>

/*
 * The memset implementation below is optimized to use prefetchw and prealloc
 * instruction in case of CPU with 64B L1 data cache line (L1_CACHE_SHIFT == 6)
 * If you want to implement optimized memset for other possible L1 data cache
 * line lengths (32B and 128B) you should rewrite code carefully checking
 * we don't call any prefetchw/prealloc instruction for L1 cache lines which
 * don't belongs to memset area.
 */

#if L1_CACHE_SHIFT == 6

.macro PREALLOCR s, off=0
	prealloc [\s, \off]
.endm

.macro PREFETCHWR s, off=0
	prefetchw [\s, \off]
.endm

#else

.macro PREALLOCR s, off=0
.endm

.macro PREFETCHWR s, off=0
.endm

#endif

ENTRY_CFI(memset)
	; return if size 0 (happens lot)
	mov.f	0, r2
	jz.d	[blink]
	mov	r3, r0	; make a copy of input pointer reg

	PREFETCHWR r0

	; small 1-8 byte handled in tail byte loop :-)
	brlo	r2, 8, .Lbyteloop

#ifndef CONFIG_ARC_USE_UNALIGNED_MEM_ACCESS
	; handle any starting unaligned bytes (upto 3)
	and.f	lp_count, r0, 0x3
	lpnz	1f
	stb.ab	r1, [r3,1]
	sub	r2, r2, 1
1:
#endif

	; promote memset pattern from char to int (double actually for STD)
	and	r1, r1, 0xFF
	asl	r4, r1, 8
	or	r4, r4, r1
	asl	r5, r4, 16
	or	r5, r5, r4
	mov	r4, r5

	; Loop #a:
	; - Updates 1 cache line worth data (64 bytes) per iteration
	; - PREALLOC the next line.
	;
	; = Only entered if atleast 2 lines worth of work (i.e. >= 128 bytes),
	;   else PREALLOC for next can "bleed" past end of buffer, causing data
	;   corruption issue if that line is owned by some other core.
	; = Last 64 bytes (even for min 128 bytes work) are NOT done here to
	;   avoid PREALLOC issue

	sub     r6, r2, 64
	cmp	r2, 64
	bmsk.hi	r2, r2, 5	; trailing 63 bytes
	mov.ls	r6, 0
	add.hi	r2, r2, 64	; line skipped in loop below

	lsr.f	lp_count, r6, 6
	lpnz	2f
	PREALLOCR r3, 64
	ST64.ab	r4, r3, 8
	ST64.ab	r4, r3, 8
	ST64.ab	r4, r3, 8
	ST64.ab	r4, r3, 8
	ST64.ab	r4, r3, 8
	ST64.ab	r4, r3, 8
	ST64.ab	r4, r3, 8
	ST64.ab	r4, r3, 8
2:
	; Loop #b: Remaining 32 / 64 bytes
	lsr.f	lp_count, r2, 5
	lpnz	.Lbyteloop
	ST64.ab	r4, r3, 8
	ST64.ab	r4, r3, 8
	ST64.ab	r4, r3, 8
	ST64.ab	r4, r3, 8

.Lbyteloop:
	; Loop #c: straggler 31 bytes
	and.f	lp_count, r2, 0x1F
	lpnz	4f
	stb.ab	r1, [r3, 1]
4:
	j	[blink]

END_CFI(memset)

ENTRY_CFI(memzero)
    ; adjust bzero args to memset args
    mov r2, r1
    b.d  memset    ;tail call so need to tinker with blink
    mov r1, 0
END_CFI(memzero)
