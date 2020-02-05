/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Abstraction for 64-bit load/store:
 *   - Single instruction to double load/store
 *   - output register pair r<N>:r<N+1> but only
 *     first register needs to be specified
 */

.irp xx,,.ab
.macro ST64\xx d, s, off=0
	std\xx	\d, [\s, \off]
.endm
.endr

.irp xx,,.ab
.macro LD64\xx d, s, off=0
	ldd\xx	\d, [\s, \off]
.endm
.endr
