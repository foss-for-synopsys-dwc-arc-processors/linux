/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
/*
 * Copyright (C) 2021 Synopsys, Inc. (www.synopsys.com)
 *
 * Author: Vineet Gupta <vgupta@synopsys.com>
 *
 * pseudo-mnemonics for 64-bit load/store when natively provided by ISA
 *
 *   - ARCv2 + ll64, ARCv3:ARC64 baseline
 *
 *   - For 32-bit ISA, output register pair r<N>:r<N+1> but only the
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

/*
 * load/store register pair
 */

.macro STR2 de, do, s, off=0
	std	\de, [\s, \off]
.endm

.macro LDR2 de, do, s, off=0
	ldd	\de, [\s, \off]
.endm
