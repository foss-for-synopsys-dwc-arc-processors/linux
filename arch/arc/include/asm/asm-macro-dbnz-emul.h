/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
/*
 * Copyright (C) 2021 Synopsys, Inc. (www.synopsys.com)
 *
 * Author: Vineet Gupta <vgupta@synopsys.com>
 *
 * pseudo-mnemonic for DBNZ Emulation for ARCompact and earlier ARCv2 cores
 *  - decrement-reg-and-branch-if-not-zero
 *  - 2 byte short instructions used to keep code size same as 4 byte DBNZ.
 *    This warrants usage of r0-r3, r12-r15, otherwise assembler barfs
 *    catching offenders early
 */

.macro DBNZR r, lbl
	sub_s  \r, \r, 1
	brne_s \r, 0, \lbl
.endm
