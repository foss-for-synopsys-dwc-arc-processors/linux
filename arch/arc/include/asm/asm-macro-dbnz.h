/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * DBNZ instruction introduced in ARCv2
 */
.macro DBNZR r, lbl
	dbnz  \r, \lbl
.endm
