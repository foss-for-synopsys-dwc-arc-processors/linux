/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * DBNZ emulation for ARCompact or earlier ARCv2 cores
 * 2 byte short instructions used to keep code size same as 4 byte DBNZ.
 * This warrants usage of r0-r3, r12-r15, gas barfs otherwise catching
 * offenders immediately
 */
.macro DBNZR r, lbl
	sub_s  \r, \r, 1
	brne_s \r, 0, \lbl
.endm
