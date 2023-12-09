/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Just-In-Time compiler for eBPF bytecode (ARCv2 backend).
 *
 * Copyright (c) 2023 Synopsys Inc.
 * Author: Shahab Vahedi <shahab@synopsys.com>
 */

#ifndef _BPF_JIT_ARCV2_H
#define _BPF_JIT_ARCV2_H

/* ARC core registers. */
enum {
	ARC_R_0 , ARC_R_1 , ARC_R_2 , ARC_R_3 , ARC_R_4 , ARC_R_5,
	ARC_R_6 , ARC_R_7 , ARC_R_8 , ARC_R_9 , ARC_R_10, ARC_R_11,
	ARC_R_12, ARC_R_13, ARC_R_14, ARC_R_15, ARC_R_16, ARC_R_17,
	ARC_R_18, ARC_R_19, ARC_R_20, ARC_R_21, ARC_R_22, ARC_R_23,
	ARC_R_24, ARC_R_25, ARC_R_26, ARC_R_FP, ARC_R_SP, ARC_R_ILINK,
	ARC_R_30, ARC_R_BLINK,
	/*
	 * Having ARC_R_IMM encoded as source register means there is an
	 * immediate that must be interpreted from the next 4 bytes. If
	 * encoded as the destination register though, it implies that the
	 * output of the operation is not assigned to any register. The
	 * latter is helpful if we only care about updating the CPU status
	 * flags.
	 */
	ARC_R_IMM = 62
};

/*
 * For the translation of some BPF instructions, a temporary register as
 * a place holder for some interim data might be needed.
 */
#define JIT_REG_TMP MAX_BPF_JIT_REG

#define ARC_CALLEE_SAVED_REG_FIRST ARC_R_13
#define ARC_CALLEE_SAVED_REG_LAST  ARC_R_25

extern const u8 **bpf2arc;
#define REG_LO(r) (bpf2arc[(r)][0])
#define REG_HI(r) (bpf2arc[(r)][1])

#endif /* _BPF_JIT_ARCV2_H */
