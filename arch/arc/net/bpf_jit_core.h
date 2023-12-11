/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * The backend-agnostic part of Just-In-Time compiler for eBPF bytecode.
 *
 * Copyright (c) 2023 Synopsys Inc.
 * Author: Shahab Vahedi <shahab@synopsys.com>
 */

#ifndef _BPF_JIT_CORE_H
#define _BPF_JIT_CORE_H

/* Print debug info and assert. */
/* TODO: comment me out! */
#define ARC_BPF_JIT_DEBUG

/* Determine the address type of the target. */
#ifdef CONFIG_ISA_ARCV2
/* TODO: propagate this to jit context (bpf2insn), get_targ_jit_addr, ... */
#define ARC_ADDR u32
#endif

/*
 * For the translation of some BPF instructions, a temporary register as
 * a place holder for some interim data might be needed.
 */
#define JIT_REG_TMP MAX_BPF_JIT_REG

/************* Globals that have effects on code generation ***********/
/*
 * If "emit" is true, the instructions are actually generated. Else, the
 * generation part will be skipped and only the length of instruction is
 * returned by the responsible functions.
 */
extern bool emit;

/* An indicator if zero-extend must be done for the 32-bit operations. */
extern bool zext_thyself;

/*************** Functions that the backend must provide **************/
/* Extension for 32-bit operations. */
extern inline u8 zext(u8 *buf, u8 rd);
/***** Addition *****/
extern u8 add_r32(u8 *buf, u8 rd, u8 rs);
extern u8 add_r32_i32(u8 *buf, u8 rd, s32 imm);
extern u8 add_r64(u8 *buf, u8 rd, u8 rs);
extern u8 add_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Subtraction *****/
extern u8 sub_r32(u8 *buf, u8 rd, u8 rs);
extern u8 sub_r32_i32(u8 *buf, u8 rd, s32 imm);
extern u8 sub_r64(u8 *buf, u8 rd, u8 rs);
extern u8 sub_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Multiplication *****/
extern u8 mul_r32(u8 *buf, u8 rd, u8 rs);
extern u8 mul_r32_i32(u8 *buf, u8 rd, s32 imm);
extern u8 mul_r64(u8 *buf, u8 rd, u8 rs);
extern u8 mul_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Division *****/
extern u8 div_r32(u8 *buf, u8 rd, u8 rs);
extern u8 div_r32_i32(u8 *buf, u8 rd, s32 imm);
/***** Remainder *****/
extern u8 mod_r32(u8 *buf, u8 rd, u8 rs);
extern u8 mod_r32_i32(u8 *buf, u8 rd, s32 imm);
/***** Bitwise AND *****/
extern u8 and_r32(u8 *buf, u8 rd, u8 rs);
extern u8 and_r32_i32(u8 *buf, u8 rd, s32 imm);
extern u8 and_r64(u8 *buf, u8 rd, u8 rs);
extern u8 and_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Bitwise OR *****/
extern u8 or_r32(u8 *buf, u8 rd, u8 rs);
extern u8 or_r32_i32(u8 *buf, u8 rd, s32 imm);
extern u8 or_r64(u8 *buf, u8 rd, u8 rs);
extern u8 or_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Bitwise XOR *****/
extern u8 xor_r32(u8 *buf, u8 rd, u8 rs);
extern u8 xor_r32_i32(u8 *buf, u8 rd, s32 imm);
extern u8 xor_r64(u8 *buf, u8 rd, u8 rs);
extern u8 xor_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Bitwise Negate *****/
extern u8 neg_r32(u8 *buf, u8 r);
extern u8 neg_r64(u8 *buf, u8 r);
/***** Bitwise left shift *****/
extern u8 lsh_r32(u8 *buf, u8 rd, u8 rs);
extern u8 lsh_r32_i32(u8 *buf, u8 rd, u8 imm);
extern u8 lsh_r64(u8 *buf, u8 rd, u8 rs);
extern u8 lsh_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Bitwise right shift (logical) *****/
extern u8 rsh_r32(u8 *buf, u8 rd, u8 rs);
extern u8 rsh_r32_i32(u8 *buf, u8 rd, u8 imm);
extern u8 rsh_r64(u8 *buf, u8 rd, u8 rs);
extern u8 rsh_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Bitwise right shift (arithmetic) *****/
extern u8 arsh_r32(u8 *buf, u8 rd, u8 rs);
extern u8 arsh_r32_i32(u8 *buf, u8 rd, u8 imm);
extern u8 arsh_r64(u8 *buf, u8 rd, u8 rs);
extern u8 arsh_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Moves *****/
extern u8 mov_r32(u8 *buf, u8 rd, u8 rs);
extern u8 mov_r32_i32(u8 *buf, u8 reg, s32 imm);
extern u8 mov_r64(u8 *buf, u8 rd, u8 rs);
extern u8 mov_r64_i32(u8 *buf, u8 reg, s32 imm);
extern u8 mov_r64_i64(u8 *buf, u8 reg, u32 lo, u32 hi);
/***** Loads and stores *****/
extern u8 load_r(u8 *buf, u8 rd, u8 rs, s16 off, u8 size);
extern u8 store_r(u8 *buf, u8 rd, u8 rs, s16 off, u8 size);
extern u8 store_i(u8 *buf, s32 imm, u8 rd, s16 off, u8 size);
/***** Frame related *****/
extern u32 mask_for_used_regs(u8 bpf_reg, bool is_call);
extern u8 arc_prologue(u8 *buf, u32 usage, u16 frame_size);
extern u8 arc_epilogue(u8 *buf, u32 usage, u16 frame_size);
/***** Jumps *****/
/*
 * Different sorts of conditions (ARC enum as opposed to BPF_*).
 *
 * Do not change the order of enums here. ARC_CC_SLE+1 is used
 * to determine the number of JCCs.
 */
enum ARC_CC
{
	ARC_CC_UGT = 0,		/* unsigned >  */
	ARC_CC_UGE,		/* unsigned >= */
	ARC_CC_ULT,		/* unsigned <  */
	ARC_CC_ULE,		/* unsigned <= */
	ARC_CC_SGT,		/*   signed >  */
	ARC_CC_SGE,		/*   signed >= */
	ARC_CC_SLT,		/*   signed <  */
	ARC_CC_SLE,		/*   signed <= */
	ARC_CC_AL,		/* always      */
	ARC_CC_EQ,		/*          == */
	ARC_CC_NE,		/*          != */
	ARC_CC_SET,		/* test        */
	ARC_CC_LAST
};
/* Prerequisites to call the gen_jmp_{32,64}() functions. */
extern bool check_jmp_32(ARC_ADDR curr_addr, ARC_ADDR targ_addr, u8 cond);
extern bool check_jmp_64(ARC_ADDR curr_addr, ARC_ADDR targ_addr, u8 cond);
extern u8 gen_jmp_32(u8 *buf, u8 rd, u8 rs, u8 cond, ARC_ADDR targ_addr);
extern u8 gen_jmp_64(u8 *buf, u8 rd, u8 rs, u8 cond, ARC_ADDR targ_addr);
extern u8 gen_func_call(u8 *buf, ARC_ADDR func_addr, bool external_func);
/***** Miscellaneous *****/
extern u8 gen_swap(u8 *buf, u8 rd, u8 size, u8 endian);

#endif /* _BPF_JIT_CORE_H */
