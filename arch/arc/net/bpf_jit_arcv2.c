/* TODO: Remove me? */
#include <linux/filter.h>

/* For the extern proto-types */
#include "bpf_jit_core.h"

/*
 * bpf2arc array maps BPF registers to ARC registers. For the translation
 * of some BPF instructions, a pair of temporary registers might be required.
 * This temporary register is added as yet another index in the bpf2arc array,
 * so it will unfold like the rest of registers during the code generation
 * process.
 */
#define JIT_REG_TMP MAX_BPF_JIT_REG

/*
 * Remarks about the rationale behind the chosen mapping:
 *
 * - BPF_REG_{1,2,3,4} are the argument registers and must be mapped to
 *   argument registers in ARCv2 ABI: r0-r7. The r7 registers is the last
 *   argument register in the ABI. Therefore BPF_REG_5, as the fifth
 *   argument, must be pushed onto the stack. This is a must for calling
 *   in-kernel functions.
 *
 * - In ARCv2 ABI, the return value is in r0 for 32-bit results and (r1,r0)
 *   for 64-bit results. However, because they're already used for BPF_REG_1,
 *   the next available scratch registers, r8 and r9, are the best candidates
 *   for BPF_REG_0. After a "call" to a(n) (in-kernel) function, the result
 *   is "mov"ed to these registers. At a BPF_EXIT, their value is "mov"ed to
 *   (r1,r0).
 *   It is worth mentioning that scratch registers are the best choice for
 *   BPF_REG_0, because it is very popular in BPF instruction encoding.
 *
 * - JIT_REG_TMP is an artifact needed to translate some BPF instructions.
 *   Its life span is one single BPF instruction. Since during the
 *   analyze_reg_usage(), it is not known if temporary registers are used,
 *   it is mapped to ARC's scratch registers: r10 and r11. Therefore, they
 *   don't matter in analysing phase and don't need saving.
 *
 * - Mapping of callee-saved BPF registers, BPF_REG_{6,7,8,9}, starts from
 *   (r15,r14) register pair. The (r13,r12) is not a good choice, because
 *   in ARCv2 ABI, r12 is not a callee-saved register and this can cause
 *   problem when calling an in-kernel function. Theoretically, the mapping
 *   could start from (r14,r13), but it is not a conventional ARCv2 register
 *   pair. To have a future proof design, I opted for this arrangement.
 *   If/when we decide to add ARCv2 instructions that do use register pairs,
 *   the mapping (hopefully) doesn't need to be revisited.
 */
const u8 bpf2arc[][2] = {
	/* Return value from in-kernel function, and exit value from eBPF */
	[BPF_REG_0] = {ARC_R_8 , ARC_R_9},
	/* Arguments from eBPF program to in-kernel function */
	[BPF_REG_1] = {ARC_R_0 , ARC_R_1},
	[BPF_REG_2] = {ARC_R_2 , ARC_R_3},
	[BPF_REG_3] = {ARC_R_4 , ARC_R_5},
	[BPF_REG_4] = {ARC_R_6 , ARC_R_7},
	/* Remaining arguments, to be passed on the stack per O32 ABI */
	[BPF_REG_5] = {ARC_R_22, ARC_R_23},
	/* Callee-saved registers that in-kernel function will preserve */
	[BPF_REG_6] = {ARC_R_14, ARC_R_15},
	[BPF_REG_7] = {ARC_R_16, ARC_R_17},
	[BPF_REG_8] = {ARC_R_18, ARC_R_19},
	[BPF_REG_9] = {ARC_R_20, ARC_R_21},
	/* Read-only frame pointer to access the eBPF stack. 32-bit only. */
	[BPF_REG_FP] = {ARC_R_FP, },
	/* Register for blinding constants */
	[BPF_REG_AX] = {ARC_R_24, ARC_R_25},
	/* Temporary registers for internal use */
	[JIT_REG_TMP] = {ARC_R_10, ARC_R_11}
};

/*
 * To comply with ARCv2 ABI, BPF's arg5 must be put on stack. After which,
 * the stack needs to be restored by ARG5_SIZE.
 */
#define ARG5_SIZE 8

/* Instruction lengths in bytes. */
enum {
	INSN_len_short = 2,	/* Short instructions length. */
	INSN_len_normal = 4	/* Normal instructions length. */
};

/* ZZ defines the size of operation in encodings that it is used. */
enum {
	ZZ_1_byte = 1,
	ZZ_2_byte = 2,
	ZZ_4_byte = 0,
	ZZ_8_byte = 3
};

/*
 * AA is mostly about address write back mode. It determines if the
 * address in question should be updated before usage or after:
 *   addr += offset; data = *addr;
 *   data = *addr; addr += offset;
 *
 * In "scaling" mode, the effective address will become the sum
 * of "address" + "index"*"size". The "size" is specified by the
 * "ZZ" field. There is no write back when AA is set for scaling:
 *   data = *(addr + offset<<zz)
 */
enum {
	AA_none  = 0,
	AA_pre   = 1,	/* in assembly known as "a/aw". */
	AA_post  = 2,	/* in assembly known as "ab". */
	AA_scale = 3	/* in assembly known as "as". */
};

/* D flag specifies how a memory access should be done. */
enum {
	D_cached = 0,
	D_direct = 1
};

/* X flag determines the mode of extension. */
enum {
	X_zero = 0,
	X_sign = 1
};

/* Condition codes. */
enum {
	CC_always     = 0,	/* condition is true all the time */
	CC_equal      = 1,	/* if status32.z flag is set */
	CC_unequal    = 2,	/* if status32.z flag is clear */
	CC_positive   = 3,	/* if status32.n flag is clear */
	CC_negative   = 4,	/* if status32.n flag is set */
	CC_less_u     = 5,	/* less than (unsigned) */
	CC_less_eq_u  = 14,	/* less than or equal (unsigned) */
	CC_great_eq_u = 6,	/* greater than or equal (unsigned) */
	CC_great_u    = 13,	/* greater than (unsigned) */
	CC_less_s     = 11,	/* less than (signed) */
	CC_less_eq_s  = 12,	/* less than or equal (signed) */
	CC_great_eq_s = 10,	/* greater than or equal (signed) */
	CC_great_s    = 9	/* greater than (signed) */
};

#define IN_U6_RANGE(x)	((x) <= (0x40      - 1) && (x) >= 0)
#define IN_S9_RANGE(x)	((x) <= (0x100     - 1) && (x) >= -0x100)
#define IN_S12_RANGE(x)	((x) <= (0x800     - 1) && (x) >= -0x800)
#define IN_S21_RANGE(x)	((x) <= (0x100000  - 1) && (x) >= -0x100000)
#define IN_S25_RANGE(x)	((x) <= (0x1000000 - 1) && (x) >= -0x1000000)

/* Operands in most of the encodings. */
#define OP_A(x)	((x) & 0x03f)
#define OP_B(x)	((((x) & 0x07) << 24) | (((x) & 0x38) <<  9))
#define OP_C(x)	(((x) & 0x03f) << 6)
#define OP_0	(OP_A(ARC_R_IMM))
#define OP_IMM	(OP_C(ARC_R_IMM))
#define COND(x)	(OP_A((x) & 31))
#define FLAG(x)	(((x) & 1) << 15)

/*
 * The 4-byte encoding of "add a,b,c":
 *
 * 0010_0bbb 0000_0000 fBBB_cccc ccaa_aaaa
 *
 * f:                   indicates if flags (carry, etc.) should be updated
 *
 * a:  aaaaaa		result
 * b:  BBBbbb		the 1st input operand
 * c:  cccccc		the 2nd input operand
 */
#define OPC_ADD		0x20000000
/* Addition with updating the pertinent flags in "status32" register. */
#define OPC_ADDF	(OPC_ADD | FLAG(1))
#define ADDI		(1 << 22)
#define ADDI_U6(x)	OP_C(x)
#define OPC_ADDI	(OPC_ADD | ADDI)
#define OPC_ADDIF	(OPC_ADDI | FLAG(1))
#define OPC_ADD_I	(OPC_ADD | OP_IMM)

/*
 * The 4-byte encoding of "adc a,b,c" (addition with carry):
 *
 * 0010_0bbb 0000_0001 0BBB_cccc ccaa_aaaa
 *
 * a:  aaaaaa		result
 * b:  BBBbbb		the 1st input operand
 * c:  cccccc		the 2nd input operand
 */
#define OPC_ADC		0x20010000
#define ADCI		(1 << 22)
#define ADCI_U6(x)	OP_C(x)
#define OPC_ADCI	(OPC_ADC | ADCI)

/*
 * The 4-byte encoding of "sub a,b,c":
 *
 * 0010_0bbb 0000_0010 fBBB_cccc ccaa_aaaa
 *
 * f:                   indicates if flags (carry, etc.) should be updated
 *
 * a:  aaaaaa		result
 * b:  BBBbbb		the 1st input operand
 * c:  cccccc		the 2nd input operand
 */
#define OPC_SUB		0x20020000
/* Subtraction with updating the pertinent flags in "status32" register. */
#define OPC_SUBF	(OPC_SUB | FLAG(1))
#define SUBI		(1 << 22)
#define SUBI_U6(x)	OP_C(x)
#define OPC_SUBI	(OPC_SUB | SUBI)
#define OPC_SUB_I	(OPC_SUB | OP_IMM)

/*
 * The 4-byte encoding of "sbc a,b,c" (subtraction with carry):
 *
 * 0010_0bbb 0000_0011 fBBB_cccc ccaa_aaaa
 *
 * f:                   indicates if flags (carry, etc.) should be updated
 *
 * a:  aaaaaa		result
 * b:  BBBbbb		the 1st input operand
 * c:  cccccc		the 2nd input operand
 */
#define OPC_SBC		0x20030000

/*
 * The 4-byte encoding of "cmp[.qq] b,c":
 *
 * 0010_0bbb 1100_1100 1BBB_cccc cc0q_qqqq
 *
 * qq:	qqqqq		condtion code
 *
 * b:  BBBbbb		the 1st operand
 * c:  cccccc		the 2nd operand
 */
#define OPC_CMP		0x20cc8000
#define OPC_CMP_I	(OPC_CMP | OP_IMM)

/*
 * The 4-byte encoding of "neg a,b":
 *
 * 0010_0bbb 0100_1110 0BBB_0000 00aa_aaaa
 *
 * a:  BBBbbb		result
 * b:  BBBbbb		input
 */
#define OPC_NEG		0x204e0000

/*
 * The 4-byte encoding of "mpy a,b,c".
 * mpy is the signed 32-bit multiplication with the lower 32-bit
 * of the product as the result.
 *
 * 0010_0bbb 0001_1010 0BBB_cccc ccaa_aaaa
 *
 * a:  aaaaaa		result
 * b:  BBBbbb		the 1st input operand
 * c:  cccccc		the 2nd input operand
 */
#define OPC_MPY		0x201a0000
#define OPC_MPYI	OPC_MPY | OP_IMM

/*
 * The 4-byte encoding of "mpydu a,b,c".
 * mpydu is the unsigned 32-bit multiplication with the lower 32-bit of
 * the product in register "a" and the higher 32-bit in register "a+1".
 *
 * 0010_1bbb 0001_1001 0BBB_cccc ccaa_aaaa
 *
 * a:  aaaaaa		64-bit result in registers (R_a+1,R_a)
 * b:  BBBbbb		the 1st input operand
 * c:  cccccc		the 2nd input operand
 */
#define OPC_MPYDU	0x28190000
#define OPC_MPYDUI	OPC_MPYDU | OP_IMM

/*
 * The 4-byte encoding of "div a,b,c":
 *
 * 0010_1bbb 0000_0101 0BBB_cccc ccaa_aaaa
 *
 * a:  aaaaaa		result (quotient)
 * b:  BBBbbb		the 1st input operand
 * c:  cccccc		the 2nd input operand (divisor)
 */
#define OPC_DIVU	0x28050000
#define OPC_DIVUI	OPC_DIVU | OP_IMM

/*
 * The 4-byte encoding of "rem a,b,c":
 *
 * 0010_1bbb 0000_1001 0BBB_cccc ccaa_aaaa
 *
 * a:  aaaaaa		result (remainder)
 * b:  BBBbbb		the 1st input operand
 * c:  cccccc		the 2nd input operand (divisor)
 */
#define OPC_REMU	0x28090000
#define OPC_REMUI	OPC_REMU | OP_IMM

/*
 * The 4-byte encoding of "and a,b,c":
 *
 * 0010_0bbb 0000_0100 fBBB_cccc ccaa_aaaa
 *
 * f:                   indicates if zero and negative flags should be updated
 *
 * a:  aaaaaa		result
 * b:  BBBbbb		the 1st input operand
 * c:  cccccc		the 2nd input operand
 */
#define OPC_AND		0x20040000
#define OPC_ANDI	(OPC_AND | OP_IMM)

/*
 * The 4-byte encoding of "tst[.qq] b,c":
 *
 * 0010_0bbb 1100_1011 1BBB_cccc cc0q_qqqq
 *
 * qq:	qqqqq		condtion code
 *
 * b:  BBBbbb		the 1st input operand
 * c:  cccccc		the 2nd input operand
 */
#define OPC_TST		0x20cb8000
#define OPC_TSTI	(OPC_TST | OP_IMM)

/*
 * The 4-byte encoding of "or a,b,c":
 *
 * 0010_0bbb 0000_0101 0BBB_cccc ccaa_aaaa
 *
 * a:  aaaaaa		result
 * b:  BBBbbb		the 1st input operand
 * c:  cccccc		the 2nd input operand
 */
#define OR_OPCODE	0x20050000
#define OPC_ORI		OR_OPCODE | OP_IMM

/*
 * The 4-byte encoding of "xor a,b,c":
 *
 * 0010_0bbb 0000_0111 0BBB_cccc ccaa_aaaa
 *
 * a:  aaaaaa		result
 * b:  BBBbbb		the 1st input operand
 * c:  cccccc		the 2nd input operand
 */
#define XOR_OPCODE	0x20070000
#define OPC_XORI	XOR_OPCODE | OP_IMM

/*
 * The 4-byte encoding of "not b,c":
 *
 * 0010_0bbb 0010_1111 0BBB_cccc cc00_1010
 *
 * b:  BBBbbb		result
 * c:  cccccc		input
 */
#define NOT_OPCODE	0x202f000a

/*
 * The 4-byte encoding of "btst b,u6":
 *
 * 0010_0bbb 0101_0001 1BBB_uuuu uu00_0000
 *
 * b:  BBBbbb		input number to check
 * u6: uuuuuu		6-bit unsigned number specifying bit position to check
 */
#define BTSTU6_OPCODE	0x20518000
#define BTST_U6(x)	(OP_C((x) & 63))

/*
 * The 4-byte encoding of "asl[.qq] b,b,c" (arithmetic shift left):
 *
 * 0010_1bbb 0i00_0000 0BBB_cccc ccaa_aaaa
 *
 * i:			if set, c is considered a 5-bit immediate, else a reg.
 *
 * b:  BBBbbb		result and the first operand (number to be shifted)
 * c:  cccccc		amount to be shifted
 */
#define ASL_OPCODE	0x28000000
#define ASL_I		(1 << 22)
#define ASLI_U6(x)	OP_C((x) & 31)
#define OPC_ASLI	(ASL_OPCODE | ASL_I)

/*
 * The 4-byte encoding of "asr a,b,c" (arithmetic shift right):
 *
 * 0010_1bbb 0i00_0010 0BBB_cccc ccaa_aaaa
 *
 * i:			if set, c is considered a 6-bit immediate, else a reg.
 *
 * a:  aaaaaa		result
 * b:  BBBbbb		first input:  number to be shifted
 * c:  cccccc		second input: amount to be shifted
 */
#define ASR_OPCODE	0x28020000
#define ASR_I		ASL_I
#define ASRI_U6(x)	ASLI_U6(x)
#define OPC_ASRI	(ASR_OPCODE | ASR_I)

/*
 * The 4-byte encoding of "lsr a,b,c" (logical shift right):
 *
 * 0010_1bbb 0i00_0001 0BBB_cccc ccaa_aaaa
 *
 * i:			if set, c is considered a 6-bit immediate, else a reg.
 *
 * a:  aaaaaa		result
 * b:  BBBbbb		first input:  number to be shifted
 * c:  cccccc		second input: amount to be shifted
 */
#define LSR_OPCODE	0x28010000
#define LSR_I		ASL_I
#define LSRI_U6(x)	ASLI_U6(x)
#define OPC_LSRI	LSR_OPCODE | LSR_I

/*
 * The 4-byte encoding of "swape b,c":
 *
 * 0010_1bbb 0010_1111 0bbb_cccc cc00_1001
 *
 * b:  BBBbbb		destination register
 * c:  cccccc		source register
 */
#define OPC_SWAPE	0x282f0009

/*
 * The 4-byte encoding of "mov b,c":
 *
 * 0010_0bbb 0000_1010 0BBB_cccc cc00_0000
 *
 * b:  BBBbbb		destination register
 * c:  cccccc		source register
 */
#define MOV_OPCODE	0x200a0000

/*
 * The 4-byte encoding of "mov b,s12" (used for moving small immediates):
 *
 * 0010_0bbb 1000_1010 0BBB_ssss ssSS_SSSS
 *
 * b:  BBBbbb		destination register
 * s:  SSSSSSssssss	source immediate (signed)
 */
#define MOVI_OPCODE	0x208a0000
#define MOVI_S12(x)	((((x) & 0xfc0) >> 6) | (((x) & 0x3f) << 6))

/*
 * The 4-byte encoding of "mov[.qq] b,u6", used for conditional
 * moving of even smaller immediates:
 *
 * 0010_0bbb 1100_1010 0BBB_cccc cciq_qqqq
 *
 * qq: qqqqq		condition code
 * i:			If set, c is considered a 6-bit unsigned number iso reg.
 *
 * b:  BBBbbb		destination register
 * c:  cccccc		source
 */
#define MOV_CC_OPCODE	0x20ca0000
#define OPC_MOV_CC	MOV_CC_OPCODE
#define MOV_CC_I	(1 << 5)
#define OPC_MOVU_CC	MOV_CC_OPCODE | MOV_CC_I

/*
 * The 4-byte encoding of "ld[zz][.x][.aa][.di] c,[b,s9]":
 *
 * 0001_0bbb ssss_ssss SBBB_daaz zxcc_cccc
 *
 * zz:			size mode
 * aa:			address write back mode
 * d:			memory access mode
 * x:			extension mode
 *
 * s9: S_ssss_ssss	9-bit signed number
 * b:  BBBbbb		source reg for address
 * c:  cccccc		destination register
 */
#define LOAD_OPCODE	0x10000000
#define LOAD_X(x)	((x) << 6)
#define LOAD_ZZ(x)	((x) << 7)
#define LOAD_AA(x)	((x) << 9)
#define LOAD_D(x)	((x) << 11)
#define LOAD_S9(x)	((((x) & 0x0ff) << 16) | (((x) & 0x100) <<  7))
#define LOAD_C(x)	((x) & 0x03f)
/* Generic load. */
#define OPC_LD		LOAD_OPCODE | LOAD_D(D_cached) | LOAD_X(X_zero)
/* 32-bit load. */
#define OPC_LD32	OPC_LD | LOAD_ZZ(ZZ_4_byte)
/* "pop reg" is merely a "ld.ab reg,[sp,4]". */
#define OPC_POP		\
	OPC_LD32 | LOAD_AA(AA_post) | LOAD_S9(4) | OP_B(ARC_R_SP)

/*
 * The 4-byte encoding of "st[zz][.aa][.di] c,[b,s9]":
 *
 * 0001_1bbb ssss_ssss SBBB_cccc ccda_azz0
 *
 * zz: zz		size mode
 * aa: aa		address write back mode
 * d:  d		memory access mode
 *
 * s9: S_ssss_ssss	9-bit signed number
 * b:  BBBbbb		source reg for address
 * c:  cccccc		source reg to be stored
 */
#define STORE_OPCODE	0x18000000
#define STORE_ZZ(x)	((x) << 1)
#define STORE_AA(x)	((x) << 3)
#define STORE_D(x)	((x) << 5)
#define STORE_S9(x)	((((x) & 0x0ff) << 16) | (((x) & 0x100) <<  7))
/* Generic store. */
#define OPC_ST		STORE_OPCODE | STORE_D(D_cached)
/* 32-bit store. */
#define OPC_ST32	OPC_ST | STORE_ZZ(ZZ_4_byte)
/* "push reg" is merely a "st.aw reg,[sp,-4]". */
#define OPC_PUSH	\
	OPC_ST32 | STORE_AA(AA_pre) | STORE_S9(-4) | OP_B(ARC_R_SP)

/*
 * Encoding for jump to an address in register:
 * j reg_c
 *
 * 0010_0000 1110_0000 0000_cccc cc00_0000
 *
 * c:  cccccc		register holding the destination address
 */
#define JMP_OPCODE	0x20e00000
/* Jump to "branch-and-link" register, which effectively is a "return". */
#define OPC_J_BLINK	JMP_OPCODE | OP_C(ARC_R_BLINK)

/*
 * Encoding for jump-and-link to an address in register:
 * jl reg_c
 *
 * 0010_0000 0010_0010 0000_cccc cc00_0000
 *
 * c:  cccccc		register holding the destination address
 */
#define JL_OPCODE	0x20220000

/*
 * Encoding for (conditional) branch to an offset from the current location
 * that is word aligned: (PC & ~0xffff_fff4) + s21
 * B[qq] s21
 *
 * 0000_0sss ssss_sss0 SSSS_SSSS SS0q_qqqq
 *
 * qq:	qqqqq				condtion code
 * s21:	SSSS SSSS_SSss ssss_ssss	The displacement (21-bit signed)
 *
 * The displacement is supposed to be 16-bit (2-byte) aligned. Therefore,
 * it should be a multiple of 2. Hence, there is an implied '0' bit at its
 * LSB: S_SSSS SSSS_Ssss ssss_sss0
 */
#define BCC_OPCODE	0x00000000
#define BCC_S21(d)	((((d) & 0x7fe) << 16) | (((d) & 0x1ff800) >> 5))

/*
 * Encoding for unconditinal branch to an offset from the current location
 * that is word aligned: (PC & ~0xffff_fff4) + s25
 * B s25
 *
 * 0000_0sss ssss_sss1 SSSS_SSSS SS00_TTTT
 *
 * s25:	TTTT SSSS SSSS_SSss ssss_ssss	The displacement (25-bit signed)
 *
 * The displacement is supposed to be 16-bit (2-byte) aligned. Therefore,
 * it should be a multiple of 2. Hence, there is an implied '0' bit at its
 * LSB: T TTTS_SSSS SSSS_Ssss ssss_sss0
 */
#define B_OPCODE	0x00010000
#define B_S25(d)	((((d) & 0x1e00000) >> 21) | BCC_S21(d))

static inline void emit_2_bytes(u8 *buf, u16 bytes)
{
	*((u16 *) buf) = bytes;
}

static inline void emit_4_bytes(u8 *buf, u32 bytes)
{
	emit_2_bytes(buf+0, bytes >>     16);
	emit_2_bytes(buf+2, bytes  & 0xffff);
}

static inline u8 bpf_to_arc_size(u8 size)
{
	switch (size) {
	case BPF_B:
		return ZZ_1_byte;
	case BPF_H:
		return ZZ_2_byte;
	case BPF_W:
		return ZZ_4_byte;
	case BPF_DW:
		return ZZ_8_byte;
	default:
		return ZZ_4_byte;
	}
}

/*********************** Encoders ************************/

/* add Ra,Ra,Rc */
static u8 arc_add_r(u8 *buf, u8 ra, u8 rc)
{
	if (emit) {
		const u32 insn = OPC_ADD | OP_A(ra) | OP_B(ra) | OP_C(rc);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* add.f Ra,Ra,Rc */
static u8 arc_addf_r(u8 *buf, u8 ra, u8 rc)
{
	if (emit) {
		const u32 insn = OPC_ADDF | OP_A(ra) | OP_B(ra) | OP_C(rc);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* add.f Ra,Ra,u6 */
static u8 arc_addif_r(u8 *buf, u8 ra, u8 u6)
{
	if (emit) {
		const u32 insn = OPC_ADDIF | OP_A(ra) | OP_B(ra) | ADDI_U6(u6);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* add Ra,Ra,u6 */
static u8 arc_addi_r(u8 *buf, u8 ra, u8 u6)
{
	if (emit) {
		const u32 insn = OPC_ADDI | OP_A(ra) | OP_B(ra) | ADDI_U6(u6);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* add Ra,Rb,imm */
static u8 arc_add_i(u8 *buf, u8 ra, u8 rb, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_ADD_I | OP_A(ra) | OP_B(rb);
		emit_4_bytes(buf                , insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

/* adc Ra,Ra,Rc */
static u8 arc_adc_r(u8 *buf, u8 ra, u8 rc)
{
	if (emit) {
		const u32 insn = OPC_ADC | OP_A(ra) | OP_B(ra) | OP_C(rc);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* adc Ra,Ra,u6 */
static u8 arc_adci_r(u8 *buf, u8 ra, u8 u6)
{
	if (emit) {
		const u32 insn = OPC_ADCI | OP_A(ra) | OP_B(ra) | ADCI_U6(u6);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* sub Ra,Ra,Rc */
static u8 arc_sub_r(u8 *buf, u8 ra, u8 rc)
{
	if (emit) {
		const u32 insn = OPC_SUB | OP_A(ra) | OP_B(ra) | OP_C(rc);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* sub.f Ra,Ra,Rc */
static u8 arc_subf_r(u8 *buf, u8 ra, u8 rc)
{
	if (emit) {
		const u32 insn = OPC_SUBF | OP_A(ra) | OP_B(ra) | OP_C(rc);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* sub Ra,Ra,u6 */
static u8 arc_subi_r(u8 *buf, u8 ra, u8 u6)
{
	if (emit) {
		const u32 insn = OPC_SUBI | OP_A(ra) | OP_B(ra) | SUBI_U6(u6);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* sub Ra,Ra,imm */
static u8 arc_sub_i(u8 *buf, u8 ra, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_SUB_I | OP_A(ra) | OP_B(ra);
		emit_4_bytes(buf                , insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

/* sbc Ra,Ra,Rc */
static u8 arc_sbc_r(u8 *buf, u8 ra, u8 rc)
{
	if (emit) {
		const u32 insn = OPC_SBC | OP_A(ra) | OP_B(ra) | OP_C(rc);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* cmp Rb,Rc */
static u8 arc_cmp_r(u8 *buf, u8 rb, u8 rc)
{
	if (emit) {
		const u32 insn = OPC_CMP | OP_B(rb) | OP_C(rc);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* cmp Rb,imm */
static u8 arc_cmp_i(u8 *buf, u8 rb, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_CMP_I | OP_B(rb);
		emit_4_bytes(buf                , insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

/*
 * cmp.z Rb,Rc
 *
 * This "cmp.z" variant of compare instruction is used on lower
 * 32-bits of register pairs after "cmp"ing their upper parts. If the
 * upper parts are equal (z), then this one will proceed to check the
 * rest.
 */
static u8 arc_cmpz_r(u8 *buf, u8 rb, u8 rc)
{
	if (emit) {
		const u32 insn = OPC_CMP | OP_B(rb) | OP_C(rc) | CC_equal;
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* neg Ra,Rb */
static u8 arc_neg_r(u8 *buf, u8 ra, u8 rb)
{
	if (emit) {
		const u32 insn = OPC_NEG | OP_A(ra) | OP_B(rb);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* mpy Ra,Rb,Rc */
static u8 arc_mpy_r(u8 *buf, u8 ra, u8 rb, u8 rc)
{
	if (emit) {
		const u32 insn = OPC_MPY | OP_A(ra) | OP_B(rb) | OP_C(rc);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* mpy Ra,Rb,imm */
static u8 arc_mpy_i(u8 *buf, u8 ra, u8 rb, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_MPYI | OP_A(ra) | OP_B(rb);
		emit_4_bytes(buf, insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

/* mpydu Ra,Ra,Rc */
static u8 arc_mpydu_r(u8 *buf, u8 ra, u8 rc)
{
	if (emit) {
		const u32 insn = OPC_MPYDU | OP_A(ra) | OP_B(ra) | OP_C(rc);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* mpydu Ra,Ra,imm */
static u8 arc_mpydu_i(u8 *buf, u8 ra, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_MPYDUI | OP_A(ra) | OP_B(ra);
		emit_4_bytes(buf, insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

static u8 arc_divu_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_DIVU | OP_A(rd) | OP_B(rd) | OP_C(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_divu_i(u8 *buf, u8 rd, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_DIVUI | OP_A(rd) | OP_B(rd);
		emit_4_bytes(buf, insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

static u8 arc_remu_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_REMU | OP_A(rd) | OP_B(rd) | OP_C(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_remu_i(u8 *buf, u8 rd, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_REMUI | OP_A(rd) | OP_B(rd);
		emit_4_bytes(buf, insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

static u8 arc_and_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_AND | OP_A(rd) | OP_B(rd) | OP_C(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_and_i(u8 *buf, u8 rd, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_ANDI | OP_A(rd) | OP_B(rd);
		emit_4_bytes(buf                , insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

static u8 arc_tst_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_TST | OP_B(rd) | OP_C(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_tst_i(u8 *buf, u8 rd, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_TSTI | OP_B(rd);
		emit_4_bytes(buf                , insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

/*
 * This particular version, "tst.z ...", is meant to be used after a
 * "tst" on the low 32-bit of register pairs. If that "tst" is not
 * zero, then we don't need to test the upper 32-bits lest it sets
 * the zero flag.
 */
static u8 arc_tstz_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_TST | OP_B(rd) | OP_C(rs) | CC_equal;
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_or_r(u8 *buf, u8 rd, u8 rs1, u8 rs2)
{
	if (emit) {
		const u32 insn = OR_OPCODE | OP_A(rd) | OP_B(rs1) | OP_C(rs2);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_or_i(u8 *buf, u8 rd, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_ORI | OP_A(rd) | OP_B(rd);
		emit_4_bytes(buf                , insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

static u8 arc_xor_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = XOR_OPCODE | OP_A(rd) | OP_B(rd) | OP_C(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_xor_i(u8 *buf, u8 rd, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_XORI | OP_A(rd) | OP_B(rd);
		emit_4_bytes(buf                , insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

static u8 arc_not_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = NOT_OPCODE | OP_B(rd) | OP_C(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_btst_i(u8 *buf, u8 rs, u8 imm)
{
	if (emit) {
		const u32 insn = BTSTU6_OPCODE | OP_B(rs) | BTST_U6(imm);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_asl_r(u8 *buf, u8 rd, u8 rs1, u8 rs2)
{
	if (emit) {
		const u32 insn = ASL_OPCODE | OP_A(rd) | OP_B(rs1) | OP_C(rs2);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_asli_r(u8 *buf, u8 rd, u8 rs, u8 imm)
{
	if (emit) {
		const u32 insn = OPC_ASLI | OP_A(rd) | OP_B(rs) | ASLI_U6(imm);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_asr_r(u8 *buf, u8 rd, u8 rs1, u8 rs2)
{
	if (emit) {
		const u32 insn = ASR_OPCODE | OP_A(rd) | OP_B(rs1) | OP_C(rs2);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_asri_r(u8 *buf, u8 rd, u8 rs, u8 imm)
{
	if (emit) {
		const u32 insn = OPC_ASRI | OP_A(rd) | OP_B(rs) | ASRI_U6(imm);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_lsr_r(u8 *buf, u8 rd, u8 rs1, u8 rs2)
{
	if (emit) {
		const u32 insn = LSR_OPCODE | OP_A(rd) | OP_B(rs1) | OP_C(rs2);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_lsri_r(u8 *buf, u8 rd, u8 rs, u8 imm)
{
	if (emit) {
		const u32 insn = OPC_LSRI | OP_A(rd) | OP_B(rs) | LSRI_U6(imm);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_swape_r(u8 *buf, u8 r)
{
	if (emit) {
		const u32 insn = OPC_SWAPE | OP_B(r) | OP_C(r);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* Move an immediate to register with a 4-byte instruction. */
static u8 arc_movi_r(u8 *buf, u8 reg, s16 imm)
{
	if (emit) {
		const u32 insn = MOVI_OPCODE | OP_B(reg) | MOVI_S12(imm);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_mov_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = MOV_OPCODE | OP_B(rd) | OP_C(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* The emitted code may have different sizes based on "imm". */
static u8 arc_mov_i(u8 *buf, u8 rd, s32 imm)
{
	if (IN_S12_RANGE(imm))
		return arc_movi_r(buf, rd, imm);

	if (emit) {
		const u32 insn = MOV_OPCODE | OP_B(rd) | OP_IMM;
		emit_4_bytes(buf                , insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

/* The emitted code will always have the same size (8). */
static u8 arc_mov_i_fixed(u8 *buf, u8 rd, s32 imm)
{
	if (emit) {
		const u32 insn = MOV_OPCODE | OP_B(rd) | OP_IMM;
		emit_4_bytes(buf                , insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

static u8 arc_mov_cc_r(u8 *buf, u8 cc, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_MOV_CC | OP_B(rd) | OP_C(rs) | COND(cc);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_movu_cc_r(u8 *buf, u8 cc, u8 rd, u8 imm)
{
	if (emit) {
		const u32 insn = OPC_MOVU_CC | OP_B(rd) | OP_C(imm) | COND(cc);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* st reg, [reg_mem, off] */
static u8 arc_st_r(u8 *buf, u8 reg, u8 reg_mem, s16 off, u8 zz)
{
	if (emit) {
		const u32 insn = OPC_ST | STORE_AA(AA_none) | STORE_ZZ(zz) |
			   OP_C(reg) | OP_B(reg_mem) | STORE_S9(off);
		emit_4_bytes(buf, insn);
	}

	return INSN_len_normal;
}

/* "push reg" is merely a "st.aw reg, [sp, -4]". */
static u8 arc_push_r(u8 *buf, u8 reg)
{
	if (emit) {
		const u32 insn = OPC_PUSH | OP_C(reg);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* ld reg, [reg_mem, off] */
static u8 arc_ld_r(u8 *buf, u8 reg, u8 reg_mem, s16 off, u8 zz)
{
	if (emit) {
		const u32 insn = OPC_LD | LOAD_AA(AA_none) | LOAD_ZZ(zz) |
			   LOAD_C(reg) | OP_B(reg_mem) | LOAD_S9(off);
		emit_4_bytes(buf, insn);
	}

	return INSN_len_normal;
}

static u8 arc_pop_r(u8 *buf, u8 reg)
{
	if (emit) {
		const u32 insn = OPC_POP | LOAD_C(reg);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_jmp_return(u8 *buf)
{
	if (emit)
		emit_4_bytes(buf, OPC_J_BLINK);
	return INSN_len_normal;
}

static u8 arc_jl(u8 *buf, u8 reg)
{
	if (emit) {
		const u32 insn = JL_OPCODE | OP_C(reg);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/*
 * Conditional jump to an address that is max 21 bits away (signed).
 *
 * b<cc> s21
 */
static u8 arc_bcc(u8 *buf, u8 cc, int offset)
{
	if (emit) {
		const u32 insn = BCC_OPCODE | BCC_S21(offset) | COND(cc);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/*
 * Unconditional jump to an address that is max 25 bits away (signed).
 *
 * b     s25
 */
static u8 arc_b(u8 *buf, s32 offset)
{
	if (emit) {
		const u32 insn = B_OPCODE | B_S25(offset);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/*********************** Packers *************************/

inline u8 zext(u8 *buf, u8 rd)
{
	if (zext_thyself && rd != BPF_REG_FP)
		return arc_movi_r(buf, REG_HI(rd), 0);
	else
		return 0;
}

u8 add_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_add_r(buf, REG_LO(rd), REG_LO(rs));
}

u8 add_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	if (IN_U6_RANGE(imm))
		return arc_addi_r(buf, REG_LO(rd), imm);
	else
		return arc_add_i(buf, REG_LO(rd), REG_LO(rd), imm);
}

u8 add_r64(u8 *buf, u8 rd, u8 rs)
{
	u8 len;
	len  = arc_addf_r(buf, REG_LO(rd), REG_LO(rs));
	len += arc_adc_r(buf+len, REG_HI(rd), REG_HI(rs));
	return len;
}

u8 add_r64_i32(u8 *buf, u8 rd, s32 imm)
{
	u8 len;
	if (IN_U6_RANGE(imm)) {
		len  = arc_addif_r(buf, REG_LO(rd), imm);
		len += arc_adci_r(buf+len, REG_HI(rd), 0);
	} else {
		len  = mov_r64_i32(buf, JIT_REG_TMP, imm);
		len += add_r64(buf+len, rd, JIT_REG_TMP);
	}
	return len;
}

u8 sub_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_sub_r(buf, REG_LO(rd), REG_LO(rs));
}

u8 sub_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	if (IN_U6_RANGE(imm))
		return arc_subi_r(buf, REG_LO(rd), imm);
	else
		return arc_sub_i(buf, REG_LO(rd), imm);
}

u8 sub_r64(u8 *buf, u8 rd, u8 rs)
{
	u8 len;
	len  = arc_subf_r(buf, REG_LO(rd), REG_LO(rs));
	len += arc_sbc_r(buf+len, REG_HI(rd), REG_HI(rs));
	return len;
}

u8 sub_r64_i32(u8 *buf, u8 rd, s32 imm)
{
	u8 len;
	len  = mov_r64_i32(buf, JIT_REG_TMP, imm);
	len += sub_r64(buf+len, rd, JIT_REG_TMP);
	return len;
}

static u8 cmp_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_cmp_r(buf, REG_LO(rd), REG_LO(rs));
}

static u8 cmp_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	return arc_cmp_i(buf, REG_LO(rd), imm);
}

u8 neg_r32(u8 *buf, u8 r)
{
	return arc_neg_r(buf, REG_LO(r), REG_LO(r));
}

/* In a two's complement system, -r is (~r + 1). */
u8 neg_r64(u8 *buf, u8 r)
{
	u8 len;
	len  = arc_not_r(buf, REG_LO(r), REG_LO(r));
	len += arc_not_r(buf+len, REG_HI(r), REG_HI(r));
	len += add_r64_i32(buf+len, r, 1);
	return len;
}

u8 mul_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_mpy_r(buf, REG_LO(rd), REG_LO(rd), REG_LO(rs));
}

u8 mul_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	return arc_mpy_i(buf, REG_LO(rd), REG_LO(rd), imm);
}

/*
 * MUL B, C
 * --------
 * mpy       t0, B_hi, C_lo
 * mpy       t1, B_lo, C_hi
 * mpydu   B_lo, B_lo, C_lo
 * add     B_hi, B_hi,   t0
 * add     B_hi, B_hi,   t1
 */
u8 mul_r64(u8 *buf, u8 rd, u8 rs)
{
	const u8 t0   = REG_LO(JIT_REG_TMP);
	const u8 t1   = REG_HI(JIT_REG_TMP);
	const u8 C_lo = REG_LO(rs);
	const u8 C_hi = REG_HI(rs);
	const u8 B_lo = REG_LO(rd);
	const u8 B_hi = REG_HI(rd);
	u8 len;

	len  = arc_mpy_r(buf, t0, B_hi, C_lo);
	len += arc_mpy_r(buf+len, t1, B_lo, C_hi);
	len += arc_mpydu_r(buf+len, B_lo, C_lo);
	len += arc_add_r(buf+len, B_hi, t0);
	len += arc_add_r(buf+len, B_hi, t1);

	return len;
}

/*
 * MUL B, imm
 * ----------
 *
 *  To get a 64-bit result from a signed 64x32 multiplication:
 *
 *         B_hi             B_lo   *
 *         sign             imm
 *  -----------------------------
 *  HI(B_lo*imm)     LO(B_lo*imm)  +
 *     B_hi*imm                    +
 *     B_lo*sign
 *  -----------------------------
 *        res_hi           res_lo
 *
 * mpy     t1, B_lo, sign(imm)
 * mpy     t0, B_hi, imm
 * mpydu B_lo, B_lo, imm
 * add   B_hi, B_hi,  t0
 * add   B_hi, B_hi,  t1
 *
 * Note: We can't use signed double multiplication, "mpyd", instead of an
 * unsigned verstion, "mpydu", and then get rid of the sign adjustments
 * calculated in "t1". The signed multiplication, "mpyd", will consider
 * both operands, "B_lo" and "imm", as signed inputs. However, for this
 * 64x32 multiplication, "B_lo" must be treated as an unsigned number.
 */
u8 mul_r64_i32(u8 *buf, u8 rd, s32 imm)
{
	const u8 t0   = REG_LO(JIT_REG_TMP);
	const u8 t1   = REG_HI(JIT_REG_TMP);
	const u8 B_lo = REG_LO(rd);
	const u8 B_hi = REG_HI(rd);
	u8 len = 0;

	if (imm == 1)
		return 0;

	/* Is the sign-extension of the immediate "-1"? */
	if (imm < 0)
		len += arc_neg_r(buf+len, t1, B_lo);

	len += arc_mpy_i(buf+len, t0, B_hi, imm);
	len += arc_mpydu_i(buf+len, B_lo, imm);
	len += arc_add_r(buf+len, B_hi, t0);

	/* Add the "sign*B_lo" part, if necessary. */
	if (imm < 0)
		len += arc_add_r(buf+len, B_hi, t1);

	return len;
}

u8 div_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_divu_r(buf, REG_LO(rd), REG_LO(rs));
}

u8 div_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	return arc_divu_i(buf, REG_LO(rd), imm);
}

u8 mod_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_remu_r(buf, REG_LO(rd), REG_LO(rs));
}

u8 mod_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	return arc_remu_i(buf, REG_LO(rd), imm);
}

u8 and_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_and_r(buf, REG_LO(rd), REG_LO(rs));
}

u8 and_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	return arc_and_i(buf, REG_LO(rd), imm);
}

u8 and_r64(u8 *buf, u8 rd, u8 rs)
{
	u8 len;
	len  = arc_and_r(buf    , REG_LO(rd), REG_LO(rs));
	len += arc_and_r(buf+len, REG_HI(rd), REG_HI(rs));
	return len;
}

u8 and_r64_i32(u8 *buf, u8 rd, s32 imm)
{
	u8 len;
	len  = mov_r64_i32(buf, JIT_REG_TMP, imm);
	len += and_r64(buf+len, rd, JIT_REG_TMP);
	return len;
}

static u8 tst_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_tst_r(buf, REG_LO(rd), REG_LO(rs));
}

static u8 tst_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	return arc_tst_i(buf, REG_LO(rd), imm);
}

u8 or_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_or_r(buf, REG_LO(rd), REG_LO(rd), REG_LO(rs));
}

u8 or_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	return arc_or_i(buf, REG_LO(rd), imm);
}

u8 or_r64(u8 *buf, u8 rd, u8 rs)
{
	u8 len;
	len  = arc_or_r(buf    , REG_LO(rd), REG_LO(rd), REG_LO(rs));
	len += arc_or_r(buf+len, REG_HI(rd), REG_HI(rd), REG_HI(rs));
	return len;
}

u8 or_r64_i32(u8 *buf, u8 rd, s32 imm)
{
	u8 len;
	len  = mov_r64_i32(buf, JIT_REG_TMP, imm);
	len += or_r64(buf+len, rd, JIT_REG_TMP);
	return len;
}

u8 xor_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_xor_r(buf, REG_LO(rd), REG_LO(rs));
}

u8 xor_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	return arc_xor_i(buf, REG_LO(rd), imm);
}

u8 xor_r64(u8 *buf, u8 rd, u8 rs)
{
	u8 len;
	len  = arc_xor_r(buf    , REG_LO(rd), REG_LO(rs));
	len += arc_xor_r(buf+len, REG_HI(rd), REG_HI(rs));
	return len;
}

u8 xor_r64_i32(u8 *buf, u8 rd, s32 imm)
{
	u8 len;
	len  = mov_r64_i32(buf, JIT_REG_TMP, imm);
	len += xor_r64(buf+len, rd, JIT_REG_TMP);
	return len;
}

/* "asl a,b,c" --> "a = (b << (c & 31))". */
u8 lsh_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_asl_r(buf, REG_LO(rd), REG_LO(rd), REG_LO(rs));
}

u8 lsh_r32_i32(u8 *buf, u8 rd, u8 imm)
{
	return arc_asli_r(buf, REG_LO(rd), REG_LO(rd), imm);
}

/*
 * algorithm
 * ---------
 * if (n <= 32)
 *   to_hi = lo >> (32-n)   # (32-n) is the negate of "n" in a 5-bit width.
 *   lo <<= n
 *   hi <<= n
 *   hi |= to_hi
 * else
 *   hi = lo << (n-32)
 *   lo = 0
 *
 * assembly translation for "LSH B, C"
 * (heavily influenced by ARC gcc)
 * -----------------------------------
 * not    t0, C_lo            # The first 3 lines are almost the same as:
 * lsr    t1, B_lo, 1         #   neg   t0, C_lo
 * lsr    t1, t1, t0          #   lsr   t1, B_lo, t0   --> t1 is "to_hi"
 * mov    t0, C_lo*           # with one important difference. In "neg"
 * asl    B_lo, B_lo, t0      # version, when C_lo=0, t1 becomes B_lo while
 * asl    B_hi, B_hi, t0      # it should be 0. The "not" approach instead,
 * or     B_hi, B_hi, t1      # "shift"s t1 once and 31 times, practically
 * btst   t0, 5               # setting it to 0 when C_lo=0.
 * mov.ne B_hi, B_lo**
 * mov.ne B_lo, 0
 *
 * *The "mov t0, C_lo" is necessary to cover the cases that C is the same
 * register as B.
 *
 * **ARC performs a shift in this manner: B <<= (C & 31)
 * For 32<=n<64, "n-32" and "n&31" are the same. Therefore, "B << n" and
 * "B << (n-32)" yield the same results. e.g. the results of "B << 35" and
 * "B << 3" are the same.
 *
 * The behaviour is undefined for n >= 64.
 */
u8 lsh_r64(u8 *buf, u8 rd, u8 rs)
{
	const u8 t0   = REG_LO(JIT_REG_TMP);
	const u8 t1   = REG_HI(JIT_REG_TMP);
	const u8 C_lo = REG_LO(rs);
	const u8 B_lo = REG_LO(rd);
	const u8 B_hi = REG_HI(rd);
	u8 len;

	len  = arc_not_r(buf, t0, C_lo);
	len += arc_lsri_r(buf+len, t1, B_lo, 1);
	len += arc_lsr_r(buf+len, t1, t1, t0);
	len += arc_mov_r(buf+len, t0, C_lo);
	len += arc_asl_r(buf+len, B_lo, B_lo, t0);
	len += arc_asl_r(buf+len, B_hi, B_hi, t0);
	len += arc_or_r(buf+len, B_hi, B_hi, t1);
	len += arc_btst_i(buf+len, t0, 5);
	len += arc_mov_cc_r(buf+len, CC_unequal, B_hi, B_lo);
	len += arc_movu_cc_r(buf+len, CC_unequal, B_lo, 0);

	return len;
}

/*
 * if (n < 32)
 *   to_hi = B_lo >> 32-n          # extract upper n bits
 *   lo <<= n
 *   hi <<=n
 *   hi |= to_hi
 * else if (n < 64)
 *   hi = lo << n-32
 *   lo = 0
 */
u8 lsh_r64_i32(u8 *buf, u8 rd, s32 imm)
{
	const u8 t0   = REG_LO(JIT_REG_TMP);
	const u8 B_lo = REG_LO(rd);
	const u8 B_hi = REG_HI(rd);
	const u8 n    = (u8) imm;
	u8 len = 0;

	if (n == 0) {
		return 0;
	} else if (n <= 31) {
		len  = arc_lsri_r(buf, t0, B_lo, 32 - n);
		len += arc_asli_r(buf+len, B_lo, B_lo, n);
		len += arc_asli_r(buf+len, B_hi, B_hi, n);
		len += arc_or_r(buf+len, B_hi, B_hi, t0);
	} else if (n <= 63) {
		len  = arc_asli_r(buf, B_hi, B_lo, n - 32);
		len += arc_movi_r(buf+len, B_lo, 0);
	}
	/* n >= 64 is undefined behaviour. */

	return len;
}

/* "lsr a,b,c" --> "a = (b >> (c & 31))". */
u8 rsh_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_lsr_r(buf, REG_LO(rd), REG_LO(rd), REG_LO(rs));
}

u8 rsh_r32_i32(u8 *buf, u8 rd, u8 imm)
{
	return arc_lsri_r(buf, REG_LO(rd), REG_LO(rd), imm);
}

/*
 * For better commentary, see lsh_r64().
 *
 * algorithm
 * ---------
 * if (n <= 32)
 *   to_lo = hi << (32-n)
 *   hi >>= n
 *   lo >>= n
 *   lo |= to_lo
 * else
 *   lo = hi >> (n-32)
 *   hi = 0
 *
 * RSH    B,C
 * ----------
 * not    t0, C_lo
 * asl    t1, B_hi, 1
 * asl    t1, t1, t0
 * mov    t0, C_lo
 * lsr    B_hi, B_hi, t0
 * lsr    B_lo, B_lo, t0
 * or     B_lo, B_lo, t1
 * btst   t0, 5
 * mov.ne B_lo, B_hi
 * mov.ne B_hi, 0
 */
u8 rsh_r64(u8 *buf, u8 rd, u8 rs)
{
	const u8 t0   = REG_LO(JIT_REG_TMP);
	const u8 t1   = REG_HI(JIT_REG_TMP);
	const u8 C_lo = REG_LO(rs);
	const u8 B_lo = REG_LO(rd);
	const u8 B_hi = REG_HI(rd);
	u8 len;

	len  = arc_not_r(buf, t0, C_lo);
	len += arc_asli_r(buf+len, t1, B_hi, 1);
	len += arc_asl_r(buf+len, t1, t1, t0);
	len += arc_mov_r(buf+len, t0, C_lo);
	len += arc_lsr_r(buf+len, B_hi, B_hi, t0);
	len += arc_lsr_r(buf+len, B_lo, B_lo, t0);
	len += arc_or_r(buf+len, B_lo, B_lo, t1);
	len += arc_btst_i(buf+len, t0, 5);
	len += arc_mov_cc_r(buf+len, CC_unequal, B_lo, B_hi);
	len += arc_movu_cc_r(buf+len, CC_unequal, B_hi, 0);

	return len;
}

/*
 * if (n < 32)
 *   to_lo = B_lo << 32-n     # extract lower n bits, right-padded with 32-n 0s
 *   lo >>=n
 *   hi >>=n
 *   hi |= to_lo
 * else if (n < 64)
 *   lo = hi >> n-32
 *   hi = 0
 */
u8 rsh_r64_i32(u8 *buf, u8 rd, s32 imm)
{
	const u8 t0   = REG_LO(JIT_REG_TMP);
	const u8 B_lo = REG_LO(rd);
	const u8 B_hi = REG_HI(rd);
	const u8 n    = (u8) imm;
	u8 len = 0;

	if (n == 0) {
		return 0;
	} else if (n <= 31) {
		len  = arc_asli_r(buf, t0, B_hi, 32 - n);
		len += arc_lsri_r(buf+len, B_lo, B_lo, n);
		len += arc_lsri_r(buf+len, B_hi, B_hi, n);
		len += arc_or_r(buf+len, B_lo, B_lo, t0);
	} else if (n <= 63) {
		len  = arc_lsri_r(buf, B_lo, B_hi, n - 32);
		len += arc_movi_r(buf+len, B_hi, 0);
	}
	/* n >= 64 is undefined behaviour. */

	return len;
}

/* "asr a,b,c" --> "a = (b s>> (c & 31))". */
u8 arsh_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_asr_r(buf, REG_LO(rd), REG_LO(rd), REG_LO(rs));
}

u8 arsh_r32_i32(u8 *buf, u8 rd, u8 imm)
{
	return arc_asri_r(buf, REG_LO(rd), REG_LO(rd), imm);
}

/*
 * For comparison, see rsh_r64().
 *
 * algorithm
 * ---------
 * if (n <= 32)
 *   to_lo = hi << (32-n)
 *   hi s>>= n
 *   lo  >>= n
 *   lo |= to_lo
 * else
 *   hi_sign = hi s>>31
 *   lo = hi s>> (n-32)
 *   hi = hi_sign
 *
 * ARSH   B,C
 * ----------
 * not    t0, C_lo
 * asl    t1, B_hi, 1
 * asl    t1, t1, t0
 * mov    t0, C_lo
 * asr    B_hi, B_hi, t0
 * lsr    B_lo, B_lo, t0
 * or     B_lo, B_lo, t1
 * btst   t0, 5
 * asr    t0, B_hi, 31        # now, t0 = 0 or -1 based on B_hi's sign
 * mov.ne B_lo, B_hi
 * mov.ne B_hi, t0
 */
u8 arsh_r64(u8 *buf, u8 rd, u8 rs)
{
	const u8 t0   = REG_LO(JIT_REG_TMP);
	const u8 t1   = REG_HI(JIT_REG_TMP);
	const u8 C_lo = REG_LO(rs);
	const u8 B_lo = REG_LO(rd);
	const u8 B_hi = REG_HI(rd);
	u8 len;

	len  = arc_not_r(buf, t0, C_lo);
	len += arc_asli_r(buf+len, t1, B_hi, 1);
	len += arc_asl_r(buf+len, t1, t1, t0);
	len += arc_mov_r(buf+len, t0, C_lo);
	len += arc_asr_r(buf+len, B_hi, B_hi, t0);
	len += arc_lsr_r(buf+len, B_lo, B_lo, t0);
	len += arc_or_r(buf+len, B_lo, B_lo, t1);
	len += arc_btst_i(buf+len, t0, 5);
	len += arc_asri_r(buf+len, t0, B_hi, 31);
	len += arc_mov_cc_r(buf+len, CC_unequal, B_lo, B_hi);
	len += arc_mov_cc_r(buf+len, CC_unequal, B_hi, t0);

	return len;
}

/*
 * if (n < 32)
 *   to_lo = lo << 32-n     # extract lower n bits, right-padded with 32-n 0s
 *   lo >>=n
 *   hi s>>=n
 *   hi |= to_lo
 * else if (n < 64)
 *   lo = hi s>> n-32
 *   hi = (lo[msb] ? -1 : 0)
 */
u8 arsh_r64_i32(u8 *buf, u8 rd, s32 imm)
{
	const u8 t0   = REG_LO(JIT_REG_TMP);
	const u8 B_lo = REG_LO(rd);
	const u8 B_hi = REG_HI(rd);
	const u8 n    = (u8) imm;
	u8 len = 0;

	if (n == 0) {
		return 0;
	} else if (n <= 31) {
		len  = arc_asli_r(buf, t0, B_hi, 32 - n);
		len += arc_lsri_r(buf+len, B_lo, B_lo, n);
		len += arc_asri_r(buf+len, B_hi, B_hi, n);
		len += arc_or_r(buf+len, B_lo, B_lo, t0);
	} else if (n <= 63) {
		len  = arc_asri_r(buf, B_lo, B_hi, n - 32);
		len += arc_movi_r(buf+len, B_hi, -1);
		len += arc_btst_i(buf+len, B_lo, 31);
		len += arc_movu_cc_r(buf+len, CC_equal, B_hi, 0);
	}
	/* n >= 64 is undefined behaviour. */

	return len;
}

u8 gen_swap(u8 *buf, u8 rd, u8 size, u8 endian)
{
	u8 len = 0;
#ifdef __BIG_ENDIAN
	const u8 host_endian = BPF_FROM_BE;
#else
	const u8 host_endian = BPF_FROM_LE;
#endif
	/*
	 * If the same endianness, there's not much to do other
	 * than zeroing out the upper bytes based on the "size".
	 */
	if (host_endian == endian) {
		switch (size) {
		case 16:
			len += arc_and_i(buf+len, REG_LO(rd), 0xffff);
			fallthrough;
		case 32:
			len += zext(buf+len, rd);
			fallthrough;
		case 64:
			break;
		default:
			/* The caller must have handled this. */
		}
	} else {
		switch (size) {
		case 16:
			/*
			 * r = B4B3_B2B1 << 16 --> r = B2B1_0000
			 * swape(r) is 0000_B1B2
			 */
			len += arc_asli_r(buf+len, REG_LO(rd), REG_LO(rd), 16);
			fallthrough;
		case 32:
			len += arc_swape_r(buf+len, REG_LO(rd));
			len += zext(buf+len, rd);
			break;
		case 64:
			/*
			 * swap "hi" and "lo":
			 *   hi ^= lo;
			 *   lo ^= hi;
			 *   hi ^= lo;
			 * and then swap the bytes in "hi" and "lo".
			 */
			len += arc_xor_r(buf+len, REG_HI(rd), REG_LO(rd));
			len += arc_xor_r(buf+len, REG_LO(rd), REG_HI(rd));
			len += arc_xor_r(buf+len, REG_HI(rd), REG_LO(rd));
			len += arc_swape_r(buf+len, REG_LO(rd));
			len += arc_swape_r(buf+len, REG_HI(rd));
			break;
		default:
			/* The caller must have handled this. */
		}
	}

	return len;
}

u8 mov_r32(u8 *buf, u8 rd, u8 rs)
{
	if (rd == rs)
		return 0;
	return arc_mov_r(buf, REG_LO(rd), REG_LO(rs));
}

u8 mov_r32_i32(u8 *buf, u8 reg, s32 imm)
{
	return arc_mov_i(buf, REG_LO(reg), imm);
}

u8 mov_r64(u8 *buf, u8 rd, u8 rs)
{
	u8 len;

	if (rd == rs)
		return 0;

	len = arc_mov_r(buf, REG_LO(rd), REG_LO(rs));

	if (rs != BPF_REG_FP)
		len += arc_mov_r(buf+len, REG_HI(rd), REG_HI(rs));
	/* BPF_REG_FP is mapped to 32-bit "fp" register. */
	else
		len += arc_movi_r(buf+len, REG_HI(rd), 0);

	return len;
}

/* Sign extend the 32-bit immediate into 64-bit register pair. */
u8 mov_r64_i32(u8 *buf, u8 reg, s32 imm)
{
	u8 len = 0;

	len = arc_mov_i(buf, REG_LO(reg), imm);

	/* BPF_REG_FP is mapped to 32-bit "fp" register. */
	if (reg != BPF_REG_FP) {
		if (imm >= 0)
			len += arc_movi_r(buf+len, REG_HI(reg), 0);
		else
			len += arc_movi_r(buf+len, REG_HI(reg), -1);
	}

	return len;
}

/*
 * This is merely used for translation of "LD R, IMM64" instructions
 * of the BPF. These sort of instructions are sometimes used for
 * relocations. If during the normal pass, the relocation value is
 * not known, the BPF instruction may look something like:
 *
 * LD R <- 0x0000_0001_0000_0001
 *
 * Which will nicely translate to two 4-byte ARC instructions:
 *
 * mov R_lo, 1               # imm is small enough to be s12
 * mov R_hi, 1               # ditto
 *
 * However, during the extra pass, the IMM64 will have changed
 * to the resolved address and looks something like:
 *
 * LD R <- 0x0000_0000_1234_5678
 *
 * Now, the translated code will require 12 bytes:
 *
 * mov R_lo, 0x12345678      # this is an 8-byte instruction
 * mov R_hi, 0               # still 4 bytes
 *
 * Which in practice will result in overwriting the following
 * instruction. To avoid such cases, we restrict ourselves to
 * these sort of size optimizations and will always emit codes
 * with fixed sizes.
 */
u8 mov_r64_i64(u8 *buf, u8 reg, u32 lo, u32 hi)
{
	u8 len;

	len  = arc_mov_i_fixed(buf, REG_LO(reg), lo);
	len += arc_mov_i_fixed(buf+len, REG_HI(reg), hi);

	return len;
}

/*
 * If the offset is too big to fit in s9, emit:
 *   add r20, REG_LO(rm), off
 * and make sure that r20 will be the effective address for store:
 *   st  r, [r20, 0]
 */
static u8 adjust_mem_access(u8 *buf, s16 *off, u8 size, u8 rm, u8 *arc_reg_mem)
{
	u8 len = 0;
	*arc_reg_mem = REG_LO(rm);

	if (!IN_S9_RANGE(*off) ||
	    (size == BPF_DW && !IN_S9_RANGE(*off + 4))) {
		len += arc_add_i(buf+len,
				 REG_LO(JIT_REG_TMP), REG_LO(rm), (u32) (*off));
		*arc_reg_mem = REG_LO(JIT_REG_TMP);
		*off = 0;
	}

	return len;
}

/* store rs, [rd, off] */
u8 store_r(u8 *buf, u8 rs, u8 rd, s16 off, u8 size)
{
	u8 len, arc_reg_mem;

	len = adjust_mem_access(buf, &off, size, rd, &arc_reg_mem);

	if (size == BPF_DW) {
		len += arc_st_r(buf+len, REG_LO(rs), arc_reg_mem, off,
				ZZ_4_byte);
		len += arc_st_r(buf+len, REG_HI(rs), arc_reg_mem, off+4,
				ZZ_4_byte);
	} else {
		u8 zz = bpf_to_arc_size(size);
		len += arc_st_r(buf+len, REG_LO(rs), arc_reg_mem, off, zz);
	}

	return len;
}

/*
 * For {8,16,32}-bit stores:
 *   mov r21, imm
 *   st  r21, [...]
 * For 64-bit stores:
 *   mov r21, imm
 *   st  r21, [...]
 *   mov r21, {0,-1}
 *   st  r21, [...+4]
 */
u8 store_i(u8 *buf, s32 imm, u8 rd, s16 off, u8 size)
{
	u8 len, arc_reg_mem;
	/* REG_LO(JIT_REG_TMP) might be used by "adjust_mem_access()". */
	const u8 arc_rs = REG_HI(JIT_REG_TMP);

	len = adjust_mem_access(buf, &off, size, rd, &arc_reg_mem);

	if (size == BPF_DW) {
		len += arc_mov_i(buf+len, arc_rs, imm);
		len += arc_st_r(buf+len, arc_rs, arc_reg_mem, off,
				ZZ_4_byte);
		imm = (imm >= 0 ? 0 : -1);
		len += arc_mov_i(buf+len, arc_rs, imm);
		len += arc_st_r(buf+len, arc_rs, arc_reg_mem, off+4,
				ZZ_4_byte);
	} else {
		u8 zz = bpf_to_arc_size(size);
		len += arc_mov_i(buf+len, arc_rs, imm);
		len += arc_st_r(buf+len, arc_rs, arc_reg_mem, off, zz);
	}

	return len;
}

/*
 * For the calling convention of a little endian machine, the LO part
 * must be on top of the stack.
 */
static u8 push_r64(u8 *buf, u8 reg)
{
	u8 len = 0;

#ifdef __LITTLE_ENDIAN
	/* BPF_REG_FP is mapped to 32-bit "fp" register. */
	if (reg != BPF_REG_FP)
		len += arc_push_r(buf+len, REG_HI(reg));
	len += arc_push_r(buf+len, REG_LO(reg));
#else
	len += arc_push_r(buf+len, REG_LO(reg));
	if (reg != BPF_REG_FP)
		len += arc_push_r(buf+len, REG_HI(reg));
#endif

	return len;
}

/* load rd, [rs, off] */
u8 load_r(u8 *buf, u8 rd, u8 rs, s16 off, u8 size)
{
	u8 len, arc_reg_mem;

	len = adjust_mem_access(buf, &off, size, rd, &arc_reg_mem);

	if (size == BPF_B || size == BPF_H || size == BPF_W) {
		u8 zz = bpf_to_arc_size(size);
		len += arc_ld_r(buf+len, REG_LO(rd), arc_reg_mem, off, zz);
		len += arc_movi_r(buf+len, REG_HI(rd), 0);
	} else if (size == BPF_DW) {
		/*
		 * We are about to issue 2 consecutive loads:
		 *
		 *   ld rx, [rb, off+0]
		 *   ld ry, [rb, off+4]
		 *
		 * If "rx" and "rb" are the same registers, then the order
		 * should change to guarantee that "rb" remains intact
		 * during these 2 operations:
		 *
		 *   ld ry, [rb, off+4]
		 *   ld rx, [rb, off+0]
		 */
		if (REG_LO(rd) != arc_reg_mem) {
			len += arc_ld_r(buf+len, REG_LO(rd), arc_reg_mem,
					off+0, ZZ_4_byte);
			len += arc_ld_r(buf+len, REG_HI(rd), arc_reg_mem,
					off+4, ZZ_4_byte);
		} else {
			len += arc_ld_r(buf+len, REG_HI(rd), arc_reg_mem,
					off+4, ZZ_4_byte);
			len += arc_ld_r(buf+len, REG_LO(rd), arc_reg_mem,
					off+0, ZZ_4_byte);
		}
	}

	return len;
}

/* A mere wrapper, so the core doesn't call an arc_*_() function directly. */
u8 push_r(u8 *buf, u8 reg)
{
	return arc_push_r(buf, reg);
}

/* A mere wrapper, so the core doesn't call an arc_*_() function directly. */
u8 pop_r(u8 *buf, u8 reg)
{
	return arc_pop_r(buf, reg);
}

/*
 * To create a frame, all that is needed is:
 *
 *  push fp
 *  mov  fp, sp
 *  sub  sp, <frame_size>
 *
 * "push fp" is taken care of separately while saving the clobbered registers.
 * All that remains is copying SP value to FP and shrinking SP's address space
 * for any possible function call to come.
 */
u8 frame_enter(u8 *buf, u16 size)
{
	u8 len;
	len = arc_mov_r(buf, ARC_R_FP, ARC_R_SP);
	if (IN_U6_RANGE(size))
		len += arc_subi_r(buf+len, ARC_R_SP, size);
	else
		len += arc_sub_i(buf+len, ARC_R_SP, size);
	return len;
}

/* The value of SP upon entering was copied to FP. */
u8 frame_exit(u8 *buf)
{
	return arc_mov_r(buf, ARC_R_SP, ARC_R_FP);
}

/*
 * Move the return value in BPF register "rs", into ARCv2 ABI
 * return register "r1r0".
 */
u8 frame_assign_return(u8 *buf, u8 rs)
{
	u8 len = 0;

	len += arc_mov_r(buf+len, ARC_R_0, REG_LO(rs));
	len += arc_mov_r(buf+len, ARC_R_1, REG_HI(rs));

	return len;
}

u8 frame_return(u8 *buf)
{
	return arc_jmp_return(buf);
}

u8 jmp_relative(u8 *buf, int displacement)
{
	return arc_b(buf, displacement);
}

/*
 * This translation leads to:
 *
 *   mov r20, addr
 *   jl  r20
 *
 * Here "addr" is u32, but for arc_mov_i(), it is s32.
 * The lack of an explicit conversion is OK.
 */
static u8 jump_and_link(u8 *buf, u32 addr)
{
	u8 len;
	len  = arc_mov_i(buf, REG_LO(JIT_REG_TMP), addr);
	len += arc_jl(buf+len, REG_LO(JIT_REG_TMP));
	return len;
}

/*
 * The "offset" is interpreted as the "number" of BPF instructions
 * from the _next_ BPF instruction. e.g.:
 *
 *  4 means 4 instructions after  the next insn
 *  0 means 0 instructions after  the next insn -> fall through.
 * -1 means 1 instruction  before the next insn -> jmp to current insn.
 *
 *  Another way to look at this, "offset" is the number of instructions
 *  that exist between the current instruction and the target instruction.
 *
 *  It is worth noting that a "mov r,i64", which is 16-byte long, is
 *  treated as two instructions long, therefore "offset" needn't be
 *  treated specially for those. Everything is uniform.
 *
 *  Knowing the current BPF instruction and the target BPF instruction,
 *  we can obtain their JITed memory addresses, namely "jit_curr_addr"
 *  and "jit_targ_addr". The offset, a.k.a. displacement, for ARC's
 *  "b" (branch) instruction is the distance from the _current_ instruction
 *  (PC) to the target instruction. To be precise, it is the distance from
 *  PCL (PC aLigned) to the target address. PCL is the word-aligned
 *  copy of PC.
 */
static int bpf_offset_to_jit(const struct jit_context *ctx,
			     const struct bpf_insn *insn,
			     u8 advance,
			     s32 *jit_offset,
			     bool use_far)
{
	u32 jit_curr_addr, jit_targ_addr, pcl;
	const s32 idx = get_index_for_insn(ctx, insn);
	const s16 bpf_offset = insn->off;
	const s32 bpf_targ_idx = (idx+1) + bpf_offset;

	/*
	 * "len" reflects the number of bytes for possible "check" instructions
	 * that are emitted. In that case, ARC's "b(ranch)" instruction is not
	 * emitted at the begenning of "jit.buf + bpf2ins[idx]", but "advance"
	 * bytes after that.
	 */
	jit_curr_addr = (u32) (ctx->jit.buf + ctx->bpf2insn[idx] + advance);
	jit_targ_addr = (u32) (ctx->jit.buf + ctx->bpf2insn[bpf_targ_idx]);
	pcl           = jit_curr_addr & ~3;
	*jit_offset   = jit_targ_addr - pcl;

	/* The S21 in "b" (branch) encoding must be 16-bit aligned. */
	if (*jit_offset & 1) {
		pr_err("bpf-jit: jit address is not 16-bit aligned.\n");
		return -EFAULT;
	}

	if (( use_far && !IN_S25_RANGE(*jit_offset)) ||
	    (!use_far && !IN_S21_RANGE(*jit_offset))) {
		pr_err("bpf-jit: jit address is too far to jump to.\n");
		return -EFAULT;
	}

	return 0;
}

/*
 * A branch to the instruction that is "insn->off" away.
 *
 * - "cond" must be in ARC format (CC_*). If it happens to be "CC_always",
 *   then encoding of the condition code can be skipped and a far branch
 *   can be used. A far branch supports S25 offset while the conditioned
 *   version supports S21 range.
 *
 * - "len" holds the growing length of JIT buffer that is not yet committed
 *   back to "ctx->jit" buffer. It is necessary for calculating the exact
 *   offset of a "b"ranch instruction. See "bpf_offset_to_jit()" comments
 *   for more datils.
 */
static int gen_branch(struct jit_context *ctx,
		      const struct bpf_insn *insn,
		      u8 cond,
		      u8 *len)
{
	s32 disp = 0;
	u8 *buf = effective_jit_buf(&ctx->jit);

	/* After that ctx->bpf2insn[] is initialised, offsets can be deduced. */
	if (ctx->bpf2insn_valid) {
		int ret = bpf_offset_to_jit(ctx, insn, *len, &disp,
					    cond == CC_always);
		if (ret < 0)
			return ret;
	}

	if (cond == CC_always)
		*len += arc_b(buf+*len, disp);
	else
		*len += arc_bcc(buf+*len, cond, disp);
	return 0;
}

/*
 * A wrapper around "gen_branch()", so "handle_insn()" doesn't need to know
 * about back-end internal (CC_always), while handling "BPF_JA".
 */
static int gen_ja(struct jit_context *ctx,
		  const struct bpf_insn *insn,
		  u8 *len)
{
	return gen_branch(ctx, insn, CC_always, len);
}

/* Convert BPF conditions to ARC's, for 32-bit versions. */
static inline int bpf_cond_to_arc(const u8 op)
{
	switch (op) {
	case BPF_JA:	return CC_always;
	case BPF_JEQ:	return CC_equal;
	case BPF_JGT:	return CC_great_u;
	case BPF_JGE:	return CC_great_eq_u;
	case BPF_JSET:	return CC_unequal;
	case BPF_JNE:	return CC_unequal;
	case BPF_JSGT:	return CC_great_s;
	case BPF_JSGE:	return CC_great_eq_s;
	case BPF_JLT:	return CC_less_u;
	case BPF_JLE:	return CC_less_eq_u;
	case BPF_JSLT:	return CC_less_s;
	case BPF_JSLE:	return CC_less_eq_s;
	default:
	}
	pr_err("bpf-jit: can't hanlde condition 0x%02X\n", op);
	return -EINVAL;
}

/*
 * For jset:
 * tst   r, [r,i]      # test reg vs. another reg or imm
 * bne   @target
 *
 * For others:
 * cmp   r, [r,i]      # compare regr vs. another reg or imm
 * b<cc> @target       # "cc" is deduced from the BPF condition
 */
static int gen_jcc_32(struct jit_context *ctx,
		      const struct bpf_insn *insn,
		      u8 *len)
{
	u8 *buf = effective_jit_buf(&ctx->jit);
	s8 cond;
	const u8 rd = insn->dst_reg;
	const u8 rs = insn->src_reg;
	*len = 0;

	if ((cond = bpf_cond_to_arc(BPF_OP(insn->code))) < 0)
		return cond;

	/* Either issue "tst" or "cmp" before the conditional jump. */
	switch (BPF_OP(insn->code))
	{
	case BPF_JSET:
		if (has_imm(insn))
			*len = tst_r32_i32(buf+*len, rd, insn->imm);
		else
			*len = tst_r32(buf+*len, rd, rs);
		break;
	case BPF_JEQ:
	case BPF_JNE:
	case BPF_JGT:
	case BPF_JGE:
	case BPF_JLT:
	case BPF_JLE:
	case BPF_JSGT:
	case BPF_JSGE:
	case BPF_JSLT:
	case BPF_JSLE:
		if (has_imm(insn))
			*len = cmp_r32_i32(buf+*len, rd, insn->imm);
		else
			*len = cmp_r32(buf+*len, rd, rs);
		break;
	default:
		pr_err("bpf-jit: can't handle 32-bit condition.\n");
		return -EINVAL;
	}

	return gen_branch(ctx, insn, cond, len);
}

/*
 * cmp        rd_hi, rs_hi
 * cmp.z      rd_lo, rs_lo
 * b{eq,ne}   @target
 *   |  |
 *   |  `-->  "eq" param is true  (JEQ)
 *   `----->  "eq" param is false (JNE)
 */
static int gen_j_eq_64(u8 *buf, u8 rd, u8 rs, bool eq, u32 targ_addr)
{
	u8 len = 0;

	len += arc_cmp_r(buf+len, REG_HI(rd), REG_HI(rs));
	len += arc_cmpz_r(buf+len, REG_LO(rd), REG_LO(rs));
	disp = get_displacement(buf+len, targ_addr);
	len += arc_bcc(buf+len, eq ? CC_equal : CC_unequal, disp);

	return len;
}

/*
 * tst   rd_hi, rs_hi
 * tst.z rd_lo, rs_lo
 * bne   @target
 */
static u8 gen_jset_64(u8 *buf, u8 rd, u8 rs, u32 targ_addr)
{
	u8 len = 0;
	s32 disp;

	len += arc_tst_r(buf+len, REG_HI(rd), REG_HI(rs));
	len += arc_tstz_r(buf+len, REG_LO(rd), REG_LO(rs));
	disp = get_displacement(buf+len, targ_addr);
	len += arc_bcc(buf+len, CC_unequal, disp);

	return len;
}

/*vvvvvv REVAMP JUMPS vvvvvv*/
/*
 * For details on the algorithm, see the comments of "gen_jcc_64()".
 *
 * This data structure is holding information for jump translations.
 *
 * jit_off: How many bytes into the current JIT address, "b"ranch insn. occurs
 * cond: The condition that the ARC branch instruction must use
 *
 * e.g.:
 *
 * BPF_JGE  R1, R0, @target
 * ------------------------
 *            |
 *            v
 * 0x1000: cmp  r3, r1     # 0x1000 is the JIT address for "BPF_JGE ..." insn
 * 0x1004: bhs  @target    # branch higher or same
 * 0x1008: ...
 *
 * The jit_off(set) of the "bhs" is 4 bytes.
 * The cond(ition) for the "bhs" is "CC_great_equal_u".
 *
 * The jit_off(set) is necessary for calculating the exact displacement
 * to the "target" address:
 *
 * jit_address + jit_off(set) - @target
 * 0x1000      + 4            - @target
 */
#define NR_OF_JMPS_IN_JCC64 3
/* TODO: Shahab, maybe the "c2" can go away if the 2nd "cmp" becomes "cmp.z". */
const struct = {
	/*
	 * "jit_off" is common between all "jmp[]" and is coupled with
	 * "cond" of each "jmp[]" instance. e.g.:
	 *
	 * arcv2_64b_jumps.jit_off[1]
	 * arcv2_64b_jumps.jmp[ARC_CC_UGT].cond[1]
	 *
	 * Are indicating that the second jump in JITed code of "UGT"
	 * is at offset "jit_off[1]" while its condition is "cond[1]".
	 */
	u8 jit_off[NR_OF_JMPS_IN_JCC64];

	struct {
		u8 cond[NR_OF_JMPS_IN_JCC64];
	} jmp[ARC_CC_SLE+1];
} arcv2_64b_jccs = {
	.jit_off = {
		INSN_len_normal*1,
		INSN_len_normal*2,
		INSN_len_normal*4
	},
	/*
	 *   cmp  rd_hi, rs_hi
	 *   bhi  @target         # 1: u>
	 *   blo  @end            # 2: u<
	 *   cmp  rd_lo, rs_lo
	 *   bhi  @target         # 3: u>
	 * end:
	 */
	.jmp[ARC_CC_UGT] = {
		.cond = {CC_great_u, CC_less_u, CC_great_u}
	},
	/*
	 *   cmp  rd_hi, rs_hi
	 *   bhi  @target         # 1: u>
	 *   blo  @end            # 2: u<
	 *   cmp  rd_lo, rs_lo
	 *   bhs  @target         # 3: u>=
	 * end:
	 */
	.jmp[ARC_CC_UGE] = {
		.cond = {CC_great_u, CC_less_u, CC_great_eq_u}
	},
	/*
	 *   cmp  rd_hi, rs_hi
	 *   blo  @target         # 1: u<
	 *   bhi  @end            # 2: u>
	 *   cmp  rd_lo, rs_lo
	 *   blo  @target         # 3: u<
	 * end:
	 */
	.jmp[ARC_CC_ULT] = {
		.cond = {CC_less_u, CC_great_u, CC_less_u}
	},
	/*
	 *   cmp  rd_hi, rs_hi
	 *   blo  @target         # 1: u<
	 *   bhi  @end            # 2: u>
	 *   cmp  rd_lo, rs_lo
	 *   bls  @target         # 3: u<=
	 * end:
	 */
	.jmp[ARC_CC_ULE] = {
		.cond = {CC_less_u, CC_great_u, CC_less_eq_u}
	},
	/*
	 *   cmp  rd_hi, rs_hi
	 *   bgt  @target         # 1: s>
	 *   blt  @end            # 2: s<
	 *   cmp  rd_lo, rs_lo
	 *   bhi  @target         # 3: u>
	 * end:
	 */
	.jmp[ARC_CC_SGT] = {
		.cond = {CC_great_s, CC_less_s, CC_great_u}
	},
	/*
	 *   cmp  rd_hi, rs_hi
	 *   bgt  @target         # 1: s>
	 *   blt  @end            # 2: s<
	 *   cmp  rd_lo, rs_lo
	 *   bhs  @target         # 3: u>=
	 * end:
	 */
	.jmp[ARC_CC_SGE] = {
		.cond = {CC_great_s, CC_less_s, CC_great_eq_u}
	},
	/*
	 *   cmp  rd_hi, rs_hi
	 *   blt  @target         # 1: s<
	 *   bgt  @end            # 2: s>
	 *   cmp  rd_lo, rs_lo
	 *   blo  @target         # 3: u<
	 * end:
	 */
	.jmp[ARC_CC_SLT] = {
		.cond = {CC_less_s, CC_great_s, CC_less_u}
	},
	/*
	 *   cmp  rd_hi, rs_hi
	 *   blt  @target         # 1: s<
	 *   bgt  @end            # 2: s>
	 *   cmp  rd_lo, rs_lo
	 *   bls  @target         # 3: u<=
	 * end:
	 */
	.jmp[ARC_CC_SLE] = {
		.cond = {CC_less_s, CC_great_s, CC_less_eq_u}
	}
};

/*
 * Check couple of things:
 *
 * 1. The displacement is 16-bit aligned.
 * 2. The range is valid based on the jump (cond. vs uncond.).
 */
bool is_displacement_valid(s32 disp, u8 cond)
{
	/* If no conditional code has to be encoded, we can jump furhter. */
	const bool use_far = (cond == CC_always);

	if (disp & 1)
		return false;

	if (( use_far && !IN_S25_RANGE(disp)) ||
	    (!use_far && !IN_S21_RANGE(disp)))
		return false;

	return true;
}

/*
 * The displacement (offset) for ARC's "b"ranch instruction is the distance
 * from the aligned version of _current_ instruction (PCL) to the target
 * instruction:
 *
 * DISP = TARGET - PCL          # PCL is the word aligned PC
 */
static inline s32 get_displacement(u32 curr_addr, u32 targ_addr)
{
	return (s32) targ_addr - ((s32) (curr_addr & ~3L);
}


/*
 * The template for the 64-bit jumps with the following BPF conditions
 *
 * u< u<= u> u>= s< s<= s> s>=
 *
 * Looks like below:
 *
 *   cmp   rd_hi, rs_hi
 *   b<c1> @target
 *   b<c2> @end
 *   cmp   rd_lo, rs_lo   # if execution reaches here, r{d,s}_hi are equal
 *   b<c3> @target
 * end:
 *
 * "c1" is the condition that JIT is handling minus the equality part.
 * For instance if we have to translate an "unsigned greater or equal",
 * then "c1" will be "unsigned greater". We won't know about equality
 * until all 64-bits of data (higeher and lower registers) are processed.
 *
 * "c2" is the counter logic of "c1". For instance, if "c1" is originated
 * from "s>", then "c2" would be "s<". Notice that equality doesn't play
 * a role here either because the lower 32 bits are not processed yet.
 *
 * "c3" is the unsigned version of "c1", no matter if the BPF condition
 * was signed or unsigned. An unsigned version is necessary, because the
 * MSB of the lower 32 bits does not reflect a sign in the whole 64-bit
 * scheme. Otherwise, 64-bit comparisons like
 * (0x0000_0000,0x8000_0000) s>= (0x0000_0000,0x0000_0000)
 * would yield an incorrect result. Finally, if there is an equality
 * check in the BPF condition, it will be reflected in "c3".
 *
 * You can find all the instances of this template where the
 * "arcv2_64b_jccs" is getting initialised.
 */
static u8 gen_jcc_64(u8 *buf, u8 rd, u8 rs, u8 cond, u32 target)
{
	s32 disp;
	u32 end;
	const u8 *cond = arcv2_64b_jccs.jmp[cond].cond;
	u8 len = 0;

	/* cmp rd_hi, rs_hi */
	len += arc_cmp_r(buf, REG_HI(rd), REG_HI(rs));

	/* b<c1> @target */
	disp = get_displacement(buf+len, target);
	len += arc_bcc(buf+len, cond[0], disp);

	/* b<c2> @end */
	end = buf + len + (3 * INSN_len_normal);
	disp = get_displacement(buf+len, end);
	len += arc_bcc(buf+len, cond[1], disp);

	/* cmp rd_lo, rs_lo */
	arc_cmp_r(buf+len, REG_LO(rd), REG_LO(rs));

	/* b<c3> @target */
	disp = get_displacement(buf+len, target);
	len += arc_bcc(buf+len, cond[2], disp);

	return len;
}

/*
 * This function only applies the necessary logic to make the proper
 * translations. All the sanity checks must have already been done
 * by calling the check_jmp_64().
 */
u8 gen_jmp_64(u8 *buf, u8 rd, u8 rs, u8 cond, u32 target)
{
	u8 len = 0;
	bool eq = false;

	switch (cond) {
	case ARC_CC_AL:
		len = arc_b(buf, disp, get_displacement(buf, target));
		break;
	case ARC_CC_UGT:
	case ARC_CC_UGE:
	case ARC_CC_ULT:
	case ARC_CC_ULE:
	case ARC_CC_SGT:
	case ARC_CC_SGE:
	case ARC_CC_SLT:
	case ARC_CC_SLE:
		len = gen_jcc_64(buf, rd, rs, cond, target);
		break;
	case ARC_CC_EQ:
		eq = true;
		/* fall through. */
	case ARC_CC_NE:
		len = gen_j_eq_64(buf, rd, rs, eq, target);
		break;
	case ARC_CC_SET:
		len = gen_jset_64(buf, rd, rs, target);
		break;
	default:
#ifdef ARC_BPF_JIT_DEBUG
		BUG("64-bit jump condition is not known.");
#endif
	}
	return len;
}

/*
 * Generate code for functions calls. There can be two types of calls:
 *
 * - Calling another BPF function
 * - Calling an in-kernel function which is compiled by ARC gcc
 *
 * In the later case, we must comply to ARCv2 ABI and handle arguments
 * and return values accordingly.
 */
u8 gen_func_call(u8 *buf, u64 func_addr, bool external_func)
{
	u8 len = 0;

	/*
	 * In case of an in-kernel function call, always push the 5th
	 * argument onto the stack, because that's where the ABI dictates
	 * it should be found. If the callee doesn't really use it, no harm
	 * is done. The stack is readjusted either way after the call.
	 */
	if (external_func)
		len += push_r64(buf+len, BPF_REG_5);

	len += jump_and_link(buf+len, (u32) func_addr);

	if (external_func) {
		len += arc_add_i(buf+len, ARC_R_SP, ARC_R_SP, ARG5_SIZE);
		/* Assigning ABI's return reg to our JIT's return reg. */
		len += arc_mov_r(buf+len, REG_LO(BPF_REG_0), ARC_R_0);
		len += arc_mov_r(buf+len, REG_HI(BPF_REG_0), ARC_R_1);
	}

	return len;
}
/*^^^^^^ REVAMP JUMPS ^^^^^^*/
