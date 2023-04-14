#include <linux/filter.h>

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
 * bpf2arc array maps BPF registers to ARC registers. For the translation
 * of some BPF instructions, a pair of temporary registers might be required.
 * This temporary register is added as yet another index in the bpf2arc array,
 * so it will unfold like the rest of registers into the compiling process.
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
static const u8 bpf2arc[][2] = {
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

#define REG_LO(r) (bpf2arc[(r)][0])
#define REG_HI(r) (bpf2arc[(r)][1])

/*
 * To comply with ARCv2 ABI, BPF's arg5 must be put on stack. After which,
 * the stack needs to be restored by ARG5_SIZE.
 */
#define ARG5_SIZE 8

#define ARC_CALLEE_SAVED_REG_FIRST ARC_R_13
#define ARC_CALLEE_SAVED_REG_LAST  ARC_R_25

/* Bytes. */
enum {
	INSN_len_short = 2,	/* Short instructions length. */
	INSN_len_normal = 4,	/* Normal instructions length. */
	INSN_len_imm = 4	/* Length of an extra 32-bit immediate. */
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

#define IN_U6_RANGE(x)	((x) <= 63 && (x) >= 0)
#define IN_S9_RANGE(x)	((x) <= 255 && (x) >= -256)
#define IN_S12_RANGE(x)	((x) <= 2047 && (x) >= -2048)
#define IN_S21_RANGE(x)	((x) <= 1048575 && (x) >= -1048576)

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
 * The 4-byte encoding of "mpyd a,b,c".
 * mpyd is the signed 32-bit multiplication with the lower 32-bit of
 * the prodcut in register "a" and the higher 32-bit in register "a+1".
 *
 * 0010_1bbb 0001_1000 0BBB_cccc ccaa_aaaa
 *
 * a:  aaaaaa		64-bit result in registers (R_a+1,R_a)
 * b:  BBBbbb		the 1st input operand
 * c:  cccccc		the 2nd input operand
 */
#define OPC_MPYD	0x28180000
#define OPC_MPYDI	OPC_MPYD | OP_IMM

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
 * that is world aligned: (PC & ~0xffff_fff4) + s21
 * B[qq] s21
 *
 * 0000_0sss ssss_sss0 SSSS_SSSS SS0q_qqqq
 *
 * qq:	qqqqq				condtion code
 * s21:	SSSS SSSS_SSss ssss_ssss	The displacement (21-bit signed)
 *
 * The displacement is supposed to be 16-bit (2-byte) aligned. Therefore,
 * it should be a multiple of 2. Hence, there is a implied '0' bit at its
 * LSB: S_SSSS SSSS_Ssss ssss_sss0
 */
#define B_OPCODE	0x00000000
#define B_S21(d)	((((d) & 0x7fe) << 16) | (((d) & 0x1ff800) >> 5))

/*
 * TODO: remove me.
 * Dumps bytes in /var/log/messages at KERN_INFO level (4).
 */
static void dump_bytes(const u8 *buf, u32 len, bool jit)
{
	u8 line[256];
	size_t i, j;

	if (jit)
		pr_info("-----------------[ jited ]-----------------\n");
	else
		pr_info("-----------------[  VM   ]-----------------\n");

	for (i = 0, j = 0; i < len; i++) {
		if (i == len-1) {
			sprintf(line+j, "0x%02x" , buf[i]);
			pr_info("%s\n", line);
			break;
		}
		else if (i % 8 == 7) {
			sprintf(line+j, "0x%02x", buf[i]);
			pr_info("%s\n", line);
			j = 0;
		} else {
			j += sprintf(line+j, "0x%02x, ", buf[i]);
		}
	}

	if (jit)
		pr_info("\n");
}

/*
 * If "emit" is true, the instructions are actually generated. Else, the
 * generation part will be skipped and only the length of instruction is
 * returned by the responsible functions.
 */
static bool emit = false;

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

static u8 arc_add_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_ADD | OP_A(rd) | OP_B(rd) | OP_C(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_addf_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_ADDF | OP_A(rd) | OP_B(rd) | OP_C(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_addif_r(u8 *buf, u8 rd, u8 imm)
{
	if (emit) {
		const u32 insn = OPC_ADDIF | OP_A(rd) | OP_B(rd) | ADDI_U6(imm);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_addi_r(u8 *buf, u8 rd, u8 imm)
{
	if (emit) {
		const u32 insn = OPC_ADDI | OP_A(rd) | OP_B(rd) | ADDI_U6(imm);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_add_i(u8 *buf, u8 rd, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_ADD_I | OP_A(rd) | OP_B(rd);
		emit_4_bytes(buf                , insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

static u8 arc_adc_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_ADC | OP_A(rd) | OP_B(rd) | OP_C(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_adci_r(u8 *buf, u8 rd, u8 imm)
{
	if (emit) {
		const u32 insn = OPC_ADCI | OP_A(rd) | OP_B(rd) | ADCI_U6(imm);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_sub_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_SUB | OP_A(rd) | OP_B(rd) | OP_C(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_subf_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_SUBF | OP_A(rd) | OP_B(rd) | OP_C(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_subi_r(u8 *buf, u8 rd, u8 imm)
{
	if (emit) {
		const u32 insn = OPC_SUBI | OP_A(rd) | OP_B(rd) | SUBI_U6(imm);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_sub_i(u8 *buf, u8 rd, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_SUB_I | OP_A(rd) | OP_B(rd);
		emit_4_bytes(buf                , insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

static u8 arc_sbc_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_SBC | OP_A(rd) | OP_B(rd) | OP_C(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_cmp_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_CMP | OP_B(rd) | OP_C(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_cmp_i(u8 *buf, u8 rd, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_CMP_I | OP_B(rd);
		emit_4_bytes(buf                , insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

/*
 * This "cmp.z" variant of compare instruction is used on lower
 * 32-bits of register pairs after "cmp"ing their upper parts. If the
 * upper parts are equal (z), then this one will proceed to check the
 * rest.
 */
static u8 arc_cmpz_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_CMP | OP_B(rd) | OP_C(rs) | CC_equal;
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_neg_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_NEG | OP_A(rd) | OP_B(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_mpy_r(u8 *buf, u8 rd, u8 rs1, u8 rs2)
{
	if (emit) {
		const u32 insn = OPC_MPY | OP_A(rd) | OP_B(rs1) | OP_C(rs2);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_mpy_i(u8 *buf, u8 rd, u8 rs, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_MPYI | OP_A(rd) | OP_B(rs);
		emit_4_bytes(buf, insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

static u8 arc_mpyd_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_MPYD | OP_A(rd) | OP_B(rd) | OP_C(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_mpyd_i(u8 *buf, u8 rd, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_MPYDI | OP_A(rd) | OP_B(rd);
		emit_4_bytes(buf, insn);
		emit_4_bytes(buf+INSN_len_normal, imm);
	}
	return INSN_len_normal + INSN_len_imm;
}

static u8 arc_mpydu_r(u8 *buf, u8 rd, u8 rs)
{
	if (emit) {
		const u32 insn = OPC_MPYDU | OP_A(rd) | OP_B(rd) | OP_C(rs);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

static u8 arc_mpydu_i(u8 *buf, u8 rd, s32 imm)
{
	if (emit) {
		const u32 insn = OPC_MPYDUI | OP_A(rd) | OP_B(rd);
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

/* st.as reg_c, [reg_b, off] */
static u8 arc_st_r(u8 *buf, u8 reg, u8 reg_mem, s16 off, u8 zz)
{
	if (emit) {
		const u32 insn = OPC_ST | STORE_AA(AA_none) | STORE_ZZ(zz) |
			   OP_C(reg) | OP_B(reg_mem) | STORE_S9(off);
		emit_4_bytes(buf, insn);
	}

	return INSN_len_normal;
}

/* "push reg" is merely a "st.aw reg_c, [sp, -4]". */
static u8 arc_push_r(u8 *buf, u8 reg)
{
	if (emit) {
		const u32 insn = OPC_PUSH | OP_C(reg);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/* ld.aw reg_c, [reg_b, off] */
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

static u8 arc_b(u8 *buf, u8 cc, int offset)
{
	if (emit) {
		const u32 insn = B_OPCODE | B_S21(offset) | COND(cc);
		emit_4_bytes(buf, insn);
	}
	return INSN_len_normal;
}

/*********************** Packers *************************/

/* An indicator if zero-extend must be done for the 32-bit operations. */
bool zext_thyself = false;

static inline u8 zext(u8 *buf, u8 rd)
{
	if (zext_thyself && rd != BPF_REG_FP)
		return arc_movi_r(buf, REG_HI(rd), 0);
	else
		return 0;
}

static u8 add_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_add_r(buf, REG_LO(rd), REG_LO(rs));
}

static u8 add_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	if (IN_U6_RANGE(imm))
		return arc_addi_r(buf, REG_LO(rd), imm);
	else
		return arc_add_i(buf, REG_LO(rd), imm);
}

static u8 add_r64(u8 *buf, u8 rd, u8 rs)
{
	u8 len;
	len  = arc_addf_r(buf, REG_LO(rd), REG_LO(rs));
	len += arc_adc_r(buf+len, REG_HI(rd), REG_HI(rs));
	return len;
}

static u8 mov_r64_i32(u8 *, u8, s32);

static u8 add_r64_i32(u8 *buf, u8 rd, s32 imm)
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

static u8 sub_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_sub_r(buf, REG_LO(rd), REG_LO(rs));
}

static u8 sub_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	if (IN_U6_RANGE(imm))
		return arc_subi_r(buf, REG_LO(rd), imm);
	else
		return arc_sub_i(buf, REG_LO(rd), imm);
}

static u8 sub_r64(u8 *buf, u8 rd, u8 rs)
{
	u8 len;
	len  = arc_subf_r(buf, REG_LO(rd), REG_LO(rs));
	len += arc_sbc_r(buf+len, REG_HI(rd), REG_HI(rs));
	return len;
}

static u8 sub_r64_i32(u8 *buf, u8 rd, s32 imm)
{
	u8 len;
	len  = mov_r64_i32(buf, JIT_REG_TMP, imm);
	len += sub_r64(buf+len, rd, JIT_REG_TMP);
	return len;
}

static u8 cmp_r32(u8 *buf, u8 rd, u8 rs)
{
	u8 len;
	len = arc_cmp_r(buf, REG_LO(rd), REG_LO(rs));
	return len;
}

static u8 cmp_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	return arc_cmp_i(buf, REG_LO(rd), imm);
}

/*
 * Check the higher 32-bit parts first. Only if they're equal,
 * then move on to the lower parts. Else, the result is known.
 */
static u8 cmp_r64(u8 *buf, u8 rd, u8 rs)
{
	u8 len;
	len  = arc_cmp_r(buf     , REG_HI(rd), REG_HI(rs));
	len += arc_cmpz_r(buf+len, REG_LO(rd), REG_LO(rs));
	return len;
}

static u8 cmp_r64_i32(u8 *buf, u8 rd, s32 imm)
{
	u8 len;
	len  = mov_r64_i32(buf, JIT_REG_TMP, imm);
	len += cmp_r64(buf+len, rd, JIT_REG_TMP);
	return len;
}

static u8 neg_r32(u8 *buf, u8 r)
{
	return arc_neg_r(buf, REG_LO(r), REG_LO(r));
}

/* In a two's complement system, -r is (~r + 1). */
static u8 neg_r64(u8 *buf, u8 r)
{
	u8 len;
	len  = arc_not_r(buf, REG_LO(r), REG_LO(r));
	len += arc_not_r(buf+len, REG_HI(r), REG_HI(r));
	len += add_r64_i32(buf+len, r, 1);
	return len;
}

static u8 mul_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_mpy_r(buf, REG_LO(rd), REG_LO(rd), REG_LO(rs));
}

static u8 mul_r32_i32(u8 *buf, u8 rd, s32 imm)
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
static u8 mul_r64(u8 *buf, u8 rd, u8 rs)
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
 * --------
 * mpy     t0, B_hi, imm
 * mpyd  B_lo, B_lo, imm
 * add   B_hi, B_hi,  t0
 */
static u8 mul_r64_i32(u8 *buf, u8 rd, s32 imm)
{
	const u8 t0   = REG_LO(JIT_REG_TMP);
	const u8 B_lo = REG_LO(rd);
	const u8 B_hi = REG_HI(rd);
	u8 len;

	if (imm == 1)
		return 0;

	len  = arc_mpy_i(buf, t0, B_hi, imm);
	len += arc_mpyd_i(buf+len, B_lo, imm);
	len += arc_add_r(buf+len, B_hi, t0);

	return len;
}

static u8 div_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_divu_r(buf, REG_LO(rd), REG_LO(rs));
}

static u8 div_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	return arc_divu_i(buf, REG_LO(rd), imm);
}

static u8 mod_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_remu_r(buf, REG_LO(rd), REG_LO(rs));
}

static u8 mod_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	return arc_remu_i(buf, REG_LO(rd), imm);
}

static u8 and_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_and_r(buf, REG_LO(rd), REG_LO(rs));
}

static u8 and_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	return arc_and_i(buf, REG_LO(rd), imm);
}

static u8 and_r64(u8 *buf, u8 rd, u8 rs)
{
	u8 len;
	len  = arc_and_r(buf    , REG_LO(rd), REG_LO(rs));
	len += arc_and_r(buf+len, REG_HI(rd), REG_HI(rs));
	return len;
}

static u8 and_r64_i32(u8 *buf, u8 rd, s32 imm)
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

/*
 * Check the high 32-bits only if the low 32-bits actually set
 * the zero flag. Otherwise, we might end up setting the zero
 * flag by looking into the second half while the first half
 * was not zero.
 */
static u8 tst_r64(u8 *buf, u8 rd, u8 rs)
{
	u8 len;
	len  = arc_tst_r(buf     , REG_LO(rd), REG_LO(rs));
	len += arc_tstz_r(buf+len, REG_HI(rd), REG_HI(rs));
	return len;
}

static u8 tst_r64_i32(u8 *buf, u8 rd, s32 imm)
{
	u8 len;
	len  = mov_r64_i32(buf, JIT_REG_TMP, imm);
	len += tst_r64(buf+len, rd, JIT_REG_TMP);
	return len;
}

static u8 or_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_or_r(buf, REG_LO(rd), REG_LO(rd), REG_LO(rs));
}

static u8 or_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	return arc_or_i(buf, REG_LO(rd), imm);
}

static u8 or_r64(u8 *buf, u8 rd, u8 rs)
{
	u8 len;
	len  = arc_or_r(buf    , REG_LO(rd), REG_LO(rd), REG_LO(rs));
	len += arc_or_r(buf+len, REG_HI(rd), REG_HI(rd), REG_HI(rs));
	return len;
}

static u8 or_r64_i32(u8 *buf, u8 rd, s32 imm)
{
	u8 len;
	len  = mov_r64_i32(buf, JIT_REG_TMP, imm);
	len += or_r64(buf+len, rd, JIT_REG_TMP);
	return len;
}

static u8 xor_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_xor_r(buf, REG_LO(rd), REG_LO(rs));
}

static u8 xor_r32_i32(u8 *buf, u8 rd, s32 imm)
{
	return arc_xor_i(buf, REG_LO(rd), imm);
}

static u8 xor_r64(u8 *buf, u8 rd, u8 rs)
{
	u8 len;
	len  = arc_xor_r(buf    , REG_LO(rd), REG_LO(rs));
	len += arc_xor_r(buf+len, REG_HI(rd), REG_HI(rs));
	return len;
}

static u8 xor_r64_i32(u8 *buf, u8 rd, s32 imm)
{
	u8 len;
	len  = mov_r64_i32(buf, JIT_REG_TMP, imm);
	len += xor_r64(buf+len, rd, JIT_REG_TMP);
	return len;
}

/* "asl a,b,c" --> "a = (b << (c & 31))". */
static u8 lsh_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_asl_r(buf, CC_great_eq_u, rd, rs);
}

static u8 lsh_r32_i32(u8 *buf, u8 rd, u8 imm)
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
 *   hi = lo << (n-32)      # for n>=32, effective n is n&31, therefore
 *   lo = 0                 # "lo << (n-32)" is the same as "lo << n"
 *
 * assembly translation for "LSH B, C"
 * (heavily influenced by ARC gcc)
 * -----------------------------------
 * not    t0, C_lo            # The first 3 lines are almost the same as:
 * lsr    t1, B_lo, 1         #   neg   t0, C_lo
 * lsr    t1, t1, t0          #   lsr   t1, B_lo, t0   --> t1 is "to_hi"
 * mov    t0, C_lo            # with one important difference. In "neg"
 * asl    B_lo, B_lo, C_lo    # version, when C_lo=0, t1 becomes B_lo while
 * asl    B_hi, B_hi, C_lo    # it should be 0. The "not" approach instead,
 * or     B_hi, B_hi, t1      # "shift"s t1 once and 31 times, practically
 * btst   t0, 5               # setting it to 0 when C_lo=0.
 * mov.ne B_hi, B_lo
 * mov.ne B_lo, 0
 *
 * The "mov t0, C_lo" is necessary to cover the cases that C is the same
 * register as B.
 *
 * The behaviour is undefined for n >= 64.
 */
static u8 lsh_r64(u8 *buf, u8 rd, u8 rs)
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
	len += arc_asl_r(buf+len, B_lo, B_lo, C_lo);
	len += arc_asl_r(buf+len, B_hi, B_hi, C_lo);
	len += arc_or_r(buf+len, B_hi, B_hi, t1);
	len += arc_btst_i(buf+len, t0, 5);
	len += arc_movu_cc_r(buf+len, CC_unequal, B_hi, B_lo);
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
static u8 lsh_r64_i32(u8 *buf, u8 rd, s32 imm)
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
static u8 rsh_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_lsr_r(buf, CC_great_eq_u, rd, rs);
}

static u8 rsh_r32_i32(u8 *buf, u8 rd, u8 imm)
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
 * lsr    B_hi, B_hi, C_lo
 * lsr    B_lo, B_lo, C_lo
 * or     B_lo, B_lo, t1
 * btst   t0, 5
 * mov.ne B_lo, B_hi
 * mov.ne B_hi, 0
 */
static u8 rsh_r64(u8 *buf, u8 rd, u8 rs)
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
	len += arc_lsr_r(buf+len, B_hi, B_hi, C_lo);
	len += arc_lsr_r(buf+len, B_lo, B_lo, C_lo);
	len += arc_or_r(buf+len, B_lo, B_lo, t1);
	len += arc_btst_i(buf+len, t0, 5);
	len += arc_movu_cc_r(buf+len, CC_unequal, B_lo, B_hi);
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
static u8 rsh_r64_i32(u8 *buf, u8 rd, s32 imm)
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
static u8 arsh_r32(u8 *buf, u8 rd, u8 rs)
{
	return arc_asr_r(buf, CC_great_eq_u, rd, rs);
}

static u8 arsh_r32_i32(u8 *buf, u8 rd, u8 imm)
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
 * asr    B_hi, B_hi, C_lo
 * lsr    B_lo, B_lo, C_lo
 * or     B_lo, B_lo, t1
 * btst   t0, 5
 * asr    t0, B_hi, 31        # now, t0 = 0 or -1 based on B_hi's sign
 * mov.ne B_lo, B_hi
 * mov.ne B_hi, t0
 */
static u8 arsh_r64(u8 *buf, u8 rd, u8 rs)
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
	len += arc_asr_r(buf+len, B_hi, B_hi, C_lo);
	len += arc_lsr_r(buf+len, B_lo, B_lo, C_lo);
	len += arc_or_r(buf+len, B_lo, B_lo, t1);
	len += arc_btst_i(buf+len, t0, 5);
	len += arc_asri_r(buf+len, t0, B_hi, 31);
	len += arc_movu_cc_r(buf+len, CC_unequal, B_lo, B_hi);
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
static u8 arsh_r64_i32(u8 *buf, u8 rd, s32 imm)
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

static u8 gen_swap(u8 *buf, u8 rd, u8 size, u8 endian, u8 *len)
{
	int ret = 0;
#ifdef __BIG_ENDIAN
	const u8 host_endian = BPF_FROM_BE;
#else
	const u8 host_endian = BPF_FROM_LE;
#endif
	*len = 0;

	/*
	 * If the same endianness, there's not much to do other
	 * than zeroing out the upper bytes based on the "size".
	 */
	if (host_endian == endian) {
		switch (size) {
		case 16:
			*len += arc_and_i(buf+*len, REG_LO(rd), 0xffff);
			fallthrough;
		case 32:
			*len += zext(buf+*len, rd);
			fallthrough;
		case 64:
			break;
		default:
			ret = -EINVAL;
		}
	} else {
		switch (size) {
		case 16:
			/*
			 * r = B4B3_B2B1 << 16 --> r = B2B1_0000
			 * swape(r) is 0000_B1B2
			 */
			*len += arc_asli_r(buf+*len, REG_LO(rd), REG_LO(rd),
					   16);
			fallthrough;
		case 32:
			*len += arc_swape_r(buf+*len, REG_LO(rd));
			*len += zext(buf+*len, rd);
			break;
		case 64:
			/*
			 * swap "hi" and "lo":
			 *   hi ^= lo;
			 *   lo ^= hi;
			 *   hi ^= lo;
			 * and then swap the bytes in "hi" and "lo".
			 */
			*len += arc_xor_r(buf+*len, REG_HI(rd), REG_LO(rd));
			*len += arc_xor_r(buf+*len, REG_LO(rd), REG_HI(rd));
			*len += arc_xor_r(buf+*len, REG_HI(rd), REG_LO(rd));
			*len += arc_swape_r(buf+*len, REG_LO(rd));
			*len += arc_swape_r(buf+*len, REG_HI(rd));
			break;
		default:
			ret = -EINVAL;
		}
	}

	if (ret != 0)
		pr_err("bpf-jit: invalid size for swap.\n");
	return ret;
}

static u8 mov_r32(u8 *buf, u8 rd, u8 rs)
{
	if (rd == rs)
		return 0;
	return arc_mov_r(buf, REG_LO(rd), REG_LO(rs));
}

static u8 mov_r32_i32(u8 *buf, u8 reg, s32 imm)
{
	return arc_mov_i(buf, REG_LO(reg), imm);
}

static u8 mov_r64(u8 *buf, u8 rd, u8 rs)
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

/* sign extend the 32-bit immediate into 64-bit register pair. */
static u8 mov_r64_i32(u8 *buf, u8 reg, s32 imm)
{
	u8 len = 0;

	len = arc_mov_i(buf, REG_LO(reg), imm);
	if (imm >= 0)
		len += arc_movi_r(buf+len, REG_HI(reg), 0);
	else
		len += arc_movi_r(buf+len, REG_HI(reg), -1);

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
static u8 mov_r64_i64(u8 *buf, u8 reg, u32 lo, u32 hi)
{
	u8 len;

	len  = arc_mov_i_fixed(buf, REG_LO(reg), lo);
	len += arc_mov_i_fixed(buf+len, REG_HI(reg), hi);

	return len;
}

/*
 * If the offset is too big to fit in s9, emit:
 *   mov r20, reg
 *   add r20, r20, off
 * and make sure that r20 will be the effective address for store:
 *   st  r, [r20, 0]
 */
static u8 correct_mem_offset(u8 *buf, s16 *off, u8 size,
			     u8 reg_mem, u8 *arc_reg_mem)
{
	u8 len = 0;

	if (!IN_S9_RANGE(*off) ||
	    (size == BPF_DW && !IN_S9_RANGE(*off + 4))) {
		*arc_reg_mem = REG_LO(JIT_REG_TMP);
		len  = arc_mov_r(buf    , *arc_reg_mem, reg_mem);
		len += arc_add_i(buf+len, *arc_reg_mem, (u32) off);
		*off = 0;
	}

	return len;
}

static u8 store_r(u8 *buf, u8 reg, u8 reg_mem, s16 off, u8 size)
{
	u8 arc_reg_mem = REG_LO(reg_mem);
	u8 len;

	len = correct_mem_offset(buf, &off, size, reg_mem, &arc_reg_mem);

	if (size == BPF_DW) {
		len += arc_st_r(buf+len, REG_LO(reg), arc_reg_mem, off,
				ZZ_4_byte);
		len += arc_st_r(buf+len, REG_HI(reg), arc_reg_mem, off+4,
				ZZ_4_byte);
	} else {
		u8 zz = bpf_to_arc_size(size);
		len += arc_st_r(buf+len, REG_LO(reg), arc_reg_mem, off, zz);
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
static u8 store_i(u8 *buf, s32 imm, u8 reg_mem, s16 off, u8 size)
{
	/* REG_LO(JIT_REG_TMP) might be used by "correct_mem_offset()". */
	const u8 arc_rs = REG_HI(JIT_REG_TMP);
	u8 arc_reg_mem = REG_LO(reg_mem);
	u8 len;

	len = correct_mem_offset(buf, &off, size, reg_mem, &arc_reg_mem);

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

static u8 load_r(u8 *buf, u8 reg, u8 reg_mem, s16 off, u8 size)
{
	u8 len = 0;
	u8 arc_reg_mem = REG_LO(reg_mem);

	/*
	 * If the offset is too big to fit in s9, emit:
	 *   mov r20, reg
	 *   add r20, r20, off
	 * and make sure that r20 will be the effective address for the "load".
	 *   ld  r, [r20, 0]
	 */
	if (!IN_S9_RANGE(off) ||
	    (size == BPF_DW && !IN_S9_RANGE(off + 4))) {
		arc_reg_mem = REG_LO(JIT_REG_TMP);
		len  = arc_mov_r(buf    , arc_reg_mem, reg_mem);
		len += arc_add_i(buf+len, arc_reg_mem, (u32) off);
		off = 0;
	}

	if (size == BPF_B || size == BPF_H || size == BPF_W) {
		u8 zz = bpf_to_arc_size(size);
		len += arc_ld_r(buf+len, REG_LO(reg), arc_reg_mem, off, zz);
		len += arc_movi_r(buf+len, REG_HI(reg), 0);
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
		if (REG_LO(reg) != arc_reg_mem) {
			len += arc_ld_r(buf+len, REG_LO(reg), arc_reg_mem,
					off+0, ZZ_4_byte);
			len += arc_ld_r(buf+len, REG_HI(reg), arc_reg_mem,
					off+4, ZZ_4_byte);
		} else {
			len += arc_ld_r(buf+len, REG_HI(reg), arc_reg_mem,
					off+4, ZZ_4_byte);
			len += arc_ld_r(buf+len, REG_LO(reg), arc_reg_mem,
					off+0, ZZ_4_byte);
		}
	}

	return len;
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
static u8 enter_frame(u8 *buf, u16 size)
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
static u8 exit_frame(u8 *buf)
{
	return arc_mov_r(buf, ARC_R_SP, ARC_R_FP);
}

static u8 jump_return(u8 *buf)
{
	return arc_jmp_return(buf);
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

/********************* JIT context ***********************/

/*
 * buf:		Translated instructions end up here.
 * len:		The length of whole block in bytes.
 * index:	The offset at which the _next_ instruction may be put.
 */
struct jit_buffer
{
	u8	*buf;
	u32	len;
	u32	index;
};

/*
 * This is a subset of "struct jit_context" that its information is deemed
 * necessary for the next extra pass to come.
 *
 * bpf_header:	Needed to finally lock the region.
 * bpf2insn:	Used to find the translation of "call" instructions.
 *
 * Things like "jit.buf" and "jit.len" can be retrieved respectively from
 * "prog->bpf_func" and "prog->jited_len".
 */
struct arc_jit_data
{
	struct bpf_binary_header *bpf_header;
	u32                      *bpf2insn;
};

/*
 * The JIT pertinent context that is used by different functions.
 *
 * prog:		The current eBPF program being handled.
 * orig_prog:		The original eBPF program before any possible change.
 * jit:			The JIT buffer and its length.
 * bpf_header:		The JITed program header. "jit.buf" points inside it.
 * bpf2insn:		Maps BPF insn indices to their counterparts in jit.buf.
 * bpf2insn_valid:	Indicates if "bpf2ins" is populated with the mappings.
 * jit_data:		A piece of memory to transfer data to the next pass.
 * arc_regs_clobbered:	Each bit status determines if that arc reg is clobbered.
 * save_blink:		If ARC's "blink" register needs to be saved.
 * frame_size:		Derived from FP accesses (fp-4, fp-8, ...).
 * epilogue_offset:	Used by early "return"s in the code to jump here.
 * need_extra_pass:	A forecast if an "extra_pass" will occur.
 * is_extra_pass:	Indicates if the current pass is an extra pass.
 * user_bpf_prog:	True, if VM opcodes come from a real program.
 * blinded:		True if "constant blinding" step returned a new "prog".
 * success:		Indicates if the whole JIT went OK.
 */
struct jit_context
{
	struct bpf_prog			*prog;
	struct bpf_prog			*orig_prog;
	struct jit_buffer		jit;
	struct bpf_binary_header	*bpf_header;
	u32				*bpf2insn;
	bool				bpf2insn_valid;
	struct arc_jit_data		*jit_data;
	u32				arc_regs_clobbered;
	bool				save_blink;
	u16				frame_size;
	u32				epilogue_offset;
	bool				need_extra_pass;
	bool				is_extra_pass;
	bool				user_bpf_prog;
	bool				blinded;
	bool				success;
};

static int jit_ctx_init(struct jit_context *ctx, struct bpf_prog *prog)
{
	ctx->orig_prog = prog;

	/* If constant blinding was requested but failed, scram. */
	ctx->prog = bpf_jit_blind_constants(prog);
	if (IS_ERR(ctx->prog))
		return PTR_ERR(ctx->prog);
	ctx->blinded = (ctx->prog == ctx->orig_prog ? false : true);

	ctx->jit.buf            = NULL;
	ctx->jit.len            = 0;
	ctx->jit.index          = 0;
	ctx->bpf_header         = NULL;
	ctx->bpf2insn           = NULL;
	ctx->bpf2insn_valid     = false;
	ctx->jit_data           = NULL;
	ctx->arc_regs_clobbered = 0;
	ctx->save_blink         = false;
	ctx->frame_size         = 0;
	ctx->epilogue_offset    = 0;
	ctx->need_extra_pass    = false;
	ctx->is_extra_pass	= ctx->prog->jited;
	ctx->user_bpf_prog	= ctx->prog->is_func;
	ctx->success            = false;

	/* If the verifier doesn't zero-extend, then we have to do it. */
	zext_thyself = !ctx->prog->aux->verifier_zext;

	return 0;
}

/*
 * "*mem" should be freed when there is no "extra pass" to come,
 * or the compilation terminated abruptly. A few of such memory
 * allocations are: ctx->jit_data and ctx->bpf2insn.
 */
static inline void maybe_free(struct jit_context *ctx, void **mem)
{
	if (*mem) {
		if (!ctx->success || !ctx->need_extra_pass) {
			kfree(*mem);
			*mem = NULL;
		}
	}
}

/*
 * Free memories based on the status of the context.
 *
 * A note about "bpf_header": On successful runs, "bpf_header" is
 * not freed, because "jit.buf", a sub-array of it, is returned as
 * the "bpf_func". However, "bpf_header" is lost and nothing points
 * to it. This should not cause a leakage, because apparently
 * "bpf_header" can be revived by "bpf_jit_binary_hdr()". This is
 * how "bpf_jit_free()" in "kernel/bpf/core.c" releases the memory.
 */
static void jit_ctx_cleanup(struct jit_context *ctx)
{
	if (ctx->blinded) {
		/* if all went well, release the orig_prog. */
		if (ctx->success)
			bpf_jit_prog_release_other(ctx->prog, ctx->orig_prog);
		else
			bpf_jit_prog_release_other(ctx->orig_prog, ctx->prog);
	}

	maybe_free(ctx, (void **) &ctx->bpf2insn);
	maybe_free(ctx, (void **) &ctx->jit_data);

	if (!ctx->bpf2insn)
		ctx->bpf2insn_valid = false;

	/* Freeing "bpf_header" is enough. "jit.buf" is a sub-array of it. */
	if (!ctx->success && ctx->bpf_header) {
		bpf_jit_binary_free(ctx->bpf_header);
		ctx->bpf_header = NULL;
		ctx->jit.buf    = NULL;
		ctx->jit.index  = 0;
		ctx->jit.len    = 0;
	}

	/* Global vars back to their original state. */
	emit         = false;
	zext_thyself = false;
}

/*
 * This function is responsible for deciding which ARC registers must be
 * saved and restored accross the JIT translation of a BPF function. It
 * merely looks at "dst" register of BPF instructions and their mappings
 * to figure this out. Therefore, it is not aware of the semantics of any
 * instruction. When a register of interest is clobbered, its corresponding
 * bit position in ctx->arc_regs_clobbered is set to true.
 */
static void analyze_reg_usage(struct jit_context *ctx)
{
	u32 usage = 0;
	s16 size = 0;	/* Will be "min()"ed against negative numbers. */
	size_t i;
	const struct bpf_insn *insn = ctx->prog->insnsi;

	for (i = 0; i < ctx->prog->len; i++) {
		const u8 bpf_reg = insn[i].dst_reg;

		/* BPF registers that must be saved. */
		if (bpf_reg >= BPF_REG_6 && bpf_reg <= BPF_REG_9) {
			usage |= BIT(REG_LO(bpf_reg));
			usage |= BIT(REG_HI(bpf_reg));
		/*
		 * Reading the frame pointer register implies that it should
		 * be saved and reinitialised with the current frame data.
		 */
		} else if (bpf_reg == BPF_REG_FP) {
			const u8 store_mem_mask = 0x67;
			const u8 code_mask = insn[i].code & store_mem_mask;
			usage |= BIT(REG_LO(BPF_REG_FP));
			/* Is FP usage in the form of "*(FP + -off) = data"? */
			if (code_mask == (BPF_STX | BPF_MEM)) {
				/* Then, record the deepest "off"set. */
				size = min(size, insn[i].off);
			}
		/* Could there be some ARC registers that must to be saved? */
		} else {
			if (REG_LO(bpf_reg) >= ARC_CALLEE_SAVED_REG_FIRST &&
			    REG_LO(bpf_reg) <= ARC_CALLEE_SAVED_REG_LAST)
				usage |= BIT(REG_LO(bpf_reg));

			if (REG_HI(bpf_reg) >= ARC_CALLEE_SAVED_REG_FIRST &&
			    REG_HI(bpf_reg) <= ARC_CALLEE_SAVED_REG_LAST)
				usage |= BIT(REG_HI(bpf_reg));
		}

		/* A "call" indicates that ARC's "blink" reg must be saved. */
		if (insn[i].code == (BPF_JMP | BPF_CALL))
			usage |= BIT(ARC_R_BLINK);
	}

	ctx->arc_regs_clobbered = usage;
	ctx->frame_size         = abs(size);
}

/* Verify that no instruction will be emitted when there is no buffer. */
static inline int jit_buffer_check(const struct jit_buffer *jbuf)
{
	if (emit == true) {
		if (jbuf->buf == NULL) {
			pr_err("bpf-jit: inconsistence state; no "
			       "buffer to emit instructions.\n");
			return -EINVAL;
		} else if (jbuf->index > jbuf->len) {
			pr_err("bpf-jit: estimated JIT length is less "
			       "than the emitted instructions.\n");
			return -EFAULT;
		}
	}
	return 0;
}

/* On a dry run (emit=false), "jit.len" is growing gradually. */
static inline void jit_buffer_update(struct jit_buffer *jbuf, u32 n)
{
	if (!emit)
		jbuf->len += n;
	else
		jbuf->index += n;
}

/* Based on "emit", determine the address where instructions are emitted. */
static inline u8 *effective_jit_buf(const struct jit_buffer *jbuf)
{
	return (emit ? jbuf->buf + jbuf->index : NULL);
}

/*
 * If "emit" is true, all the necessary "push"s are generated. Else, it acts
 * as a dry run and only updates the length of would-have-been instructions.
 */
static int handle_prologue(struct jit_context *ctx)
{
	int ret;
	u32 gp_regs = 0;
	u8 *buf = effective_jit_buf(&ctx->jit);
	u32 len = 0;

	if ((ret = jit_buffer_check(&ctx->jit)))
	    return ret;

	/* Deal with blink first. */
	if (ctx->arc_regs_clobbered & BIT(ARC_R_BLINK))
		len += arc_push_r(buf+len, ARC_R_BLINK);

	gp_regs = ctx->arc_regs_clobbered & ~(BIT(ARC_R_BLINK) | BIT(ARC_R_FP));
	while (gp_regs) {
		u8 reg = __builtin_ffs(gp_regs) - 1;

		len += arc_push_r(buf+len, reg);
		gp_regs &= ~BIT(reg);
	}

	/* Deal with fp last. */
	if (ctx->arc_regs_clobbered & BIT(ARC_R_FP))
		len += arc_push_r(buf+len, ARC_R_FP);

	if (ctx->frame_size)
		len += enter_frame(buf+len, ctx->frame_size);

	jit_buffer_update(&ctx->jit, len);

	return 0;
}

/*
 * The counter part for "handle_prologue()". If this function is asked to emit
 * instructions then it continues with "jit.index". If no instruction is
 * supposed to be emitted, it means it should contribute to the calculation of
 * "jit.len", and therefore it begins with that.
 */
static int handle_epilogue(struct jit_context *ctx)
{
	int ret;
	u32 gp_regs = 0;
	u8 *buf = effective_jit_buf(&ctx->jit);
	u32 len = 0;

	if ((ret = jit_buffer_check(&ctx->jit)))
	    return ret;

	if (ctx->frame_size)
		len += exit_frame(buf+len);

	/* Deal with fp first. */
	if (ctx->arc_regs_clobbered & BIT(ARC_R_FP))
		len += arc_pop_r(buf+len, ARC_R_FP);

	gp_regs = ctx->arc_regs_clobbered & ~(BIT(ARC_R_BLINK) | BIT(ARC_R_FP));
	while (gp_regs) {
		u8 reg = 31 - __builtin_clz(gp_regs);

		len += arc_pop_r(buf+len, reg);
		gp_regs &= ~BIT(reg);
	}

	/* Deal with blink last. */
	if (ctx->arc_regs_clobbered & BIT(ARC_R_BLINK))
		len += arc_pop_r(buf+len, ARC_R_BLINK);

	/* Assigning JIT's return reg to ABI's return reg. */
	len += arc_mov_r(buf+len, ARC_R_0, REG_LO(BPF_REG_0));
	len += arc_mov_r(buf+len, ARC_R_1, REG_HI(BPF_REG_0));

	/* At last, issue the "return". */
	len += jump_return(buf+len);

	jit_buffer_update(&ctx->jit, len);

	return 0;
}

static inline s32 get_index_for_insn(const struct jit_context *ctx,
				     const struct bpf_insn *insn)
{
	return (insn - ctx->prog->insnsi);
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
			     const struct bpf_insn *insn, u8 advance,
			     s32 *jit_offset)
{
	u32 jit_curr_addr, jit_targ_addr, pcl;
	const s32 idx = get_index_for_insn(ctx, insn);
	const s16 bpf_offset = insn->off;
	const s32 bpf_targ_idx = (idx+1) + bpf_offset;

	if (idx < 0 || idx >= ctx->prog->len) {
		pr_err("bpf-jit: offset calc. -> insn is not in prog.");
		return -EINVAL;
	}

	if (bpf_targ_idx < 0 || bpf_targ_idx >= ctx->prog->len) {
		pr_err("bpf-jit: bpf jump label is out of range.");
		return -EINVAL;

	}

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
		pr_err("bpf-jit: jit address is not 16-bit aligned.");
		return -EFAULT;
	}

	if (!IN_S21_RANGE(*jit_offset)) {
		pr_err("bpf-jit: jit address is too far to jump to.");
		return -EFAULT;
	}

	return 0;
}

/* Used to emit condition checking instructions before a conditional jump. */
enum OP_TYPES {
	OP_R32_R32,
	OP_R32_I32,
	OP_R64_R64,
	OP_R64_I32
};

/* Note: This conversion function does not handle "BPF_JSET". */
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
 * - emit "cmp" instructions for conditional jumps other than "jset".
 * - emit "tst" instructions for "jset" variant.
 * - emit nothing for unconditional jump "ja".
 */
static u8 emit_check_insn(u8 *buf, const struct bpf_insn *insn,
			  const enum OP_TYPES op_types)
{
	const u8  op  = BPF_OP(insn->code);
	const u8  dst = insn->dst_reg;
	const u8  src = insn->src_reg;
	const s32 imm = insn->imm;
	      u8  len = 0;

	if (op != BPF_JA && op != BPF_JSET) {
		if (op_types == OP_R32_R32)
			len = cmp_r32(buf, dst, src);
		else if (op_types == OP_R32_I32)
			len = cmp_r32_i32(buf, dst, imm);
		else if (op_types == OP_R64_R64)
			len = cmp_r64(buf, dst, src);
		else if (op_types == OP_R64_I32)
			len = cmp_r64_i32(buf, dst, imm);
	} else if (op == BPF_JSET) {
		if (op_types == OP_R32_R32)
			len = tst_r32(buf, dst, src);
		else if (op_types == OP_R32_I32)
			len = tst_r32_i32(buf, dst, imm);
		else if (op_types == OP_R64_R64)
			len = tst_r64(buf, dst, src);
		else if (op_types == OP_R64_I32)
			len = tst_r64_i32(buf, dst, imm);
	}

	return len;
}

/*
 * Emit "check" instructions for conditional jumps,
 * calculate the offset for jump's target address in JIT,
 * and issue the "branch" instruction with the right "cond".
 */
static int gen_jmp(struct jit_context *ctx, const struct bpf_insn *insn,
		   const enum OP_TYPES op_types, u8 *len)
{
	s8  cond;
	s32 disp = 0;
	u8  *buf = effective_jit_buf(&ctx->jit);

	if ((cond = bpf_cond_to_arc(BPF_OP(insn->code))) < 0)
		return cond;

	/* The "op_types" range is already verified by "bpf_cond_to_arc()". */
	*len = emit_check_insn(buf, insn, op_types);

	/* After that ctx->bpf2insn[] is initialised, offsets can be deduced. */
	if (ctx->bpf2insn_valid) {
		int ret = bpf_offset_to_jit(ctx, insn, *len, &disp);
		if (ret < 0)
			return ret;
	}

	*len += arc_b(buf+*len, (u8) cond, disp);

	return 0;
}

/*
 * Invocation of this function, conditionally signals the need for
 * an extra pass. The conditions that must be met are:
 *
 * 1. The current pass itself shouldn't be an extra pass.
 * 2. The stream of bytes being JITed must come from a user program.
 */
static inline void set_need_for_extra_pass(struct jit_context *ctx)
{
	if (!ctx->is_extra_pass)
		ctx->need_extra_pass = ctx->user_bpf_prog;
}

/* Try to get the resolved address and generate the instructions. */
static int gen_call(struct jit_context *ctx, const struct bpf_insn *insn,
		    u8 *len)
{
	int  ret;
	bool in_kernel_func, fixed = false;
	u64  addr = 0;
	u8  *buf = effective_jit_buf(&ctx->jit);

	ret = bpf_jit_get_func_addr(ctx->prog, insn, ctx->is_extra_pass, &addr,
				    &fixed);
	if (ret < 0) {
		pr_err("bpf-jit: can't get the address for call.");
		return ret;
	}
	in_kernel_func = (fixed ? true : false);

	/* No valuble address retrieved (yet). */
	if (!fixed && !addr)
		set_need_for_extra_pass(ctx);

	*len = 0;
	/* In case of an in-kernel function, arg5 is always pushed. */
	if (in_kernel_func)
		*len += push_r64(buf+*len, BPF_REG_5);

	*len += jump_and_link(buf+*len, (u32) addr);

	if (in_kernel_func) {
		*len += arc_add_i(buf+*len, ARC_R_SP, ARG5_SIZE);
		/* Assigning ABI's return reg to our JIT's return reg. */
		*len += arc_mov_r(buf+*len, REG_LO(BPF_REG_0), ARC_R_0);
		*len += arc_mov_r(buf+*len, REG_HI(BPF_REG_0), ARC_R_1);
	}

	return 0;
}

static inline bool is_last_insn(const struct bpf_prog *prog, u32 idx)
{
	return (idx == (prog->len - 1));
}

/*
 * Try to generate instructions for loading a 64-bit immediate.
 * These sort of instructions are usually associated with the 64-bit
 * relocations: R_BPF_64_64. Therefore, signal the need for an extra
 * pass if the circumstances are right.
 */
static int gen_ld_imm64(struct jit_context *ctx, const struct bpf_insn *insn,
			u8 *len)
{
	const s32 idx = get_index_for_insn(ctx, insn);
	u8 *buf = effective_jit_buf(&ctx->jit);

	/* We're about to consume 2 VM instructions. */
	if (is_last_insn(ctx->prog, idx)) {
		pr_err("bpf-jit: need more data for 64-bit immediate.");
		return -EINVAL;
	}

	*len = mov_r64_i64(buf, insn->dst_reg, insn->imm, (insn+1)->imm);
	set_need_for_extra_pass(ctx);

	return 0;
}

/*
 * Jump to epilogue from the current location (insn). For details on
 * offset calculation, see the comments of bpf_offset_to_jit().
 */
static int gen_jmp_epilogue(struct jit_context *ctx,
			    const struct bpf_insn *insn, u8 *len)
{
	int disp = 0;
	u8  *buf = effective_jit_buf(&ctx->jit);
	const s32 idx = get_index_for_insn(ctx, insn);

	if (idx < 0 || idx >= ctx->prog->len) {
		pr_err("bpf-jit: jmp epilogue -> insn is not in prog.");
		return -EINVAL;
	}

	/* Only after the dry-run, ctx->bpf2insn[] holds valid entries. */
	if (ctx->bpf2insn_valid)
		disp = ctx->epilogue_offset - ctx->bpf2insn[idx];

	if (disp & 1 || !IN_S21_RANGE(disp)) {
		pr_err("bpf-jit: displacement to epilogue is not valid.");
		return -EFAULT;
	}

	*len = arc_b(buf, CC_always, disp);

	return 0;
}

/*
 * Handles one eBPF instruction at a time. To make this function faster,
 * it does not call "jit_buffer_check()". Else, it would call it for every
 * instruction. As a result, it should not be invoked directly. Only
 * "handle_body()", that has already executed the verification, may call
 * this function.
 *
 * If the "ret" value is negative, something has went wrong. Else,
 * it mostly holds the value 0 and rarely 1. Number 1 signals
 * the loop in "handle_body()" to skip the next instruction, because
 * it has been consumed as part of a 64-bit immediate value.
 */
static int handle_insn(struct jit_context *ctx, u32 idx)
{
	const struct bpf_insn *insn = &ctx->prog->insnsi[idx];
	u8   code = insn->code;
	u8   dst  = insn->dst_reg;
	u8   src  = insn->src_reg;
	s16  off  = insn->off;
	s32  imm  = insn->imm;
	u8  *buf  = effective_jit_buf(&ctx->jit);
	u8   len  = 0;
	int  ret  = 0;

	switch (code) {
	/* dst += src (32-bit) */
	case BPF_ALU | BPF_ADD | BPF_X:
		len = add_r32(buf, dst, src);
		break;
	/* dst += imm (32-bit) */
	case BPF_ALU | BPF_ADD | BPF_K:
		len = add_r32_i32(buf, dst, imm);
		break;
	/* dst -= src (32-bit) */
	case BPF_ALU | BPF_SUB | BPF_X:
		len = sub_r32(buf, dst, src);
		break;
	/* dst -= imm (32-bit) */
	case BPF_ALU | BPF_SUB | BPF_K:
		len = sub_r32_i32(buf, dst, imm);
		break;
	/* dst = -dst (32-bit) */
	case BPF_ALU | BPF_NEG:
		len = neg_r32(buf, dst);
		break;
	/* dst *= src (32-bit) */
	case BPF_ALU | BPF_MUL | BPF_X:
		len = mul_r32(buf, dst, src);
		break;
	/* dst *= imm (32-bit) */
	case BPF_ALU | BPF_MUL | BPF_K:
		len = mul_r32_i32(buf, dst, imm);
		break;
	/* dst /= src (32-bit) */
	case BPF_ALU | BPF_DIV | BPF_X:
		len = div_r32(buf, dst, src);
		break;
	/* dst /= imm (32-bit) */
	case BPF_ALU | BPF_DIV | BPF_K:
		len = div_r32_i32(buf, dst, imm);
		break;
	/* dst %= src (32-bit) */
	case BPF_ALU | BPF_MOD | BPF_X:
		len = mod_r32(buf, dst, src);
		break;
	/* dst %= imm (32-bit) */
	case BPF_ALU | BPF_MOD | BPF_K:
		len = mod_r32_i32(buf, dst, imm);
		break;
	/* dst &= src (32-bit) */
	case BPF_ALU | BPF_AND | BPF_X:
		len = and_r32(buf, dst, src);
		break;
	/* dst &= imm (32-bit) */
	case BPF_ALU | BPF_AND | BPF_K:
		len = and_r32_i32(buf, dst, imm);
		break;
	/* dst |= src (32-bit) */
	case BPF_ALU | BPF_OR | BPF_X:
		len = or_r32(buf, dst, src);
		break;
	/* dst |= imm (32-bit) */
	case BPF_ALU | BPF_OR | BPF_K:
		len = or_r32_i32(buf, dst, imm);
		break;
	/* dst ^= src (32-bit) */
	case BPF_ALU | BPF_XOR | BPF_X:
		len = xor_r32(buf, dst, src);
		break;
	/* dst ^= imm (32-bit) */
	case BPF_ALU | BPF_XOR | BPF_K:
		len = xor_r32_i32(buf, dst, imm);
		break;
	/* dst <<= src (32-bit) */
	case BPF_ALU | BPF_LSH | BPF_X:
		len = lsh_r32(buf, dst, imm);
		break;
	/* dst <<= imm (32-bit) */
	case BPF_ALU | BPF_LSH | BPF_K:
		len = lsh_r32_i32(buf, dst, imm);
		break;
	/* dst >>= src (32-bit) [unsigned] */
	case BPF_ALU | BPF_RSH | BPF_X:
		len = rsh_r32(buf, dst, imm);
		break;
	/* dst >>= imm (32-bit) [unsigned] */
	case BPF_ALU | BPF_RSH | BPF_K:
		len = rsh_r32_i32(buf, dst, imm);
		break;
	/* dst >>= src (32-bit) [signed] */
	case BPF_ALU | BPF_ARSH | BPF_X:
		len = arsh_r32(buf, dst, imm);
		break;
	/* dst >>= imm (32-bit) [signed] */
	case BPF_ALU | BPF_ARSH | BPF_K:
		len = arsh_r32_i32(buf, dst, imm);
		break;
	/* dst = src (32-bit) */
	case BPF_ALU | BPF_MOV | BPF_X:
		len = mov_r32(buf, dst, src);
		break;
	/* dst = imm32 (32-bit) */
	case BPF_ALU | BPF_MOV | BPF_K:
		len = mov_r32_i32(buf, dst, imm);
		break;
	/* dst = swap(dst) */
	case BPF_ALU | BPF_END | BPF_FROM_LE:
	case BPF_ALU | BPF_END | BPF_FROM_BE:
		if ((ret = gen_swap(buf, dst, imm, BPF_SRC(code), &len)) < 0)
			return ret;
		break;
	/* dst += src (64-bit) */
	case BPF_ALU64 | BPF_ADD | BPF_X:
		len = add_r64(buf, dst, src);
		break;
	/* dst += imm32 (64-bit) */
	case BPF_ALU64 | BPF_ADD | BPF_K:
		len = add_r64_i32(buf, dst, imm);
		break;
	/* dst -= src (64-bit) */
	case BPF_ALU64 | BPF_SUB | BPF_X:
		len = sub_r64(buf, dst, src);
		break;
	/* dst -= imm32 (64-bit) */
	case BPF_ALU64 | BPF_SUB | BPF_K:
		len = sub_r64_i32(buf, dst, imm);
		break;
	/* dst = -dst (64-bit) */
	case BPF_ALU64 | BPF_NEG:
		len = neg_r64(buf, dst);
		break;
	/* dst *= src (64-bit) */
	case BPF_ALU64 | BPF_MUL | BPF_X:
		len = mul_r64(buf, dst, src);
		break;
	/* dst *= imm32 (64-bit) */
	case BPF_ALU64 | BPF_MUL | BPF_K:
		len = mul_r64_i32(buf, dst, imm);
		break;
	/* dst &= src (64-bit) */
	case BPF_ALU64 | BPF_AND | BPF_X:
		len = and_r64(buf, dst, src);
		break;
	/* dst &= imm32 (64-bit) */
	case BPF_ALU64 | BPF_AND | BPF_K:
		len = and_r64_i32(buf, dst, imm);
		break;
	/* dst |= src (64-bit) */
	case BPF_ALU64 | BPF_OR | BPF_X:
		len = or_r64(buf, dst, src);
		break;
	/* dst |= imm32 (64-bit) */
	case BPF_ALU64 | BPF_OR | BPF_K:
		len = or_r64_i32(buf, dst, imm);
		break;
	/* dst ^= src (64-bit) */
	case BPF_ALU64 | BPF_XOR | BPF_X:
		len = xor_r64(buf, dst, src);
		break;
	/* dst ^= imm32 (64-bit) */
	case BPF_ALU64 | BPF_XOR | BPF_K:
		len = xor_r64_i32(buf, dst, imm);
		break;
	/* dst <<= src (64-bit) */
	case BPF_ALU64 | BPF_LSH | BPF_X:
		len = lsh_r64(buf, dst, src);
		break;
	/* dst <<= imm32 (64-bit) */
	case BPF_ALU64 | BPF_LSH | BPF_K:
		len = lsh_r64_i32(buf, dst, imm);
		break;
	/* dst >>= src (64-bit) [unsigned] */
	case BPF_ALU64 | BPF_RSH | BPF_X:
		len = rsh_r64(buf, dst, src);
		break;
	/* dst >>= imm32 (64-bit) [unsigned] */
	case BPF_ALU64 | BPF_RSH | BPF_K:
		len = rsh_r64_i32(buf, dst, imm);
		break;
	/* dst >>= src (64-bit) [signed] */
	case BPF_ALU64 | BPF_ARSH | BPF_X:
		len = arsh_r64(buf, dst, src);
		break;
	/* dst >>= imm32 (64-bit) [signed] */
	case BPF_ALU64 | BPF_ARSH | BPF_K:
		len = arsh_r64_i32(buf, dst, imm);
		break;
	/* dst = src (64-bit) */
	case BPF_ALU64 | BPF_MOV | BPF_X:
		len = mov_r64(buf, dst, src);
		break;
	/* dst = imm32 (sign extend to 64-bit) */
	case BPF_ALU64 | BPF_MOV | BPF_K:
		len = mov_r64_i32(buf, dst, imm);
		break;
	/* dst = imm64 */
	case BPF_LD | BPF_DW | BPF_IMM:
		if ((ret = gen_ld_imm64(ctx, insn, &len)) < 0)
			return ret;
		/* Tell the loop to skip the next instruction. */
		ret = 1;
		break;
	/* dst = *(size *)(src + off) */
	case BPF_LDX | BPF_MEM | BPF_W:
	case BPF_LDX | BPF_MEM | BPF_H:
	case BPF_LDX | BPF_MEM | BPF_B:
	case BPF_LDX | BPF_MEM | BPF_DW:
		len = load_r(buf, dst, src, off, BPF_SIZE(code));
		break;
	/* *(size *)(dst + off) = src */
	case BPF_STX | BPF_MEM | BPF_W:
	case BPF_STX | BPF_MEM | BPF_H:
	case BPF_STX | BPF_MEM | BPF_B:
	case BPF_STX | BPF_MEM | BPF_DW:
		len = store_r(buf, src, dst, off, BPF_SIZE(code));
		break;
	case BPF_ST | BPF_MEM | BPF_W:
	case BPF_ST | BPF_MEM | BPF_H:
	case BPF_ST | BPF_MEM | BPF_B:
	case BPF_ST | BPF_MEM | BPF_DW:
		len = store_i(buf, imm, dst, off, BPF_SIZE(code));
		break;
	case BPF_JMP | BPF_JA:
	case BPF_JMP | BPF_JEQ  | BPF_X:
	case BPF_JMP | BPF_JGT  | BPF_X:
	case BPF_JMP | BPF_JGE  | BPF_X:
	case BPF_JMP | BPF_JSET | BPF_X:
	case BPF_JMP | BPF_JNE  | BPF_X:
	case BPF_JMP | BPF_JSGT | BPF_X:
	case BPF_JMP | BPF_JSGE | BPF_X:
	case BPF_JMP | BPF_JLT  | BPF_X:
	case BPF_JMP | BPF_JLE  | BPF_X:
	case BPF_JMP | BPF_JSLT | BPF_X:
	case BPF_JMP | BPF_JSLE | BPF_X:
		if ((ret = gen_jmp(ctx, insn, OP_R64_R64, &len)) < 0)
			return ret;
		break;
	case BPF_JMP | BPF_JEQ  | BPF_K:
	case BPF_JMP | BPF_JGT  | BPF_K:
	case BPF_JMP | BPF_JGE  | BPF_K:
	case BPF_JMP | BPF_JSET | BPF_K:
	case BPF_JMP | BPF_JNE  | BPF_K:
	case BPF_JMP | BPF_JSGT | BPF_K:
	case BPF_JMP | BPF_JSGE | BPF_K:
	case BPF_JMP | BPF_JLT  | BPF_K:
	case BPF_JMP | BPF_JLE  | BPF_K:
	case BPF_JMP | BPF_JSLT | BPF_K:
	case BPF_JMP | BPF_JSLE | BPF_K:
		if ((ret = gen_jmp(ctx, insn, OP_R64_I32, &len)) < 0)
			return ret;
		break;
	case BPF_JMP32 | BPF_JEQ  | BPF_X:
	case BPF_JMP32 | BPF_JGT  | BPF_X:
	case BPF_JMP32 | BPF_JGE  | BPF_X:
	case BPF_JMP32 | BPF_JSET | BPF_X:
	case BPF_JMP32 | BPF_JNE  | BPF_X:
	case BPF_JMP32 | BPF_JSGT | BPF_X:
	case BPF_JMP32 | BPF_JSGE | BPF_X:
	case BPF_JMP32 | BPF_JLT  | BPF_X:
	case BPF_JMP32 | BPF_JLE  | BPF_X:
	case BPF_JMP32 | BPF_JSLT | BPF_X:
	case BPF_JMP32 | BPF_JSLE | BPF_X:
		if ((ret = gen_jmp(ctx, insn, OP_R32_R32, &len)) < 0)
			return ret;
		break;
	case BPF_JMP32 | BPF_JEQ  | BPF_K:
	case BPF_JMP32 | BPF_JGT  | BPF_K:
	case BPF_JMP32 | BPF_JGE  | BPF_K:
	case BPF_JMP32 | BPF_JSET | BPF_K:
	case BPF_JMP32 | BPF_JNE  | BPF_K:
	case BPF_JMP32 | BPF_JSGT | BPF_K:
	case BPF_JMP32 | BPF_JSGE | BPF_K:
	case BPF_JMP32 | BPF_JLT  | BPF_K:
	case BPF_JMP32 | BPF_JLE  | BPF_K:
	case BPF_JMP32 | BPF_JSLT | BPF_K:
	case BPF_JMP32 | BPF_JSLE | BPF_K:
		if ((ret = gen_jmp(ctx, insn, OP_R32_I32, &len)) < 0)
			return ret;
		break;
	case BPF_JMP | BPF_CALL:
		if ((ret = gen_call(ctx, insn, &len)) < 0)
			return ret;
		break;

	case BPF_JMP | BPF_EXIT:
		/* If this is the last instruction, epilogue will follow. */
		if (is_last_insn(ctx->prog, idx))
			break;
		if ((ret = gen_jmp_epilogue(ctx, insn, &len)) < 0)
			return ret;
		break;
	default:
		pr_err("bpf-jit: can't handle instruction code 0x%02X\n", code);
		return -ENOTSUPP;
	}

	if (BPF_CLASS(code) == BPF_ALU) {
		/*
		 * Also 64-bit swaps are of type BPF_ALU.  Therefore,
		 * gen_swap() itself handles calling zext() based on
		 * its input "size" argument.
		 */
		if (BPF_OP(code) != BPF_END)
			len += zext(buf+len, dst);
	}

	jit_buffer_update(&ctx->jit, len);

	return ret;
}

static int handle_body(struct jit_context *ctx)
{
	int ret;
	bool populate_bpf2insn = false;
	const struct bpf_prog *prog = ctx->prog;

	if ((ret = jit_buffer_check(&ctx->jit)))
	    return ret;

	/*
	 * Record the mapping for the instructions during the dry-run.
	 * Doing it this way allows us to have the mapping ready for
	 * the jump instructions during the real compilation phase.
	 */
	if (!emit)
		populate_bpf2insn = true;

	for (u32 i = 0; i < prog->len; i++) {
		/* During the dry-run, jit.len grows gradually per BPF insn. */
		if (populate_bpf2insn)
			ctx->bpf2insn[i] = ctx->jit.len;

		if ((ret = handle_insn(ctx, i)) < 0)
			return ret;

		/* "ret" holds 1 if two (64-bit) chunks were consumed. */
		i += ret;
	}

	/* If bpf2insn had to be populated, then it is done at this point. */
	if (populate_bpf2insn)
		ctx->bpf2insn_valid = true;

	return 0;
}

/*
 * Initialize the memory with "unimp_s" which is the mnemonic for
 * "unimplemented" instruction and always raises an exception.
 *
 * The instruction is 2 bytes. If "size" is odd, there is not much
 * that can be done about the last byte in "area". Because, the
 * CPU always fetches instructions in two bytes. Therefore, the
 * byte beyond the last one is going to accompany it during a
 * possible fetch. In the most likely case of a little endian
 * system, that beyond-byte will become the major opcode and
 * we have no control over its initialisation.
 */
static void fill_ill_insn(void *area, unsigned int size)
{
	const u16 unimp_s = 0x79e0;

	if (size & 1) {
		*((u8 *) area + (size - 1)) = 0xff;
		size -= 1;
	}

	memset16(area, unimp_s, size >> 1);
}

/* Piece of memory that can be allocated at the begining of jit_prepare(). */
static int jit_prepare_early_mem_alloc(struct jit_context *ctx)
{
	ctx->bpf2insn = kcalloc(ctx->prog->len, sizeof(ctx->jit.len),
				GFP_KERNEL);

	if (!ctx->bpf2insn) {
		pr_err("bpf-jit: could not allocate memory for "
		       "mapping of the instructions.\n");
		return -ENOMEM;
	}

	return 0;
}

/*
 * Memory allocations that rely on parameters known at the
 * end of jit_prepare().
 */
static int jit_prepare_final_mem_alloc(struct jit_context *ctx)
{
	ctx->bpf_header = bpf_jit_binary_alloc(ctx->jit.len, &ctx->jit.buf,
					       INSN_len_normal, fill_ill_insn);

	if (!ctx->bpf_header) {
		pr_err("bpf-jit: could not allocate memory for translation.\n");
		return -ENOMEM;
	}

	if (ctx->need_extra_pass) {
		ctx->jit_data = kzalloc(sizeof(struct arc_jit_data),
					GFP_KERNEL);
		if (!ctx->jit_data) {
			pr_err("bpf-jit: could not allocate memory for "
			       "the next pass's data.\n");
			return -ENOMEM;
		}
	}

	return 0;
}

/*
 * The first phase of the translation without actually emitting any
 * instruction. It helps in getting a forecast on some aspects, such
 * as the length of the whole program or where the epilogue starts.
 *
 * Whenever the necessary parameters are known, memories are allocated.
 */
static int jit_prepare(struct jit_context *ctx)
{
	int ret;

	/* Dry run. */
	emit = false;

	if ((ret = jit_prepare_early_mem_alloc(ctx)))
		return ret;

	/* Get the length of prologue section after some register analysis. */
	analyze_reg_usage(ctx);
	if ((ret = handle_prologue(ctx)))
		return ret;

	if ((ret = handle_body(ctx)))
		return ret;

	/* Record at which offset epilogue begins. */
	ctx->epilogue_offset = ctx->jit.len;

	/* Add the epilogue's length as well. */
	if ((ret = handle_epilogue(ctx)))
		return ret;

	if ((ret = jit_prepare_final_mem_alloc(ctx)))
		return ret;

	return 0;
}

/*
 * All the "handle_*()" functions have been called before by the
 * "jit_prepare()". If there was an error, we would know by now.
 * Therefore, no extra error checking at this point, other than
 * a sanity check at the end that expects the calculated length
 * (jit.len) to be equal to the length of generated instructions
 * (jit.index).
 */
static int jit_compile(struct jit_context *ctx)
{
	emit = true;

	(void) handle_prologue(ctx);

	(void) handle_body(ctx);

	(void) handle_epilogue(ctx);

	if (ctx->jit.index != ctx->jit.len) {
		pr_err("bpf-jit: divergence between the phases; "
		       "%u vs. %u (bytes).\n",
		       ctx->jit.len, ctx->jit.index);
		return -EFAULT;
	}

	return 0;
}

/*
 * Calling this function implies a successful JIT. A successful
 * translation is signaled by setting the right parameters:
 *
 * prog->jited=1, prog->jited_len=..., prog->bpf_func=...
 */
static void jit_finalize(struct jit_context *ctx)
{
	struct bpf_prog *prog = ctx->prog;

	ctx->success    = true;
	prog->bpf_func  = (void *) ctx->jit.buf;
	prog->jited_len = ctx->jit.len;
	prog->jited     = 1;

	/* We're going to need this information for the "do_extra_pass()". */
	if (ctx->need_extra_pass) {
		ctx->jit_data->bpf_header = ctx->bpf_header;
		ctx->jit_data->bpf2insn   = ctx->bpf2insn;
		prog->aux->jit_data       = (void *) ctx->jit_data;
	} else {
		/*
		 * If things seem finalised, then mark the JITed memory
		 * as R-X and flush it.
		 */
		bpf_jit_binary_lock_ro(ctx->bpf_header);
		flush_icache_range((unsigned long) ctx->bpf_header,
				   (unsigned long) ctx->jit.buf + ctx->jit.len);
		prog->aux->jit_data = NULL;
	}

	jit_ctx_cleanup(ctx);

	if (bpf_jit_enable > 1)
		bpf_jit_dump(ctx->prog->len, ctx->jit.len, 2, ctx->jit.buf);

	/* TODO: Debugging */
	dump_bytes(ctx->jit.buf, ctx->jit.len, true);
}

/* Reuse the previous pass's data. */
static int jit_resume_context(struct jit_context *ctx)
{
	struct arc_jit_data *jdata =
		(struct arc_jit_data *) ctx->prog->aux->jit_data;

	if (!jdata) {
		pr_err("bpf-jit: no jit data for the extra pass.");
		return -EINVAL;
	}

	ctx->jit.buf        = (u8 *) ctx->prog->bpf_func;
	ctx->jit.len        = ctx->prog->jited_len;
	ctx->bpf_header     = jdata->bpf_header;
	ctx->bpf2insn       = (u32 *) jdata->bpf2insn;
	ctx->bpf2insn_valid = ctx->bpf2insn ? true : false;
	ctx->jit_data       = jdata;

	return 0;
}

/*
 * Patch in the new addresses. The instructions of interest are:
 *
 * - call
 * - ld r64, imm64
 *
 * For "call"s, it resolves the addresses one more time through the
 * gen_call().
 *
 * For 64-bit immediate loads, it just retranslates them, because the BPF
 * core in kernel might have changed the value since the normal pass.
 */
static int jit_patch_relocations(struct jit_context *ctx)
{
	const u8 bpf_opc_call = BPF_JMP | BPF_CALL;
	const u8 bpf_opc_ldi64 = BPF_LD | BPF_DW | BPF_IMM;
	const struct bpf_prog *prog = ctx->prog;
	int ret;

	emit = true;
	for (u32 i = 0; i < prog->len; i++) {
		const struct bpf_insn *insn = &prog->insnsi[i];
		u8 dummy;
		/*
		 * Adjust "ctx.jit.index", so "gen_*()" functions below
		 * can use it for their output addresses.
		 */
		ctx->jit.index = ctx->bpf2insn[i];

		if (insn->code == bpf_opc_call) {
			if ((ret = gen_call(ctx, insn, &dummy)) < 0)
				return ret;
		} else if (insn->code == bpf_opc_ldi64) {
			if ((ret = gen_ld_imm64(ctx, insn, &dummy)) < 0)
				return ret;
			/* Skip the next instruction. */
			++i;
		}
	}
	return 0;
}

/*
 * A normal pass that involves a "dry-run" phase, jit_prepare(),
 * to get the necessary data for the real compilation phase,
 * jit_compile().
 */
struct bpf_prog *do_normal_pass(struct bpf_prog *prog)
{
	struct jit_context ctx;

	/* Bail out if JIT is disabled. */
	if (!prog->jit_requested)
		return prog;

	if (jit_ctx_init(&ctx, prog)) {
		jit_ctx_cleanup(&ctx);
		return prog;
	}

	/* Get the lenghts and allocate buffer. */
	if (jit_prepare(&ctx)) {
		jit_ctx_cleanup(&ctx);
		return prog;
	}

	if (jit_compile(&ctx)) {
		jit_ctx_cleanup(&ctx);
		return prog;
	}

	jit_finalize(&ctx);

	return ctx.prog;
}

/*
 * If there are multi-function BPF programs that call each other,
 * their translated addresses are not known all at once. Therefore,
 * an extra pass is needed to consult the bpf_jit_get_func_addr()
 * again to get the newly translated addresses in order to resolve
 * the "call"s.
 */
struct bpf_prog *do_extra_pass(struct bpf_prog *prog)
{
	struct jit_context ctx;

	if (jit_ctx_init(&ctx, prog)) {
		jit_ctx_cleanup(&ctx);
		return prog;
	}

	if (jit_resume_context(&ctx)) {
		jit_ctx_cleanup(&ctx);
		return prog;
	}

	if (jit_patch_relocations(&ctx)) {
		jit_ctx_cleanup(&ctx);
		return prog;
	}

	jit_finalize(&ctx);

	return ctx.prog;
}

/*
 * This function may be invoked twice for the same stream of BPF
 * instructions. The "extra pass" happens, when there are "call"s
 * involved that their addresses are not known during the first
 * invocation.
 */
struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
{
	/* TODO: Debugging */
	dump_bytes((u8 *) prog->insns, 8*prog->len, false);

	/* Was this program already translated? */
	if (!prog->jited)
		return do_normal_pass(prog);
	else
		return do_extra_pass(prog);

	return prog;
}
