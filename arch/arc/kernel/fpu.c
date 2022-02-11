// SPDX-License-Identifier: GPL-2.0-only
/*
 * fpu.c - save/restore of Floating Point Unit Registers on task switch
 *
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 */

#include <linux/sched.h>
#include <asm/fpu.h>

#ifdef CONFIG_ISA_ARCOMPACT

/*
 * To save/restore FPU regs, simplest scheme would use LR/SR insns.
 * However since SR serializes the pipeline, an alternate "hack" can be used
 * which uses the FPU Exchange insn (DEXCL) to r/w FPU regs.
 *
 * Store to 64bit dpfp1 reg from a pair of core regs:
 *   dexcl1 0, r1, r0  ; where r1:r0 is the 64 bit val
 *
 * Read from dpfp1 into pair of core regs (w/o clobbering dpfp1)
 *   mov_s    r3, 0
 *   daddh11  r1, r3, r3   ; get "hi" into r1 (dpfp1 unchanged)
 *   dexcl1   r0, r1, r3   ; get "low" into r0 (dpfp1 low clobbered)
 *   dexcl1    0, r1, r0   ; restore dpfp1 to orig value
 *
 * However we can tweak the read, so that read-out of outgoing task's FPU regs
 * and write of incoming task's regs happen in one shot. So all the work is
 * done before context switch
 */

void fpu_save_restore(struct task_struct *prev, struct task_struct *next)
{
	unsigned int *saveto = &prev->thread.fpu.aux_dpfp[0].l;
	unsigned int *readfrom = &next->thread.fpu.aux_dpfp[0].l;

	const unsigned int zero = 0;

	__asm__ __volatile__(
		"daddh11  %0, %2, %2\n"
		"dexcl1   %1, %3, %4\n"
		: "=&r" (*(saveto + 1)), /* early clobber must here */
		  "=&r" (*(saveto))
		: "r" (zero), "r" (*(readfrom + 1)), "r" (*(readfrom))
	);

	__asm__ __volatile__(
		"daddh22  %0, %2, %2\n"
		"dexcl2   %1, %3, %4\n"
		: "=&r"(*(saveto + 3)),	/* early clobber must here */
		  "=&r"(*(saveto + 2))
		: "r" (zero), "r" (*(readfrom + 3)), "r" (*(readfrom + 2))
	);
}

#else

void fpu_init_task(struct pt_regs *regs)
{
	const unsigned int fwe = 0x80000000;

	/* default rounding mode */
	write_aux_reg(ARC_REG_FPU_CTRL, 0x100);

	/* Initialize to zero: setting requires FWE be set */
	write_aux_reg(ARC_REG_FPU_STATUS, fwe);
}

#ifdef CONFIG_ISA_ARCV3
static void arcv3_fp_st(struct arc_fpu *fpu)
{
	unsigned long *fpr = &fpu->f[0];

	__asm__ __volatile__(
		"fst64  f0, [r0]	\r\n"
		"fst64  f1, [r0,   8]	\r\n"
		"fst64  f2, [r0,  16]	\r\n"
		"fst64  f3, [r0,  24]	\r\n"
		"fst64  f4, [r0,  32]	\r\n"
		"fst64  f5, [r0,  40]	\r\n"
		"fst64  f6, [r0,  48]	\r\n"
		"fst64  f7, [r0,  56]	\r\n"
		"fst64  f8, [r0,  64]	\r\n"
		"fst64  f9, [r0,  72]	\r\n"
		"fst64 f10, [r0,  80]	\r\n"
		"fst64 f11, [r0,  88]	\r\n"
		"fst64 f12, [r0,  96]	\r\n"
		"fst64 f13, [r0, 104]	\r\n"
		"fst64 f14, [r0, 112] 	\r\n"
		"fst64 f15, [r0, 120]	\r\n"
		"fst64 f16, [r0, 128]	\r\n"
		"fst64 f17, [r0, 136]	\r\n"
		"fst64 f18, [r0, 144]	\r\n"
		"fst64 f19, [r0, 152]	\r\n"
		"fst64 f20, [r0, 160]	\r\n"
		"fst64 f21, [r0, 168]	\r\n"
		"fst64 f22, [r0, 176]	\r\n"
		"fst64 f23, [r0, 184] 	\r\n"
		"fst64 f24, [r0, 192]	\r\n"
		"fst64 f25, [r0, 200]	\r\n"
		"fst64 f26, [r0, 208]	\r\n"
		"fst64 f27, [r0, 216]	\r\n"
		"fst64 f28, [r0, 224]	\r\n"
		"fst64 f29, [r0, 232]	\r\n"
		"fst64 f30, [r0, 240]	\r\n"
		"fst64 f31, [r0, 248]	\r\n"
		: :"r" (fpr));

#ifndef CONFIG_64BIT
#error "32-bit FP support missing"
#endif
}

static void arcv3_fp_ld(struct arc_fpu *fpu)
{
	unsigned long *fpr = &fpu->f[0];

	__asm__ __volatile__(
		"fld64  f0, [r0]	\r\n"
		"fld64  f1, [r0,   8]	\r\n"
		"fld64  f2, [r0,  16]	\r\n"
		"fld64  f3, [r0,  24]	\r\n"
		"fld64  f4, [r0,  32]	\r\n"
		"fld64  f5, [r0,  40]	\r\n"
		"fld64  f6, [r0,  48]	\r\n"
		"fld64  f7, [r0,  56]	\r\n"
		"fld64  f8, [r0,  64]	\r\n"
		"fld64  f9, [r0,  72]	\r\n"
		"fld64 f10, [r0,  80]	\r\n"
		"fld64 f11, [r0,  88]	\r\n"
		"fld64 f12, [r0,  96]	\r\n"
		"fld64 f13, [r0, 104]	\r\n"
		"fld64 f14, [r0, 112] 	\r\n"
		"fld64 f15, [r0, 120]	\r\n"
		"fld64 f16, [r0, 128]	\r\n"
		"fld64 f17, [r0, 136]	\r\n"
		"fld64 f18, [r0, 144]	\r\n"
		"fld64 f19, [r0, 152]	\r\n"
		"fld64 f20, [r0, 160]	\r\n"
		"fld64 f21, [r0, 168]	\r\n"
		"fld64 f22, [r0, 176]	\r\n"
		"fld64 f23, [r0, 184] 	\r\n"
		"fld64 f24, [r0, 192]	\r\n"
		"fld64 f25, [r0, 200]	\r\n"
		"fld64 f26, [r0, 208]	\r\n"
		"fld64 f27, [r0, 216]	\r\n"
		"fld64 f28, [r0, 224]	\r\n"
		"fld64 f29, [r0, 232]	\r\n"
		"fld64 f30, [r0, 240]	\r\n"
		"fld64 f31, [r0, 248]	\r\n"
		: :"r" (fpr));
}

#else

#define arcv3_fp_st(fpu)
#define arcv3_fp_ld(fpu)

#endif

void fpu_save_restore(struct task_struct *prev, struct task_struct *next)
{
	struct arc_fpu *save = &prev->thread.fpu;
	struct arc_fpu *restore = &next->thread.fpu;
	const unsigned int fwe = 0x80000000;

	save->ctrl = read_aux_reg(ARC_REG_FPU_CTRL);
	save->status = read_aux_reg(ARC_REG_FPU_STATUS);

	write_aux_reg(ARC_REG_FPU_CTRL, restore->ctrl);
	write_aux_reg(ARC_REG_FPU_STATUS, (fwe | restore->status));

	arcv3_fp_st(save);
	arcv3_fp_ld(restore);
}

#endif
