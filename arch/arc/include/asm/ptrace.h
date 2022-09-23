/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 *
 * Amit Bhor, Sameer Dhavale: Codito Technologies 2004
 */
#ifndef __ASM_ARC_PTRACE_H
#define __ASM_ARC_PTRACE_H

#include <uapi/asm/ptrace.h>

#ifndef __ASSEMBLY__

typedef union {
	struct {
#ifdef CONFIG_CPU_BIG_ENDIAN
		unsigned long state:8, vec:8, cause:8, param:8;
#else
		unsigned long param:8, cause:8, vec:8, state:8;
#endif
	};
	unsigned long full;
} ecr_reg;

/* THE pt_regs: Defines how regs are saved during entry into kernel */

#ifdef CONFIG_ISA_ARCOMPACT
struct pt_regs {

	/* Real registers */
	unsigned long bta;	/* bta_l1, bta_l2, erbta */

	unsigned long lp_start, lp_end, lp_count;

	unsigned long status32;	/* status32_l1, status32_l2, erstatus */
	unsigned long ret;	/* ilink1, ilink2 or eret */
	unsigned long blink;
	unsigned long fp;
	unsigned long gp;	/* r26 */

	unsigned long r12, r11, r10, r9, r8, r7, r6, r5, r4, r3, r2, r1, r0;

	unsigned long sp;	/* User/Kernel depending on where we came from */
	unsigned long orig_r0;

	/*
	 * To distinguish bet excp, syscall, irq
	 * For traps and exceptions, Exception Cause Register.
	 * 	ECR: <00> <VV> <CC> <PP>
	 * 	Last word used by Linux for extra state mgmt (syscall-restart)
	 * For interrupts, use artificial ECR values to note current prio-level
	 */
	ecr_reg ecr;
};

struct callee_regs {
	unsigned long r25, r24, r23, r22, r21, r20, r19, r18, r17, r16, r15, r14, r13;
};

#elif defined(CONFIG_ISA_ARCV2)

struct pt_regs {

	unsigned long orig_r0;

	ecr_reg ecr;		/* Exception Cause Reg */

	unsigned long bta;	/* erbta */

	unsigned long fp;
	unsigned long r30;
	unsigned long r12;
	unsigned long gp;	/* r26 */

#ifdef CONFIG_ARC_HAS_ACCL_REGS
	unsigned long r58, r59;	/* ACCL/ACCH used by FPU / DSP MPY */
#endif
#ifdef CONFIG_ARC_DSP_SAVE_RESTORE_REGS
	unsigned long DSP_CTRL;
#endif

	unsigned long sp;	/* user/kernel sp depending on entry  */

	/*------- Below list auto saved by h/w -----------*/
	unsigned long r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11;

	unsigned long blink;

#ifndef CONFIG_ARC_LACKS_ZOL
	unsigned long lp_end, lp_start, lp_count;
#endif
	unsigned long ei, ldi, jli;

	unsigned long ret;
	unsigned long status32;
};

struct callee_regs {
	unsigned long r25, r24, r23, r22, r21, r20, r19, r18, r17, r16, r15, r14, r13;
};

#else /* CONFIG_ISA_ARCV3 */

struct pt_regs {

	unsigned long orig_r0;
#ifdef CONFIG_ARC_HAS_ACCL_REGS
	unsigned long r58;
#ifndef CONFIG_ARC_CPU_HS6X
	unsigned long r59;
#endif
#endif
	ecr_reg ecr;
	unsigned long bta;
	unsigned long fp;
	unsigned long gp;	/* r30 */
	unsigned long sp;

	/*------- Below list auto saved by h/w -----------*/
	unsigned long r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13;
	unsigned long blink;

	unsigned long ret;
	unsigned long status32;
};

/* ARCv3 callee regs start from r14; gp is r30 not r26 */
struct callee_regs {
	unsigned long r14, r15, r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r26;
};

#endif

#define instruction_pointer(regs)	((regs)->ret)
#define profile_pc(regs)		instruction_pointer(regs)

/* return 1 if user mode or 0 if kernel mode */
#define user_mode(regs) (regs->status32 & STATUS_U_MASK)

#define user_stack_pointer(regs)\
({  unsigned int sp;		\
	if (user_mode(regs))	\
		sp = (regs)->sp;\
	else			\
		sp = -1;	\
	sp;			\
})

/* return 1 if PC in delay slot */
#define delay_mode(regs) ((regs->status32 & STATUS_DE_MASK) == STATUS_DE_MASK)

#define in_syscall(regs)    ((regs->ecr.vec == ECR_V_TRAP) && !regs->ecr.param)
#define in_brkpt_trap(regs) ((regs->ecr.vec == ECR_V_TRAP) && regs->ecr.param)

#define STATE_SCALL_RESTARTED	0x01

#define syscall_wont_restart(regs) (regs->ecr.state |= STATE_SCALL_RESTARTED)
#define syscall_restartable(regs) !(regs->ecr.state &  STATE_SCALL_RESTARTED)

#define current_pt_regs()					\
({								\
	/* open-coded current_thread_info() */			\
	register unsigned long sp asm ("sp");			\
	unsigned long pg_start = (sp & ~(THREAD_SIZE - 1));	\
	(struct pt_regs *)(pg_start + THREAD_SIZE) - 1;	\
})

static inline long regs_return_value(struct pt_regs *regs)
{
	return (long)regs->r0;
}

static inline void instruction_pointer_set(struct pt_regs *regs,
					   unsigned long val)
{
	instruction_pointer(regs) = val;
}
#endif /* !__ASSEMBLY__ */

#endif /* __ASM_PTRACE_H */
