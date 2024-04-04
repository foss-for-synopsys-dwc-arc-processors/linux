/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 */

#ifndef _ASM_ARC_SYSCALL_H
#define _ASM_ARC_SYSCALL_H  1

#include <uapi/linux/audit.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <asm/unistd.h>
#include <asm/ptrace.h>		/* in_syscall() */

extern void *sys_call_table[];

static inline long
syscall_get_nr(struct task_struct *task, struct pt_regs *regs)
{
	if (user_mode(regs) && in_syscall(regs))
		return regs->r8;
	else
		return -1;
}

static inline void
syscall_rollback(struct task_struct *task, struct pt_regs *regs)
{
	regs->r0 = regs->orig_r0;
}

static inline long
syscall_get_error(struct task_struct *task, struct pt_regs *regs)
{
	/* 0 if syscall succeeded, otherwise -Errorcode */
	return IS_ERR_VALUE(regs->r0) ? regs->r0 : 0;
}

static inline long
syscall_get_return_value(struct task_struct *task, struct pt_regs *regs)
{
	return regs->r0;
}

static inline void
syscall_set_return_value(struct task_struct *task, struct pt_regs *regs,
			 int error, long val)
{
	regs->r0 = (long) error ?: val;
}

/*
 * @i:      argument index [0,5]
 * @n:      number of arguments; n+i must be [1,6].
 */
static inline void
syscall_get_arguments(struct task_struct *task, struct pt_regs *regs,
		      unsigned long *args)
{
	unsigned long *inside_ptregs = &(regs->r0);
	unsigned int n = 6;
	unsigned int i = 0;

	while (n--) {
		args[i++] = (*inside_ptregs);
		inside_ptregs--;
	}
}

static inline int
syscall_get_arch(struct task_struct *task)
{
	int arch;

#if defined(CONFIG_ISA_ARCOMPACT)
	arch = EM_ARCOMPACT;
#elif defined(CONFIG_ISA_ARCV2)
	arch = EM_ARCV2;
#elif defined(CONFIG_ISA_ARCV3)

#if defined(CONFIG_64BIT)
	arch = EM_ARCV3 | __AUDIT_ARCH_64BIT;
#else
	arch = EM_ARCV3_32;
#endif /* CONFIG_64BIT */

#else
#error "Unknown CONFIG_ISA"
#endif /* CONFIG_ISA_* */

#if defined(__LITTLE_ENDIAN__)
	arch |= __AUDIT_ARCH_LE;
#endif /* __LITTLE_ENDIAN__ */

	return arch;
}

#endif
