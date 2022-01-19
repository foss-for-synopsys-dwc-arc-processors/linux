/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 */

#ifndef _ASM_ARC_ATOMIC_H
#define _ASM_ARC_ATOMIC_H

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/compiler.h>
#include <asm/cmpxchg.h>
#include <asm/barrier.h>
#include <asm/smp.h>

#define ATOMIC_INIT(i)	{ (i) }

#ifdef CONFIG_ARC_HAS_LLSC

#if defined(CONFIG_ISA_ARCV3)
#define ATOMIC_CONSTR	"+ATOMC"
#else
#define ATOMIC_CONSTR	"+ATO"
#endif

#define atomic_read(v)          READ_ONCE((v)->counter)
#define atomic_set(v, i)        WRITE_ONCE(((v)->counter), (i))

#define ATOMIC_OP(op, asm_op)					\
static inline void atomic_##op(int i, atomic_t *v)			\
{									\
	unsigned int val;						\
									\
	__asm__ __volatile__(						\
	"1:	llock   %[val], %[ctr]			\n"		\
	"	" #asm_op " %[val], %[val], %[i]	\n"		\
	"	scond   %[val], %[ctr]			\n"		\
	"	bnz     1b				\n"		\
	: [val]	"=&r"	(val), /* Early clobber to prevent reg reuse */	\
	  [ctr] ATOMIC_CONSTR (v->counter)				\
	: [i]	"ir"	(i)						\
	: "cc", "memory");						\
}									\

#define ATOMIC_OP_RETURN(op, asm_op)				\
static inline int atomic_##op##_return_relaxed(int i, atomic_t *v)	\
{									\
	unsigned int val;						\
									\
	__asm__ __volatile__(						\
	"1:	llock   %[val], %[ctr]			\n"		\
	"	" #asm_op " %[val], %[val], %[i]	\n"		\
	"	scond   %[val], %[ctr]			\n"		\
	"	bnz     1b				\n"		\
	: [val]	"=&r"	(val),						\
	  [ctr] ATOMIC_CONSTR (v->counter)				\
	: [i]	"ir"	(i)						\
	: "cc", "memory");						\
									\
	return val;							\
}

#define atomic_add_return_relaxed	atomic_add_return_relaxed
#define atomic_sub_return_relaxed	atomic_sub_return_relaxed

#define ATOMIC_FETCH_OP(op, asm_op)				\
static inline int atomic_fetch_##op##_relaxed(int i, atomic_t *v)	\
{									\
	unsigned int val, orig;						\
									\
	__asm__ __volatile__(						\
	"1:	llock   %[orig], %[ctr]			\n"		\
	"	" #asm_op " %[val], %[orig], %[i]	\n"		\
	"	scond   %[val], %[ctr]			\n"		\
	"	bnz     1b				\n"		\
	: [val]	"=&r"	(val),						\
	  [orig] "=&r" (orig),						\
	  [ctr] ATOMIC_CONSTR (v->counter)				\
	: [i]	"ir"	(i)						\
	: "cc", "memory");						\
									\
	return orig;							\
}

#ifdef CONFIG_ARC_HAS_ATLD
#define ATOMIC_FETCH_ATLD_OP(op, asm_op)				\
static inline int atomic_fetch_atld_##op##_relaxed(int i, atomic_t *v)	\
{									\
	unsigned int orig = i;						\
									\
	__asm__ __volatile__(						\
	"	atld."#asm_op" %[orig], %[ctr]		\n"		\
	: [orig] "+r"(orig),						\
	  [ctr] "+ATOMC" (v->counter)				\
	:								\
	: "memory");							\
									\
	return orig;							\
}
#endif

#define atomic_fetch_sub_relaxed	atomic_fetch_sub_relaxed
#define atomic_fetch_andnot_relaxed	atomic_fetch_andnot_relaxed

#define ATOMIC_OPS(op, asm_op)					\
	ATOMIC_OP(op, asm_op)					\
	ATOMIC_OP_RETURN(op, asm_op)

ATOMIC_OPS(add, add)
ATOMIC_OPS(sub, sub)

#define atomic_andnot		atomic_andnot

#undef ATOMIC_OPS
#define ATOMIC_OPS(op, asm_op)					\
	ATOMIC_OP(op, asm_op)

ATOMIC_OPS(and, and)
ATOMIC_OPS(andnot, bic)
ATOMIC_OPS(or, or)
ATOMIC_OPS(xor, xor)

#ifdef CONFIG_ARC_HAS_ATLD

#define atomic_fetch_add_relaxed	atomic_fetch_atld_add_relaxed
#define atomic_fetch_and_relaxed	atomic_fetch_atld_and_relaxed
#define atomic_fetch_or_relaxed		atomic_fetch_atld_or_relaxed
#define atomic_fetch_xor_relaxed	atomic_fetch_atld_xor_relaxed

	ATOMIC_FETCH_ATLD_OP(add, add)
	ATOMIC_FETCH_ATLD_OP(and, and)
	ATOMIC_FETCH_ATLD_OP(xor, xor)
	ATOMIC_FETCH_ATLD_OP(or, or)

	ATOMIC_FETCH_OP(sub, sub)
	ATOMIC_FETCH_OP(andnot, bic)
#else

#define atomic_fetch_add_relaxed	atomic_fetch_add_relaxed
#define atomic_fetch_and_relaxed	atomic_fetch_and_relaxed
#define atomic_fetch_or_relaxed		atomic_fetch_or_relaxed
#define atomic_fetch_xor_relaxed	atomic_fetch_xor_relaxed

	ATOMIC_FETCH_OP(add, add)
	ATOMIC_FETCH_OP(and, and)
	ATOMIC_FETCH_OP(xor, xor)
	ATOMIC_FETCH_OP(or, or)

	ATOMIC_FETCH_OP(sub, sub)
	ATOMIC_FETCH_OP(andnot, bic)
#endif

#elif defined(CONFIG_ARC_PLAT_EZNPS)

#include <asm/atomic-nps.h>

#else

#include <asm/atomic-spinlock.h>

#endif /* CONFIG_ARC_HAS_LLSC */

#undef ATOMIC_OPS
#undef ATOMIC_FETCH_OP
#undef ATOMIC_OP_RETURN
#undef ATOMIC_OP

#define atomic_cmpxchg(v, o, n)						\
({									\
	cmpxchg(&((v)->counter), (o), (n));				\
})

#ifdef cmpxchg_relaxed
#define atomic_cmpxchg_relaxed(v, o, n)					\
({									\
	cmpxchg_relaxed(&((v)->counter), (o), (n));			\
})
#endif

#define atomic_xchg(v, n)						\
({									\
	xchg(&((v)->counter), (n));					\
})

#ifdef xchg_relaxed
#define atomic_xchg_relaxed(v, n)					\
({									\
	xchg_relaxed(&((v)->counter), (n));				\
})
#endif

/*
 * 64-bit atomics
 */
#ifdef CONFIG_GENERIC_ATOMIC64
#include <asm-generic/atomic64.h>
#elif defined(CONFIG_ISA_ARCV3) && defined(CONFIG_64BIT)
#include <asm/atomic64-arcv3.h>
#else
#include <asm/atomic64-arcv2.h>
#endif

#endif	/* !__ASSEMBLY__ */

#endif
