/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_ARC_ATOMIC_LLSC_H
#define _ASM_ARC_ATOMIC_LLSC_H

#if defined(CONFIG_ISA_ARCV3)
#define ATOMIC_CONSTR	"+ATOMC"
#else
#define ATOMIC_CONSTR	"+ATO"
#endif

#define arch_atomic_set(v, i) WRITE_ONCE(((v)->counter), (i))

#define ATOMIC_OP(op, asm_op)					\
static inline void arch_atomic_##op(int i, atomic_t *v)			\
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
static inline int arch_atomic_##op##_return_relaxed(int i, atomic_t *v)	\
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

#define arch_atomic_add_return_relaxed		arch_atomic_add_return_relaxed
#define arch_atomic_sub_return_relaxed		arch_atomic_sub_return_relaxed

#define ATOMIC_FETCH_OP(op, asm_op)				\
static inline int arch_atomic_fetch_##op##_relaxed(int i, atomic_t *v)	\
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
static inline int arch_atomic_fetch_atld_##op##_relaxed(int i, atomic_t *v)	\
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

#define arch_atomic_fetch_sub_relaxed		arch_atomic_fetch_sub_relaxed
#define arch_atomic_fetch_andnot_relaxed	arch_atomic_fetch_andnot_relaxed

#define ATOMIC_OPS(op, asm_op)					\
	ATOMIC_OP(op, asm_op)					\
	ATOMIC_OP_RETURN(op, asm_op)

ATOMIC_OPS(add, add)
ATOMIC_OPS(sub, sub)

#undef ATOMIC_OPS
#define ATOMIC_OPS(op, asm_op)					\
	ATOMIC_OP(op, asm_op)

ATOMIC_OPS(and, and)
ATOMIC_OPS(andnot, bic)
ATOMIC_OPS(or, or)
ATOMIC_OPS(xor, xor)

#ifdef CONFIG_ARC_HAS_ATLD

#define arch_atomic_fetch_add_relaxed	arch_atomic_fetch_atld_add_relaxed
#define arch_atomic_fetch_and_relaxed	arch_atomic_fetch_atld_and_relaxed
#define arch_atomic_fetch_or_relaxed	arch_atomic_fetch_atld_or_relaxed
#define arch_atomic_fetch_xor_relaxed	arch_atomic_fetch_atld_xor_relaxed

	ATOMIC_FETCH_ATLD_OP(add, add)
	ATOMIC_FETCH_ATLD_OP(and, and)
	ATOMIC_FETCH_ATLD_OP(xor, xor)
	ATOMIC_FETCH_ATLD_OP(or, or)

	ATOMIC_FETCH_OP(sub, sub)
	ATOMIC_FETCH_OP(andnot, bic)
#else

#define arch_atomic_fetch_add_relaxed	arch_atomic_fetch_add_relaxed
#define arch_atomic_fetch_and_relaxed	arch_atomic_fetch_and_relaxed
#define arch_atomic_fetch_or_relaxed	arch_atomic_fetch_or_relaxed
#define arch_atomic_fetch_xor_relaxed	arch_atomic_fetch_xor_relaxed

	ATOMIC_FETCH_OP(add, add)
	ATOMIC_FETCH_OP(and, and)
	ATOMIC_FETCH_OP(xor, xor)
	ATOMIC_FETCH_OP(or, or)

	ATOMIC_FETCH_OP(sub, sub)
	ATOMIC_FETCH_OP(andnot, bic)
#endif

#define arch_atomic_andnot		arch_atomic_andnot

#undef ATOMIC_OPS
#undef ATOMIC_FETCH_OP
#undef ATOMIC_OP_RETURN
#undef ATOMIC_OP

#endif
