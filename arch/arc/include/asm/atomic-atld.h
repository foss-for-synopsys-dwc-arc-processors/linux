/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_ARC_ATOMIC_ATLD_H
#define _ASM_ARC_ATOMIC_ATLD_H

static inline void arch_atomic_set(atomic_t *v, int i)
{
	ATOMIC_OPS_FLAGS_VAR_DEF

	atomic_ops_lock(flags);
	WRITE_ONCE(v->counter, i);
	atomic_ops_unlock(flags);
}

#ifndef CONFIG_ARC_HAS_LLSC
#define arch_atomic_set_release(v, i)	arch_atomic_set((v), (i))
#endif

#define ATOMIC_OP(op, asm_op)						\
static inline void arch_atomic_##op(int i, atomic_t *v)			\
{									\
	int val = i;							\
	ATOMIC_OPS_FLAGS_VAR_DEF					\
									\
	atomic_ops_lock(flags);						\
	__asm__ __volatile__(						\
	"	atld."#asm_op" %[val], %[ctr]		\n"		\
	: [val] "+r"(val),						\
	  [ctr] "+ATOMC" (v->counter)					\
	:								\
	: "memory");							\
	atomic_ops_unlock(flags);					\
									\
}

#define ATOMIC_OP_RETURN(op, asm_op)				\
static inline int arch_atomic_##op##_return_relaxed(int i, atomic_t *v)	\
{									\
	int val = i;							\
	ATOMIC_OPS_FLAGS_VAR_DEF					\
									\
	atomic_ops_lock(flags);						\
	__asm__ __volatile__(						\
	"	atld."#asm_op" %[val], %[ctr]		\n"		\
	"	"#asm_op" %[val], %[val], %[i]		\n"		\
	: [val] "+&r"(val),						\
	  [ctr] "+ATOMC" (v->counter)					\
	: [i] "ir" (i)							\
	: "memory");							\
	atomic_ops_unlock(flags);					\
									\
	return val;							\
}

#define ATOMIC_FETCH_OP(op, asm_op)					\
static inline int arch_atomic_fetch_##op##_relaxed(int i, atomic_t *v)	\
{									\
	int orig = i;							\
	ATOMIC_OPS_FLAGS_VAR_DEF					\
									\
	atomic_ops_lock(flags);						\
	__asm__ __volatile__(						\
	"	atld."#asm_op" %[orig], %[ctr]		\n"		\
	: [orig] "+r"(orig),						\
	  [ctr] "+ATOMC" (v->counter)					\
	:								\
	: "memory");							\
	atomic_ops_unlock(flags);					\
									\
	return orig;							\
}

#define ATOMIC_OPS(op, asm_op)						\
	ATOMIC_OP(op, asm_op)						\
	ATOMIC_OP_RETURN(op, asm_op)

ATOMIC_OPS(add, add)

// Special form for sub - ATOMIC_OPS(sub, sub)
static inline void arch_atomic_sub(int i, atomic_t *v)
{
	arch_atomic_add(-i, v);
}

static inline int arch_atomic_sub_return_relaxed(int i, atomic_t *v)
{
	return arch_atomic_add_return_relaxed(-i, v);
}

#define arch_atomic_add_return_relaxed		arch_atomic_add_return_relaxed
#define arch_atomic_sub_return_relaxed		arch_atomic_sub_return_relaxed

#undef ATOMIC_OPS
#define ATOMIC_OPS(op, asm_op)						\
	ATOMIC_OP(op, asm_op)

ATOMIC_OPS(and, and)
ATOMIC_OPS(or, or)
ATOMIC_OPS(xor, xor)


// Fetches
ATOMIC_FETCH_OP(add, add)
ATOMIC_FETCH_OP(and, and)
ATOMIC_FETCH_OP(xor, xor)
ATOMIC_FETCH_OP(or, or)

// Special form for sub - ATOMIC_FETCH_OP(sub, sub)
static inline int arch_atomic_fetch_sub_relaxed(int i, atomic_t *v)
{
	return arch_atomic_fetch_add_relaxed(-i, v);
}

#define arch_atomic_fetch_add_relaxed	arch_atomic_fetch_add_relaxed
#define arch_atomic_fetch_and_relaxed	arch_atomic_fetch_and_relaxed
#define arch_atomic_fetch_xor_relaxed	arch_atomic_fetch_xor_relaxed
#define arch_atomic_fetch_or_relaxed	arch_atomic_fetch_or_relaxed
#define arch_atomic_fetch_sub_relaxed	arch_atomic_fetch_sub_relaxed

#undef ATOMIC_OPS
#undef ATOMIC_FETCH_OP
#undef ATOMIC_OP_RETURN
#undef ATOMIC_OP

#endif
