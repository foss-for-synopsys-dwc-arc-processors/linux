/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_ARC_ATOMIC64_ARCV3_H
#define _ASM_ARC_ATOMIC64_ARCV3_H

#define ATOMIC64_INIT(a) { (a) }

/*
 * Given that 64-bit is native datatype, gcc is assumed to generate 64-bit data
 * returning LDL/STL instructions. Same is not guaranteed for 32-bit systems
 * despite 64-bit LDD/STD (and even if they are aligned and on same cache line)
 * since gcc could tear load/store
 */

#define atomic64_read(v)	READ_ONCE((v)->counter)
#define atomic64_set(v, i)	WRITE_ONCE(((v)->counter), (i))

#define ATOMIC64_OP(op, op1)						\
static inline void atomic64_##op(s64 a, atomic64_t *v)			\
{									\
	s64 val;							\
									\
	__asm__ __volatile__(						\
	"1:				\n"				\
	"	llockl   %0, [%1]	\n"				\
	"	" #op1 " %0, %0, %2	\n"				\
	"	scondl   %0, [%1]	\n"				\
	"	bnz      1b		\n"				\
	: "=&r"(val)							\
	: "r"(&v->counter), "ir"(a)					\
	: "cc");							\
}									\

#define ATOMIC64_OP_RETURN(op, op1)		        	\
static inline s64 atomic64_##op##_return_relaxed(s64 a, atomic64_t *v)	\
{									\
	s64 val;							\
									\
	__asm__ __volatile__(						\
	"1:				\n"				\
	"	llockl   %0, [%1]	\n"				\
	"	" #op1 " %0, %0, %2	\n"				\
	"	scondl   %0, [%1]	\n"				\
	"	bnz      1b		\n"				\
	: [val] "=&r"(val)						\
	: "r"(&v->counter), "ir"(a)					\
	: "cc");	/* memory clobber comes from smp_mb() */	\
									\
	return val;							\
}

#define ATOMIC64_FETCH_OP(op, op1)		        		\
static inline s64 atomic64_fetch_##op##_relaxed(s64 a, atomic64_t *v)	\
{									\
	s64 val, orig;							\
									\
	__asm__ __volatile__(						\
	"1:				\n"				\
	"	llockl   %0, [%2]	\n"				\
	"	" #op1 " %1, %0, %3	\n"				\
	"	scondl   %1, [%2]	\n"				\
	"	bnz      1b		\n"				\
	: "=&r"(orig), "=&r"(val)					\
	: "r"(&v->counter), "ir"(a)					\
	: "cc");	/* memory clobber comes from smp_mb() */	\
									\
	return orig;							\
}

#define ATOMIC64_OPS(op, op1)					\
	ATOMIC64_OP(op, op1)					\
	ATOMIC64_OP_RETURN(op, op1)				\
	ATOMIC64_FETCH_OP(op, op1)

ATOMIC64_OPS(add, addl)
ATOMIC64_OPS(sub, subl)

#define atomic64_fetch_add_relaxed	atomic64_fetch_add_relaxed
#define atomic64_fetch_sub_relaxed	atomic64_fetch_sub_relaxed
#define atomic64_add_return_relaxed	atomic64_add_return_relaxed
#define atomic64_sub_return_relaxed	atomic64_sub_return_relaxed

#undef ATOMIC64_OPS
#define ATOMIC64_OPS(op, op1)					\
	ATOMIC64_OP(op, op1)					\
	ATOMIC64_FETCH_OP(op, op1)

ATOMIC64_OPS(and, andl)
ATOMIC64_OPS(andnot, bicl)
ATOMIC64_OPS(or, orl)
ATOMIC64_OPS(xor, xorl)

#define atomic64_andnot			atomic64_andnot
#define atomic64_fetch_and_relaxed	atomic64_fetch_and_relaxed
#define atomic64_fetch_andnot_relaxed	atomic64_fetch_andnot_relaxed
#define atomic64_fetch_or_relaxed	atomic64_fetch_or_relaxed
#define atomic64_fetch_xor_relaxed	atomic64_fetch_xor_relaxed

#undef ATOMIC64_OPS
#undef ATOMIC64_FETCH_OP
#undef ATOMIC64_OP_RETURN
#undef ATOMIC64_OP

static inline s64
atomic64_cmpxchg(atomic64_t *ptr, s64 expected, s64 new)
{
	s64 prev;

	smp_mb();

	__asm__ __volatile__(
	"1:	llockl  %0, [%1]	\n"
	"	brnel   %0, %2, 2f	\n"
	"	scondl  %3, [%1]	\n"
	"	bnz     1b		\n"
	"2:				\n"
	: "=&r"(prev)
	: "r"(ptr), "ir"(expected), "r"(new)
	: "cc");	/* memory clobber comes from smp_mb() */

	smp_mb();

	return prev;
}

static inline s64 atomic64_xchg(atomic64_t *ptr, s64 new)
{
	s64 prev;

	smp_mb();

	__asm__ __volatile__(
	"1:	llockl  %0, [%1]	\n"
	"	scondl  %2, [%1]	\n"
	"	bnz     1b		\n"
	"2:				\n"
	: "=&r"(prev)
	: "r"(ptr), "r"(new)
	: "cc");	/* memory clobber comes from smp_mb() */

	smp_mb();

	return prev;
}

/**
 * atomic64_dec_if_positive - decrement by 1 if old value positive
 * @v: pointer of type atomic64_t
 *
 * The function returns the old value of *v minus 1, even if
 * the atomic variable, v, was not decremented.
 */

static inline s64 atomic64_dec_if_positive(atomic64_t *v)
{
	s64 val;

	smp_mb();

	__asm__ __volatile__(
	"1:	llockl  %0, [%1]	\n"
	"	subl    %0, %0, 1	\n"
	"	brltl    %0, 0, 2f	# if signed less-than elide store\n"
	"	scondl  %0, [%1]	\n"
	"	bnz     1b		\n"
	"2:				\n"
	: "=&r"(val)
	: "r"(&v->counter)
	: "cc");	/* memory clobber comes from smp_mb() */

	smp_mb();

	return val;
}
#define atomic64_dec_if_positive atomic64_dec_if_positive

/**
 * atomic64_fetch_add_unless - add unless the number is a given value
 * @v: pointer of type atomic64_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, if it was not @u.
 * Returns the old value of @v
 */
static inline s64 atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
{
	s64 old, temp;

	smp_mb();

	__asm__ __volatile__(
	"1:	llockl  %0, [%2]	\n"
	"	breql.d	%0, %4, 3f	# return since v == u \n"
	"2:				\n"
	"	addl    %1, %0, %3	\n"
	"	scondl  %1, [%2]	\n"
	"	bnz     1b		\n"
	"3:				\n"
	: "=&r"(old), "=&r" (temp)
	: "r"(&v->counter), "r"(a), "r"(u)
	: "cc");	/* memory clobber comes from smp_mb() */

	smp_mb();

	return old;
}
#define atomic64_fetch_add_unless atomic64_fetch_add_unless

#endif
