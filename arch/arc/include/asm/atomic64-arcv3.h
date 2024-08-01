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

#define arch_atomic64_read(v)	READ_ONCE((v)->counter)
#define arch_atomic64_set(v, i)	WRITE_ONCE(((v)->counter), (i))

#ifdef CONFIG_ARC_HAS_LLSC

#ifdef CONFIG_ARC_LLSC_BACKOFF

#define SCOND_FAIL_RETRY_VAR_DEF						\
	unsigned int delay = 0x800, tmp;					\

#define SCOND_FAIL_RETRY_ASM							\
	"	bz	4f			\n"				\
	"   ; --- scond fail delay ---		\n"				\
	"	brlo	%[delay], 0x800, 3f	\n"				\
	"	lr	%[delay], [0x4]		\n"	/* read core id */	\
	"	lsr	%[delay], %[delay] ,8	\n"				\
	"	and	%[delay], %[delay], 0xFF \n"				\
	"	add	%[delay], %[delay], 1	\n"				\
	"3:	mov	%[tmp], %[delay]	\n"	/* tmp = delay */	\
	"2:	brne.d	%[tmp], 0, 2b		\n"	/* while (tmp != 0) */	\
	"	sub	%[tmp], %[tmp], 1	\n"	/* tmp-- */		\
	"	asl	%[delay], %[delay]	\n"	/* delay *= 2 */	\
	"	b	1b			\n"	/* start over */	\
	"4: ; --- success ---			\n"				\

#define SCOND_FAIL_RETRY_VARS							\
	  ,[delay] "+&r" (delay),[tmp] "=&r"	(tmp)				\

#else	/* !CONFIG_ARC_LLSC_BACKOFF */

#define SCOND_FAIL_RETRY_VAR_DEF

#define SCOND_FAIL_RETRY_ASM							\
	"	bnz     1b			\n"				\

#define SCOND_FAIL_RETRY_VARS

#endif	/* !CONFIG_ARC_LLSC_BACKOFF */

#define ATOMIC64_OP(op, op1)						\
static inline void arch_atomic64_##op(s64 a, atomic64_t *v)			\
{									\
	s64 val;							\
	SCOND_FAIL_RETRY_VAR_DEF					\
									\
	__asm__ __volatile__(						\
	"1:				\n"				\
	"	llockl   %0, %1		\n"				\
	"	" #op1 " %0, %0, %2	\n"				\
	"	scondl   %0, %1		\n"				\
	SCOND_FAIL_RETRY_ASM						\
	: "=&r"(val), "+ATOMC"(v->counter)				\
	SCOND_FAIL_RETRY_VARS						\
	: "r"(a)							\
	: "cc", "memory");						\
}									\

#define ATOMIC64_OP_RETURN(op, op1)		        	\
static inline s64 arch_atomic64_##op##_return_relaxed(s64 a, atomic64_t *v)	\
{									\
	s64 val;							\
	SCOND_FAIL_RETRY_VAR_DEF					\
									\
	__asm__ __volatile__(						\
	"1:				\n"				\
	"	llockl   %0, %1		\n"				\
	"	" #op1 " %0, %0, %2	\n"				\
	"	scondl   %0, %1		\n"				\
	SCOND_FAIL_RETRY_ASM						\
	: "=&r"(val), "+ATOMC"(v->counter)				\
	SCOND_FAIL_RETRY_VARS						\
	: "r"(a)							\
	: "cc");	/* memory clobber comes from smp_mb() */	\
									\
	return val;							\
}

#define ATOMIC64_FETCH_OP(op, op1)		        		\
static inline s64 arch_atomic64_fetch_##op##_relaxed(s64 a, atomic64_t *v)	\
{									\
	s64 val, orig;							\
	SCOND_FAIL_RETRY_VAR_DEF					\
									\
	__asm__ __volatile__(						\
	"1:				\n"				\
	"	llockl   %0, %2		\n"				\
	"	" #op1 " %1, %0, %3	\n"				\
	"	scondl   %1, %2		\n"				\
	SCOND_FAIL_RETRY_ASM						\
	: "=&r"(orig), "=&r"(val), "+ATOMC"(v->counter)			\
	SCOND_FAIL_RETRY_VARS						\
	: "r"(a)							\
	: "cc");	/* memory clobber comes from smp_mb() */	\
									\
	return orig;							\
}

#ifdef CONFIG_ARC_HAS_ATLD
#define ATOMIC64_FETCH_ATLD_OP(op, asm_op)				\
static inline s64							\
	arch_atomic64_fetch_atldl_##op##_relaxed(s64 i, atomic64_t *v)	\
{									\
	s64 orig = i;							\
									\
	__asm__ __volatile__(						\
	"	atldl."#asm_op" %0, %1 \n"				\
	: "+r"(orig), "+ATOMC" (v->counter)				\
	: 								\
	: "memory");							\
									\
	return orig;							\
}
#endif

#define ATOMIC64_OPS(op, op1)					\
	ATOMIC64_OP(op, op1)					\
	ATOMIC64_OP_RETURN(op, op1)

ATOMIC64_OPS(add, addl)
ATOMIC64_OPS(sub, subl)

#define arch_atomic64_fetch_sub_relaxed		arch_atomic64_fetch_sub_relaxed
#define arch_atomic64_add_return_relaxed	arch_atomic64_add_return_relaxed
#define arch_atomic64_sub_return_relaxed	arch_atomic64_sub_return_relaxed

#undef ATOMIC64_OPS
#define ATOMIC64_OPS(op, op1)					\
	ATOMIC64_OP(op, op1)

ATOMIC64_OPS(and, andl)
ATOMIC64_OPS(andnot, bicl)
ATOMIC64_OPS(or, orl)
ATOMIC64_OPS(xor, xorl)

#define arch_atomic64_andnot			arch_atomic64_andnot
#define arch_atomic64_fetch_andnot_relaxed	arch_atomic64_fetch_andnot_relaxed

#ifdef CONFIG_ARC_HAS_ATLD

#define arch_atomic64_fetch_add_relaxed	arch_atomic64_fetch_atldl_add_relaxed
#define arch_atomic64_fetch_and_relaxed	arch_atomic64_fetch_atldl_and_relaxed
#define arch_atomic64_fetch_or_relaxed		arch_atomic64_fetch_atldl_or_relaxed
#define arch_atomic64_fetch_xor_relaxed	arch_atomic64_fetch_atldl_xor_relaxed

ATOMIC64_FETCH_ATLD_OP(add, add)
ATOMIC64_FETCH_ATLD_OP(and, and)
ATOMIC64_FETCH_ATLD_OP(xor, xor)
ATOMIC64_FETCH_ATLD_OP(or, or)

ATOMIC64_FETCH_OP(sub, subl)
ATOMIC64_FETCH_OP(andnot, bicl)
#else

#define arch_atomic64_fetch_add_relaxed	arch_atomic64_fetch_add_relaxed
#define arch_atomic64_fetch_and_relaxed	arch_atomic64_fetch_and_relaxed
#define arch_atomic64_fetch_or_relaxed	arch_atomic64_fetch_or_relaxed
#define arch_atomic64_fetch_xor_relaxed	arch_atomic64_fetch_xor_relaxed

ATOMIC64_FETCH_OP(add, addl)
ATOMIC64_FETCH_OP(and, andl)
ATOMIC64_FETCH_OP(xor, xorl)
ATOMIC64_FETCH_OP(or, orl)

ATOMIC64_FETCH_OP(sub, subl)
ATOMIC64_FETCH_OP(andnot, bicl)
#endif

#undef ATOMIC64_OPS
#undef ATOMIC64_FETCH_OP
#undef ATOMIC64_FETCH_ATLD_OP
#undef ATOMIC64_OP_RETURN
#undef ATOMIC64_OP
#undef SCOND_FAIL_RETRY_VAR_DEF
#undef SCOND_FAIL_RETRY_ASM
#undef SCOND_FAIL_RETRY_VARS

static inline s64
arch_atomic64_cmpxchg(atomic64_t *ptr, s64 expected, s64 new)
{
	s64 prev;

	smp_mb();

	__asm__ __volatile__(
	"1:	llockl  %0, %1		\n"
	"	brnel   %0, %2, 2f	\n"
	"	scondl  %3, %1		\n"
	"	bnz     1b		\n"
	"2:				\n"
	: "=&r"(prev), "+ATOMC"(*ptr)
	: "r"(expected), "r"(new)
	: "cc");	/* memory clobber comes from smp_mb() */

	smp_mb();

	return prev;
}

static inline s64 arch_atomic64_xchg(atomic64_t *ptr, s64 new)
{
	s64 prev;

	smp_mb();

	__asm__ __volatile__(
	"1:	llockl  %0, %1		\n"
	"	scondl  %2, %1		\n"
	"	bnz     1b		\n"
	"2:				\n"
	: "=&r"(prev), "+ATOMC"(*ptr)
	: "r"(new)
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

static inline s64 arch_atomic64_dec_if_positive(atomic64_t *v)
{
	s64 val;

	smp_mb();

	__asm__ __volatile__(
	"1:	llockl  %0, %1		\n"
	"	subl    %0, %0, 1	\n"
	"	brltl    %0, 0, 2f	# if signed less-than elide store\n"
	"	scondl  %0, %1		\n"
	"	bnz     1b		\n"
	"2:				\n"
	: "=&r"(val), "+ATOMC"(v->counter)
	:
	: "cc");	/* memory clobber comes from smp_mb() */

	smp_mb();

	return val;
}
#define arch_atomic64_dec_if_positive arch_atomic64_dec_if_positive

/**
 * atomic64_fetch_add_unless - add unless the number is a given value
 * @v: pointer of type atomic64_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, if it was not @u.
 * Returns the old value of @v
 */
static inline s64 arch_atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
{
	s64 old, temp;

	smp_mb();

	__asm__ __volatile__(
	"1:	llockl  %0, %2		\n"
	"	breql.d	%0, %4, 3f	# return since v == u \n"
	"2:				\n"
	"	addl    %1, %0, %3	\n"
	"	scondl  %1, %2		\n"
	"	bnz     1b		\n"
	"3:				\n"
	: "=&r"(old), "=&r" (temp), "+ATOMC"(v->counter)
	: "r"(a), "r"(u)
	: "cc");	/* memory clobber comes from smp_mb() */

	smp_mb();

	return old;
}
#define arch_atomic64_fetch_add_unless arch_atomic64_fetch_add_unless

#endif
