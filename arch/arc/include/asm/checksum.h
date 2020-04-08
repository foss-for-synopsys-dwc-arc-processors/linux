/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 *
 * Joern Rennecke  <joern.rennecke@embecosm.com>: Jan 2012
 *  -Insn Scheduling improvements to csum core routines.
 *      = csum_fold( ) largely derived from ARM version.
 *      = ip_fast_cum( ) to have module scheduling
 *  -gcc 4.4.x broke networking. Alias analysis needed to be primed.
 *   worked around by adding memory clobber to ip_fast_csum( )
 *
 * vineetg: May 2010
 *  -Rewrote ip_fast_cscum( ) and csum_fold( ) with fast inline asm
 */

#ifndef _ASM_ARC_CHECKSUM_H
#define _ASM_ARC_CHECKSUM_H

/*
 *	Fold a partial checksum
 *
 *  The 2 swords comprising the 32bit sum are added, any carry to 16th bit
 *  added back and final sword result inverted.
 */
static inline __sum16 csum_fold(__wsum s)
{
	unsigned int r = s << 16 | s >> 16;	/* ror */
	s = ~s;
	s -= r;
	return s >> 16;
}
#define csum_fold csum_fold

#ifndef CONFIG_ARC_LACKS_ZOL
/*
 * This is a version of ip_compute_csum() optimized for IP headers,
 * which always checksum on 4 octet boundaries.
 * @ihl comes from IP hdr and is number of 4-byte words
 */
static inline __sum16
ip_fast_csum(const void *iph, unsigned int ihl)
{
	const void *ptr = iph;
	unsigned int tmp, tmp2, sum;

	__asm__(
	"	ld.ab  %0, [%3, 4]		\n"
	"	ld.ab  %2, [%3, 4]		\n"
	"	sub    %1, %4, 2		\n"
	"	lsr.f  lp_count, %1, 1		\n"
	"	bcc    0f			\n"
	"	add.f  %0, %0, %2		\n"
	"	ld.ab  %2, [%3, 4]		\n"
	"0:	lp     1f			\n"
	"	ld.ab  %1, [%3, 4]		\n"
	"	adc.f  %0, %0, %2		\n"
	"	ld.ab  %2, [%3, 4]		\n"
	"	adc.f  %0, %0, %1		\n"
	"1:	adc.f  %0, %0, %2		\n"
	"	add.cs %0,%0,1			\n"
	: "=&r"(sum), "=r"(tmp), "=&r"(tmp2), "+&r" (ptr)
	: "r"(ihl)
	: "cc", "lp_count", "memory");

	return csum_fold(sum);
}

#else

/*
 * This is a version of ip_compute_csum() optimized for IP headers,
 * which always checksum on 4 octet boundaries.
 * @ihl comes from IP hdr and is number of 4-byte words
 *  - No loop enterted for canonical 5 words
 *  - optimized for ARCv2
 *    - LDL double load for fetching first 16 bytes
 *    - DBNZ instruction for looping (ZOL not used)
 */
static inline __sum16
ip_fast_csum(const void *iph, unsigned int ihl)
{
	unsigned int tmp, sum;
	u64 dw1, dw2;

	__asm__(
#ifdef CONFIG_ARC_HAS_LL64
	"	ldd.ab %0, [%4, 8]	\n"
	"	ldd.ab %1, [%4, 8]	\n"
#else
	"	ld.ab %L0, [%4, 4]	\n"
	"	ld.ab %H0, [%4, 4]	\n"
	"	ld.ab %L1, [%4, 4]	\n"
	"	ld.ab %H1, [%4, 4]	\n"
#endif
	"	sub    %5, %5,  4	\n"
	"	add.f  %3, %L0, %H0	\n"
	"	adc.f  %3, %3,  %L1	\n"
	"	adc.f  %3, %3,  %H1	\n"
	"1:	ld.ab  %2, [%4, 4]	\n"
	"	adc.f  %3, %3,  %2	\n"
	"	DBNZR  %5, 1b		\n"
	"	add.cs %3, %3,  1	\n"

	: "=&r" (dw1), "=&r" (dw2), "=&r" (tmp), "=&r" (sum),
	  "+&r" (iph), "+&r"(ihl)
	:
	: "cc", "memory");

	return csum_fold(sum);
}

#endif

#define ip_fast_csum ip_fast_csum

/*
 * TCP pseudo Header is 12 bytes:
 * SA [4], DA [4], zeroes [1], Proto[1], TCP Seg(hdr+data) Len [2]
 */
static inline __wsum
csum_tcpudp_nofold(__be32 saddr, __be32 daddr, __u32 len,
		   __u8 proto, __wsum sum)
{
	__asm__ __volatile__(
	"	add.f %0, %0, %1	\n"
	"	adc.f %0, %0, %2	\n"
	"	adc.f %0, %0, %3	\n"
	"	adc.f %0, %0, %4	\n"
	"	adc   %0, %0, 0		\n"
	: "+&r"(sum)
	: "r"(saddr), "r"(daddr),
#ifdef CONFIG_CPU_BIG_ENDIAN
	  "r"(len),
#else
	  "r"(len << 8),
#endif
	  "r"(htons(proto))
	: "cc");

	return sum;
}
#define csum_tcpudp_nofold csum_tcpudp_nofold

#include <asm-generic/checksum.h>

#endif /* _ASM_ARC_CHECKSUM_H */
