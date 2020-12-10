/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2016-2017 Synopsys, Inc. (www.synopsys.com)
 */

#ifndef __SOC_ARC_AUX_H__
#define __SOC_ARC_AUX_H__

#ifdef CONFIG_ARC

#include <linux/bug.h>

#define read_aux_reg(r)		__builtin_arc_lr(r)

/* gcc builtin sr needs reg param to be long immediate */
#define write_aux_reg(r, v)	__builtin_arc_sr(v, r)

#ifdef CONFIG_ISA_ARCV3

#define read_aux_64(r)                                  \
({							\
	u64 v;						\
	__asm__ __volatile__("lrl %0, [%1]"		\
	: "=r"(v) : "r"(r));				\
	v;						\
})

#define write_aux_64(r, v)				\
({							\
	__asm__ __volatile__("srl %0, [%1]"		\
	: : "r"(v), "r"(r));				\
})

#endif

#else	/* !CONFIG_ARC */

static inline int read_aux_reg(u32 r)
{
	return 0;
}

/*
 * function helps elide unused variable warning
 * see: https://lists.infradead.org/pipermail/linux-snps-arc/2016-November/001748.html
 */
static inline void write_aux_reg(u32 r, u32 v)
{
	;
}

#endif

#define READ_BCR(reg, into)				\
{							\
	unsigned int tmp;				\
	BUILD_BUG_ON_MSG(sizeof(tmp) != sizeof(into),	\
		     "invalid usage of read_aux_reg");	\
	tmp = read_aux_reg(reg);			\
	into = *((typeof(into) *)&tmp);			\
}

#define WRITE_AUX(reg, from)				\
{							\
	unsigned int tmp;				\
	if (sizeof(tmp) == sizeof(from)) {		\
		tmp = *(unsigned int *)&(from);	\
		write_aux_reg(reg, tmp);		\
	} else  {					\
		extern void bogus_undefined(void);	\
		bogus_undefined();			\
	}						\
}

#ifdef CONFIG_ISA_ARCV3

#define WRITE_AUX64(reg, from)				\
{							\
	unsigned long long tmp;				\
	if (sizeof(tmp) == sizeof(from)) {		\
		tmp = *(unsigned long long *)&(from);	\
		write_aux_64(reg, tmp);			\
	} else  {					\
		extern void bogus_undefined(void);	\
		bogus_undefined();			\
	}						\
}

#endif

#endif
