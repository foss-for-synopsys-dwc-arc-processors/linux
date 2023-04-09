/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Linux cluster performance counters support for ARCv3.
 *
 * Copyright (C) 2023 Synopsys, Inc. (www.synopsys.com)
 */

#ifndef __ASM_PERF_CLUSTER_EVENT_H
#define __ASM_PERF_CLUSTER_EVENT_H

#ifndef BIT
#define BIT(x) (1 << (x))
#endif

#define SCM_AUX_CPCT_BUILD          0xC00
#define SCM_AUX_CPCT_CC_NUM         0xC03
#define SCM_AUX_CPCT_CC_NAME0       0xC04
#define SCM_AUX_CPCT_CC_NAME1       0xC05
#define SCM_AUX_CPCT_CC_NAME2       0xC06
#define SCM_AUX_CPCT_CC_NAME3       0xC07
#define SCM_AUX_CPCT_CONTROL        0xC08
#define SCM_AUX_CPCT_INT_CTRL       0xC09
#define SCM_AUX_CPCT_INT_ACT        0xC0A
// next registers are one per counter:
#define SCM_AUX_CPCT_N_CONFIG       0xD00
#define SCM_AUX_CPCT_COUNTL         0xD02
#define SCM_AUX_CPCT_COUNTH         0xD03
#define SCM_AUX_CPCT_N_SNAPL        0xD04
#define SCM_AUX_CPCT_N_SNAPH        0xD05
#define SCM_AUX_CPCT_INT_CNTL       0xD06
#define SCM_AUX_CPCT_INT_CNTH       0xD07

#define ARC_CLUSTER_PERF_MAX_COUNTERS   32

struct cpct_build {
#ifdef CONFIG_CPU_BIG_ENDIAN
	u32 res2:8, num_ctrs:8, res1:4, i:2, cs:2, ver:8;
#else
	u32 ver:8, cs:2, i:2, res1:4, num_ctrs:8, res2:8;
#endif
};

struct cpct_cc_num {
#ifdef CONFIG_CPU_BIG_ENDIAN
	u32 res:17, cc_num:15;
#else
	u32 cc_num:15, res:17;
#endif
};

#define CPCT_NAME_SZ    (16+1) // +1 zero
#pragma pack(push, 1)
union cpct_cc_name {
	s8 cc[CPCT_NAME_SZ];
	u32 uu[4];
};
#pragma pack(pop)

struct cpct_control {
#ifdef CONFIG_CPU_BIG_ENDIAN
	u32 res2:14, sn:1, cc:1, res0:15, en:1;
#else
	u32 en:1, res0:15, cc:1, sn:1, res2:14;
#endif
};

struct cpct_int_cntrl {
	u32 int_ctrl;
};

struct cpct_int_act {
	u32 int_act;
};

struct cpct_n_config {
	union {
		struct {
#ifdef CONFIG_CPU_BIG_ENDIAN
			u32 lce:1, len:1, res:12, lsn:1, lcc:1, cc_num:16;
#else
			u32 cc_num:16, lcc:1, lsn:1, res:12, len:1, lce:1;
#endif
		};
		u32 val;
	};
};

struct cpct_count {
	u32 count;
};

struct cpct_snap {
	u32 snap;
};

struct cpct_int_count {
	u32 int_cnt;
};

// Events map
#define	MAX_CONDITIONS_NUMBER	0x800	// We can't get the maximum event number from any build in registers, thats why
										// we need to scan all possible walues up to MAX_CONDITIONS_NUMBER

struct cpct_conditions_entry {
	u32 cc_number;
	union cpct_cc_name name;
};

#endif
