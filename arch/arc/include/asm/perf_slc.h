/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Linux SLC(L2$) performance counter support for ARCv2
 *
 * Copyright (C) 2014-2022 Synopsys, Inc. (www.synopsys.com)
 */

#ifndef __ASM_PERF_EVENT_SLC_H
#define __ASM_PERF_EVENT_SLC_H

#define     SLC_AUX_CACHE_PCT_NUMMBER       32 // maximum number of SLC performance counters
#define 	ARCV2_SLC_NUM_OF_EVENTS       	64 // number of SLC events

#define     CSM_BUILD                       0xE5
#define     SLC_BUILD                       0xCE
#define     SLC_AUX_CACHE_CONFIG            0x901

#define     SLC_AUX_PM_CMD     	            0x926
#define     SLC_AUX_PM_EVENT                0x927
#define     SLC_AUX_PM_OVF                  0x928
#define     SLC_AUX_PM_CNT0                 0x929
#define     SLC_AUX_PM_CNT1                 0x92A

#define     SLC_AUX_PM_CMD_ENABLE          	0x0
#define     SLC_AUX_PM_CMD_DISABLE         	0x1
#define     SLC_AUX_PM_CMD_READ            	0x2
#define     SLC_AUX_PM_CMD_READ_CLEAR      	0x3
#define     SLC_AUX_PM_CMD_PRESET          	0x4
#define     SLC_AUX_PM_CMD_DISABLE_ALL     	0x5
#define     SLC_AUX_PM_CMD_CLEAR_ALL       	0x6

struct csm_build {
#ifdef CONFIG_CPU_BIG_ENDIAN
	u32 res:8, csmecc1:2, csm_sz1:4, mpnum:2, bcycle:2, csmecc:2, csmsz:4, ver:8;
#else
	u32 ver:8, csmsz:4, csmecc:2, bcycle:2, mpnum:2, csm_sz1:4, csmecc1:2, res:8;
#endif
};

struct slc_build {
#ifdef CONFIG_CPU_BIG_ENDIAN
	u32 res:16, num:8, ver:8;
#else
	u32 ver:8, num:8, res:16;
#endif
};

struct slc_aux_cache_config {
#ifdef CONFIG_CPU_BIG_ENDIAN
	u32 r:2, b:1, pm_num:5, pms:2, tag_time:4, tbank:3, data_time:4, dbank:3, ways:2 \
        lsz:2, cache_sz:4;
#else
	u32 cache_sz:4, lsz:2, ways:2, dbank:3, data_time:4, tbank:3, tag_time:4, pms:2, \
        pm_num:5, b:1, r:2;
#endif
};

struct slc_aux_pm_cmd {
#ifdef CONFIG_CPU_BIG_ENDIAN
	u32 res:15, evt:8, cnum:5, cmd:4;
#else
	u32 cmd:4, cnum:5, evt:8, res:15;
#endif
};

struct slc_aux_pm_event {
#ifdef CONFIG_CPU_BIG_ENDIAN
	u32 res:23, evt:8, pe:1;
#else
	u32 pe:1, evt:8, res:23;
#endif
};

struct slc_aux_pm_ovf {
    u32 counter_overflow;
};

struct slc_aux_pm_cnt {
    u32 cnt;
};

static void arc_perf_event_update(struct perf_event *event,
				  struct hw_perf_event *hwc, int idx);


#define ARCPMU_EVENT_NAME_LEN	(31+1) // +1 for null terminator

// assign names to events according to PRM
char pct_names[ARCV2_SLC_NUM_OF_EVENTS][ARCPMU_EVENT_NAME_LEN]={
"TotReqPort0",
"TotReqPort1",
"TotReqPort2",
"TotReqPort3",
"TotReqPort4",
"TotReqPort5",
"TotReqPort6",
"TotReqPort7",
"TotReqPort8",
"TotReqPort9",
"TotReqPort10",
"TotReqPort11",
"TotReqPort12",
"TotReqPort13",
"TotReqPort14",
"TotReqPort15",
"TotCoreReqAllP",
"TotRdReqAllPort",
"TotWrReqAllPort",
"TotalTagMiss",
"ReadTagMiss",
"WriteTagMiss",
"TotStallCycDueToTagQfull",
"NumOfReqWithTagQfull",
"TotStallCycDueToDatQfull",
"NumOfReqWithDataQfull",
"TotStallCycDueToStatQfull",
"NumOfReqWithStatQfull",
"TotStallCycForInpReqAllP",
"TotStallCycForTagMiss",
"TotMissReqStall",
"TotNumOf32ByteEvictions",
"TotNumOfCacheLineEvictions",
"TotNumOfStalledCycForInpReq",
"TotNumOfStalledReq",
"TotStalledWrReq",
"TotStalledReq",
"TotCacheMissReq",
"CntCacheLineAsPendReq",
"CntCacheLineAsPendTagMiss",
"CntRdReqCacheLineAsTagMiss",
"CntWrReqCacheLineAsTagMiss",
"CntOfDataPrefetchReq",
"CntOfInstrPrefetchReq",
"Reserved0",
"Reserved1",
"Reserved2",
"Reserved3",
"TotStallReqForPort0",
"TotStallReqForPort1",
"TotStallReqForPort2",
"TotStallReqForPort3",
"TotStallReqForPort4",
"TotStallReqForPort5",
"TotStallReqForPort6",
"TotStallReqForPort7",
"TotStallReqForPort8",
"TotStallReqForPort9",
"TotStallReqForPort10",
"TotStallReqForPort11",
"TotStallReqForPort12",
"TotStallReqForPort13",
"TotStallReqForPort14",
"TotStallReqForPort15"
};

#define CONDITION_NONE_NUMBER   44 // using Reserved_0 condition number as no event

#endif
