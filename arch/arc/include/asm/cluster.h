/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Cluster Network Support
 *
 * Copyright (C) 2021 Synopsys, Inc. (www.synopsys.com)
 */

#ifndef _ASM_ARC_CLUSTER_H
#define _ASM_ARC_CLUSTER_H

#include <soc/arc/aux.h>

#define ARC_REG_CLNR_ADDR	0x640	/* CLN address for CLNR_DATA */
#define ARC_REG_CLNR_DATA	0x641	/* CLN data indicated by CLNR_ADDR */
#define ARC_REG_CLNR_DATA_NXT	0x642	/* CLNR_DATA and then CLNR_ADDR++ */
#define ARC_REG_CLNR_BCR_0	0xF61
#define ARC_REG_CLNR_BCR_1	0xF62
#define ARC_REG_CLNR_BCR_2	0xF63
#define ARC_REG_CLNR_SCM_BCR_0	0xF64
#define ARC_REG_CLNR_SCM_BCR_1	0xF65

struct bcr_clustv3_cfg {
#ifdef CONFIG_CPU_BIG_ENDIAN
	unsigned int pad:16, ver_min:8, ver_maj:8;
#else
	unsigned int ver_maj:8, ver_min:8, pad:16;
#endif
};

struct bcr_cln_0_cfg {
#ifdef CONFIG_CPU_BIG_ENDIAN
	unsigned int res:1, clk_gate:1, has_scm:1, acr:1, mst_per:2, has_scu:1,
		     qos:4, slv_dev:6, slv_arc:5, mst_ccm:6, mst_noc:4;
#else
	unsigned int mst_noc:4, mst_ccm:6, slv_arc:5, slv_dev:6, qos:4,
		     has_scu:1, mst_per:2, acr:1, has_scm:1, clk_gate:1, res:1;
#endif
};

struct bcr_cln_1_cfg {
#ifdef CONFIG_CPU_BIG_ENDIAN
	unsigned int res:11, txc:7, txb:7, addr_size:6, aux_slv_port:1;
#else
	unsigned int aux_slv_port:1, addr_size:6, txb:7, txc:7, res:11;
#endif
};

struct bcr_cln_2_cfg {
#ifdef CONFIG_CPU_BIG_ENDIAN
	unsigned int res:8, wpath_wide_ch:6,
		     wpath_nr_ch:6, rpath_wide_ch:6, rpath_nr_ch:6;
#else
	unsigned int rpath_nr_ch:6, rpath_wide_ch:6, wpath_nr_ch:6,
		     wpath_wide_ch:6, res:8;
#endif
};

struct bcr_cln_scm_0_cfg {
#ifdef CONFIG_CPU_BIG_ENDIAN
	unsigned int res1:2, superblocks:3,
		     data_bank_wid:2, data_sub_banks:2, cache_sets:5,
		     data_bank_sz:5, data_banks:3, cache_tag_banks:3,
		     cache_blk_sz:1 cache_assoc:4, scm_cache:1, res:1;
#else
	unsigned int res:1, scm_cache:1, cache_assoc:4, cache_blk_sz:1,
		     cache_tag_banks:3, data_banks:3, data_bank_sz:5,
		     cache_sets:5, data_sub_banks:2, data_bank_wid:2,
		     superblocks:3, res1:2;
#endif
};

struct bcr_cln_scm_1_cfg {
#ifdef CONFIG_CPU_BIG_ENDIAN
	unsigned int res:24, tbank_wait:4, dbank_wait:4;
#else
	unsigned int dbank_wait:4, tbank_wait:4, res:24;
#endif
};

#define ARC_CLN_MST_NOC_0_BCR			0
#define ARC_CLN_MST_NOC_1_BCR			1
#define ARC_CLN_MST_NOC_2_BCR			2
#define ARC_CLN_MST_NOC_3_BCR			3
#define ARC_CLN_MST_PER_0_BCR			16
#define ARC_CLN_MST_PER_1_BCR			17
#define ARC_CLN_PER_0_BASE			2688
#define ARC_CLN_PER_0_SIZE			2689
#define ARC_CLN_PER_1_BASE			2690
#define ARC_CLN_PER_1_SIZE			2691

#define ARC_CLN_SCM_BCR_0			100
#define ARC_CLN_SCM_BCR_1			101

#define ARC_CLN_MST_NOC_0_0_ADDR		292
#define ARC_CLN_MST_NOC_0_0_SIZE		293

#define ARC_CLN_SHMEM_ADDR			200
#define ARC_CLN_SHMEM_SIZE			201
#define ARC_CLN_CACHE_ADDR_LO0			204
#define ARC_CLN_CACHE_ADDR_LO1			205
#define ARC_CLN_CACHE_ADDR_HI0			206
#define ARC_CLN_CACHE_ADDR_HI1			207
#define ARC_CLN_CACHE_CMD			208
#define ARC_CLN_CACHE_CMD_OP_NOP		0b0000
#define ARC_CLN_CACHE_CMD_OP_LOOKUP		0b0001
#define ARC_CLN_CACHE_CMD_OP_PROBE		0b0010
#define ARC_CLN_CACHE_CMD_OP_IDX_INV		0b0101
#define ARC_CLN_CACHE_CMD_OP_IDX_CLN		0b0110
#define ARC_CLN_CACHE_CMD_OP_IDX_CLN_INV	0b0111
#define ARC_CLN_CACHE_CMD_OP_REG_INV		0b1001
#define ARC_CLN_CACHE_CMD_OP_REG_CLN		0b1010
#define ARC_CLN_CACHE_CMD_OP_REG_CLN_INV	0b1011
#define ARC_CLN_CACHE_CMD_OP_ADDR_INV		0b1101
#define ARC_CLN_CACHE_CMD_OP_ADDR_CLN		0b1110
#define ARC_CLN_CACHE_CMD_OP_ADDR_CLN_INV	0b1111
#define ARC_CLN_CACHE_CMD_INCR			BIT(4)

#define ARC_CLN_CACHE_STATUS			209
#define ARC_CLN_CACHE_STATUS_BUSY		BIT(23)
#define ARC_CLN_CACHE_STATUS_DONE		BIT(24)
#define ARC_CLN_CACHE_STATUS_EN			BIT(27)
#define ARC_CLN_CACHE_ERR			210
#define ARC_CLN_CACHE_ERR_ADDR0			211
#define ARC_CLN_CACHE_ERR_ADDR1			212

struct arc_cln_cache_cmd {
#ifdef CONFIG_CPU_BIG_ENDIAN
	unsigned int res:22, coherent:2, rdomid:3, incr:1, op:4;
#else
	unsigned int op:4, incr:1, rdomid:3, coherent:2, res:22;
#endif
};

struct arc_cln_cache_status {
#ifdef CONFIG_CPU_BIG_ENDIAN
	unsigned int res:4, enable:1,
		     mask:1, err:1, done:1, busy:1, moesip:3, way:4, idx:16;
#else
	unsigned int idx:16, way:4, moesip:3, busy:1, done:1, err:1, mask:1,
		     enable:1, res:4;
#endif
};

static inline unsigned int arc_cln_read_reg(unsigned int reg)
{
	write_aux_reg(ARC_REG_CLNR_ADDR, reg);

	return read_aux_reg(ARC_REG_CLNR_DATA);
}

static inline void arc_cln_write_reg(unsigned int reg, unsigned int data)
{
	write_aux_reg(ARC_REG_CLNR_ADDR, reg);

	write_aux_reg(ARC_REG_CLNR_DATA, data);
}

void arc_cluster_mumbojumbo(void);
void arc_cluster_scm_enable(void);
void arc_cluster_scm_flush_range(phys_addr_t low, phys_addr_t high);

#endif /* _ASM_ARC_CLUSTER_H */
