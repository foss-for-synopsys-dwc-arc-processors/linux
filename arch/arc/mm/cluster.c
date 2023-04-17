// SPDX-License-Identifier: GPL-2.0-only

#include <linux/mm.h>

#include <asm/cluster.h>
#include <linux/memblock.h>

void __init arc_cluster_mumbojumbo()
{
	struct bcr_clustv3_cfg cbcr;
	u64 i;
	phys_addr_t start, end;
	u32 offs, size;

	READ_BCR(ARC_REG_CLUSTER_BCR, cbcr);
	if (cbcr.ver_maj == 0)
		return;

	/*
	 * Region -> Base -> Size
	 *
	 * NOC- > 0x8z–> 1Gb
	 * Per 0 -> 0xFz -> 1Mb
	 * SCM -> 0xFz+1MB -> 1Mb
	 */

	for_each_mem_range(i, &start, &end) {
		if ((start <= CONFIG_LINUX_LINK_BASE) && (CONFIG_LINUX_LINK_BASE < end)) {
			offs = (u64)start >> 20U;
			size = ((u64)end - (u64)start) >> 20U;
			arc_cln_write_reg(ARC_CLN_MST_NOC_0_0_ADDR, offs);
			arc_cln_write_reg(ARC_CLN_MST_NOC_0_0_SIZE, size);
			break;
		}
	}

	arc_cln_write_reg(ARC_CLN_PER_0_BASE, 0xf00);
	arc_cln_write_reg(ARC_CLN_PER_0_SIZE,   0x1);

	arc_cln_write_reg(ARC_CLN_SHMEM_ADDR, 0xf01);
	arc_cln_write_reg(ARC_CLN_SHMEM_SIZE,   0x1);
}

void arc_cluster_scm_enable()
{
	/* Disable SCM, just in case. */
	arc_cln_write_reg(ARC_CLN_CACHE_STATUS, 0);

	/* Invalidate SCM before enabling. */
	arc_cln_write_reg(ARC_CLN_CACHE_CMD, ARC_CLN_CACHE_CMD_OP_REG_INV |
			  ARC_CLN_CACHE_CMD_INCR);
	while (arc_cln_read_reg(ARC_CLN_CACHE_STATUS) &
	       ARC_CLN_CACHE_STATUS_BUSY)
		;

	arc_cln_write_reg(ARC_CLN_CACHE_STATUS, ARC_CLN_CACHE_STATUS_EN);
}

void arc_cluster_scm_flush_range(phys_addr_t low, phys_addr_t high)
{
	arc_cln_write_reg(ARC_CLN_CACHE_ADDR_LO0, (u32) low);
	arc_cln_write_reg(ARC_CLN_CACHE_ADDR_LO1, (u64) low >> 32);

	arc_cln_write_reg(ARC_CLN_CACHE_ADDR_HI0, (u32) high);
	arc_cln_write_reg(ARC_CLN_CACHE_ADDR_HI1, (u64) high >> 32);

	arc_cln_write_reg(ARC_CLN_CACHE_CMD, ARC_CLN_CACHE_CMD_OP_ADDR_CLN);

	while (arc_cln_read_reg(ARC_CLN_CACHE_STATUS) &
	       ARC_CLN_CACHE_STATUS_BUSY)
		;
}
