/* SPDX-License-Identifier: GPL-2.0 */

/*
 * (C) 2023 Synopsys, Inc. (www.synopsys.com)
 *
 * Synopsys DesignWare ARC HS Hammerhead Cluster DMA driver.
 *
 * Author: Stanislav Bolshakov <Stanislav.Bolshakov@synopsys.com>
 */

#ifndef _DW_CDMA_PLATFORM_H
#define _DW_CDMA_PLATFORM_H

#include <linux/device.h>
#include <linux/dmaengine.h>
#include <linux/types.h>
#include "../virt-dma.h"

enum ch_state {
	CDMA_IDLE,
	CDMA_BUSY,
	CDMA_STOPPED,
	CDMA_RESET
};

struct cdma_hw_desc {
	dma_addr_t src_adr;
	dma_addr_t dst_adr;
	u32 length;
	u32 handle;
	struct list_head list;
};

struct c_dma_desc {
	struct virt_dma_desc vd;
	struct c_dma_chan *chan;
	struct list_head hw_desc_alloc_list;
	struct list_head hw_desc_issued_list;
	struct list_head hw_desc_finished_list;
};

struct c_dma_chan {
	struct virt_dma_chan vc;
	struct cdma_chip *chip;
	int desc_base_n;
	int desc_last_n;
	int id;
};

struct dw_cluster_dma {
	struct dma_device dma;
	struct device_dma_parameters dma_parms;
	int nr_channels;
	int nr_descr;
	int nr_max_brst;
	int nr_trans;
	u32 max_desc_len;
	struct c_dma_chan *channels;
	int cur_ch;
};

struct cdma_chip {
	struct device *dev;
	struct dw_cluster_dma *dw;
	int irq;
	int __percpu pcpu;
};

static inline struct c_dma_desc *vd_to_cdma_desc(struct virt_dma_desc *vd)
{
	return container_of(vd, struct c_dma_desc, vd);
}

static inline struct device *chan2dev(struct c_dma_chan *chan)
{
	return &chan->vc.chan.dev->device;
}

static inline struct c_dma_chan *vc_to_cdma_chan(struct virt_dma_chan *vc)
{
	return container_of(vc, struct c_dma_chan, vc);
}

static inline struct c_dma_chan *dchan_to_cdma_chan(struct dma_chan *dchan)
{
	return vc_to_cdma_chan(to_virt_chan(dchan));
}

/* CDMA client registers */
#define DMA_BUILD                   0x0E6
#define DMA_AUX_BASE                0xD00
#define DMA_C_CTRL_AUX              (DMA_AUX_BASE + 0x0) /* DMA Client Control */
#define DMA_C_CHAN_AUX              (DMA_AUX_BASE + 0x1) /* DMA Client Channel Select */
#define DMA_C_SRC_AUX               (DMA_AUX_BASE + 0x2) /* DMA Client Source Address */
#define DMA_C_SRC_HI_AUX            (DMA_AUX_BASE + 0x3) /* DMA Client Source High Address */
#define DMA_C_DST_AUX               (DMA_AUX_BASE + 0x4) /* DMA Client Destination Address */
#define DMA_C_DST_HI_AUX            (DMA_AUX_BASE + 0x5) /* DMA Client Destination High Address */
#define DMA_C_ATTR_AUX              (DMA_AUX_BASE + 0x6) /* DMA Client Attributes */
#define DMA_C_LEN_AUX               (DMA_AUX_BASE + 0x7) /* DMA Client Length */
#define DMA_C_HANDLE_AUX            (DMA_AUX_BASE + 0x8) /* DMA Client Handle */
#define DMA_C_EVSTAT_AUX            (DMA_AUX_BASE + 0xA) /* DMA Event Status */
#define DMA_C_EVSTAT_CLR_AUX        (DMA_AUX_BASE + 0xB) /* DMA Client Clear Event Status */
#define DMA_C_STAT_AUX              (DMA_AUX_BASE + 0xC) /* DMA Client Status */
#define DMA_C_INTSTAT_AUX           (DMA_AUX_BASE + 0xD) /* DMA Interrupt Status */
#define DMA_C_INTSTAT_CLR_AUX       (DMA_AUX_BASE + 0xE) /* DMA Client Clear Interrupt Status */
#define DMA_C_ERRHANDLE_AUX         (DMA_AUX_BASE + 0xF) /* DMA Client Error Handle */

/* CDMA server registers */
#define DMA_S_CTRL_AUX              (DMA_AUX_BASE + 0x10) /* DMA Server Control */
#define DMA_S_DONESTATD_AUX(d)      (DMA_AUX_BASE + 0x20 + (d)) /* DMA Server Done Status */
#define DMA_S_DONESTATD_CLR_AUX(d)  (DMA_AUX_BASE + 0x40 + (d)) /* DMA Server Clear Done Status */
#define DMA_S_BASEC_AUX(ch)         (DMA_AUX_BASE + 0x83 + (ch)*8) /* DMA Server Channel Base */
#define DMA_S_LASTC_AUX(ch)         (DMA_AUX_BASE + 0x84 + (ch)*8) /* DMA Server Channel Last */
#define DMA_S_PRIOC_AUX(ch)         (DMA_AUX_BASE + 0x85 + (ch)*8) /* DMA Channel Priority */
#define DMA_S_STATC_AUX(ch)         (DMA_AUX_BASE + 0x86 + (ch)*8) /* DMA Channel Control */

#define DMA_HANDLE_TO_N_WORD_OFFS	5 /* Get register word offset from a handle */
#define DMA_HANDLE_BIT_MASK			0x1F /* Get active bit position from a handle */
#define DW_CDMA_MIN_VERSION			0x10

/*
 * The set of bus widths supported by the CDMA controller. DW CDMA supports
 * fixed master data bus width 128 bits
 */
#define CDMA_BUSWIDTHS		  \
	(DMA_SLAVE_BUSWIDTH_1_BYTE	| \
	DMA_SLAVE_BUSWIDTH_2_BYTES	| \
	DMA_SLAVE_BUSWIDTH_4_BYTES	| \
	DMA_SLAVE_BUSWIDTH_8_BYTES	| \
	DMA_SLAVE_BUSWIDTH_16_BYTES)

/* CDMA structures */
union cdma_build_t {
	struct{
#ifdef CONFIG_CPU_BIG_ENDIAN
	u32 res:7, desci:1, dw:1, bnum:3, ntrans:2, mlen:2, dnum:4, cnum:4, ver:8;
#else
	u32 ver:8, cnum:4, dnum:4, mlen:2, ntrans:2, bnum:3, dw:1, desci:1, res:7;
#endif
	};
	u32 val;
};

struct cdma_c_attr_t {
#ifdef CONFIG_CPU_BIG_ENDIAN
	u32 res2:10, awcache:4, arcache:4, pld:1, qosd:3, ddom:2, sdom:2, res1:3, e:1, i:1, d:1;
#else
	u32 d:1, i:1, e:1, res1:3, sdom:2, ddom:2, qosd:3, pld:1, arcache:4, awcache:4, res2:10;
#endif
};

struct cdma_s_stat_t {
#ifdef CONFIG_CPU_BIG_ENDIAN
	u32 res2:21, st:2, f:1, res1:6, r:1, e:1;
#else
	u32 e:1, r:1, res1:6, f:1, st:2, res2:21;
#endif
};

struct cdma_c_ctrl_t {
#ifdef CONFIG_CPU_BIG_ENDIAN
	u32 res:31, u:1;
#else
	u32 u:1, res:31;
#endif
};

struct cdma_s_ctrl_t {
#ifdef CONFIG_CPU_BIG_ENDIAN
	u32 res2:20, mlen:4, res1:6, o:1, u:1;
#else
	u32 u:1, o:1, res1:6, mlen:4, res2:20;
#endif
};

struct cdma_s_prioc_t {
#ifdef CONFIG_CPU_BIG_ENDIAN
	u32 res:31, p:1;
#else
	u32 p:1, res:31;
#endif
};

struct cdma_c_stat_t {
#ifdef CONFIG_CPU_BIG_ENDIAN
	u32 res:31, b:1;
#else
	u32 b:1, res:31;
#endif
};

struct cdma_c_intstat_t {
#ifdef CONFIG_CPU_BIG_ENDIAN
	u32 res:29, o:1, b:1, d:1;
#else
	u32 d:1, b:1, o:1, res:29;
#endif
};

#endif /* _DW_CDMA_PLATFORM_H */
