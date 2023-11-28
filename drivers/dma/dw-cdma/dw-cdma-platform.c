// SPDX-License-Identifier: GPL-2.0

/*
 * (C) 2023 Synopsys, Inc. (www.synopsys.com)
 *
 * Synopsys DesignWare ARC HS Hammerhead Cluster DMA driver.
 *
 * Author: Stanislav Bolshakov <Stanislav.Bolshakov@synopsys.com>
 */

#include <linux/device.h>
#include <linux/dmaengine.h>
#include <linux/dma-mapping.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_dma.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <asm/cluster.h>
#include "dw-cdma.h"
#include "../dmaengine.h"
#include "../virt-dma.h"


static struct cdma_chip chip;

static void cdma_enable_ch(u32 ch)
{
	struct cdma_s_stat_t stat;

	stat.r = 0; /* Reset channel */
	stat.e = 1; /* Enable channel */
	WRITE_AUX(DMA_S_STATC_AUX(ch), stat);

	do {
		READ_BCR(DMA_S_STATC_AUX(ch), stat);
		if (stat.st == CDMA_IDLE || stat.st == CDMA_BUSY)
			break;
	} while (1);
}

static void cdma_disable_ch(u32 ch)
{
	struct cdma_s_stat_t stat;

	stat.r = 0; /* Reset channel */
	stat.e = 0; /* Disable channel */
	WRITE_AUX(DMA_S_STATC_AUX(ch), stat);

	do {
		READ_BCR(DMA_S_STATC_AUX(ch), stat);
	} while (stat.st == CDMA_BUSY);
}

static void cdma_reset_ch(u32 ch)
{
	struct cdma_s_stat_t stat;

	stat.r = 1; /* Reset channel */
	stat.e = 0; /* Enable channel */
	WRITE_AUX(DMA_S_STATC_AUX(ch), stat);

	do {
		READ_BCR(DMA_S_STATC_AUX(ch), stat);
	} while (stat.st == CDMA_BUSY);
}

static inline int cdma_get_bit_done(u32 handle)
{
	u32 a, o, x;

	a = handle >> DMA_HANDLE_TO_N_WORD_OFFS;
	o = 1 << (handle & DMA_HANDLE_BIT_MASK);
	READ_BCR(DMA_S_DONESTATD_AUX(a), x);
	x &= o;
	return x != 0;
}

static inline void cdma_clear_bit_done(u32 handle)
{
	u32 a, x;

	a = handle >> DMA_HANDLE_TO_N_WORD_OFFS;
	x = 1 << (handle & DMA_HANDLE_BIT_MASK);
	WRITE_AUX(DMA_S_DONESTATD_CLR_AUX(a), x);
}

/* Get descriptor handle of the last started DMA */
static inline u32 cdma_get_handle(void)
{
	struct cdma_c_stat_t stat;
	u32 handle;

	do {
		READ_BCR(DMA_C_STAT_AUX, stat);
	} while (stat.b);

	READ_BCR(DMA_C_HANDLE_AUX, handle);
	return handle;
}

static int free_hw_desc_list(struct list_head *list_head)
{
	struct cdma_hw_desc *hw_desc, *hw_desc_temp;

	if (list_empty(list_head))
		return 1;

	list_for_each_entry_safe(hw_desc, hw_desc_temp, list_head, list) {
		list_del(&hw_desc->list);
		kfree(hw_desc);
	}
	return 0;
}

static void vchan_desc_put(struct virt_dma_desc *vdesc)
{
	struct c_dma_desc *desc = vd_to_cdma_desc(vdesc);
	unsigned long flags;
	int done_flg;

	spin_lock_irqsave(&desc->chan->vc.lock, flags);
	done_flg = free_hw_desc_list(&desc->hw_desc_alloc_list);
	done_flg &= free_hw_desc_list(&desc->hw_desc_issued_list);
	done_flg &= !free_hw_desc_list(&desc->hw_desc_finished_list);
	spin_unlock_irqrestore(&desc->chan->vc.lock, flags);

	if (!done_flg)
		dev_warn(chan2dev(desc->chan), "Put an active descriptor.\n");

	kfree(desc);
}

static void cdma_setup(struct cdma_chip *chip)
{
	struct cdma_c_ctrl_t ctrl_c;
	struct cdma_s_ctrl_t ctrl_s;
	struct cdma_s_prioc_t prio_ch;
	struct dw_cluster_dma *dw = chip->dw;
	struct c_dma_chan *chan;
	int desc_per_ch;
	int ii;

	/* Define number of descriptors per each chanel */
	desc_per_ch = dw->nr_descr / dw->nr_channels;

	for (ii = 0; ii < dw->nr_channels; ii++) {
		cdma_reset_ch(ii);

		chan = &dw->channels[ii];
		chan->chip = chip;
		chan->id = ii;
		chan->desc_base_n = ii * desc_per_ch;
		chan->desc_last_n = (ii + 1) * desc_per_ch - 1;
		WRITE_AUX(DMA_S_BASEC_AUX(ii), chan->desc_base_n); /* Setup ch desc base */
		WRITE_AUX(DMA_S_LASTC_AUX(ii), chan->desc_last_n); /* Setup ch desc last */

		/* Setup channels priority. 0-low prio / 1-hi prio */
		prio_ch.p = 0;
		WRITE_AUX(DMA_S_PRIOC_AUX(ii), prio_ch);

		chan->vc.desc_free = vchan_desc_put;
		vchan_init(&chan->vc, &dw->dma);
	}

	/* 0 - User mode access is not allowed for client AUX regs */
	ctrl_c.u = 0;
	WRITE_AUX(DMA_C_CTRL_AUX, ctrl_c);

	/* 0 - User mode access is not allowed for server AUX regs */
	ctrl_s.u = 0;
	/* Raise an interrupt in case the client pushes a descriptor in a full channel */
	ctrl_s.o = 1;
	/* Maximum bus burst length */
	ctrl_s.mlen = 0xF;
	WRITE_AUX(DMA_S_CTRL_AUX, ctrl_s);
}

static inline void cdma_next(dma_addr_t src, dma_addr_t dst, u32 len, struct cdma_c_attr_t a)
{
#ifdef CONFIG_64BIT
	WRITE_AUX64(DMA_C_SRC_AUX, src);
	WRITE_AUX64(DMA_C_DST_AUX, dst);
#else
	u32 vv;

	vv = (u32)src;
	WRITE_AUX(DMA_C_SRC_AUX, vv);
	vv = (u32)dst;
	WRITE_AUX(DMA_C_DST_AUX, vv);
#endif /* CONFIG_64BIT */

	WRITE_AUX(DMA_C_ATTR_AUX, a);
	/* The length register triggers the actual dma_push message */
	WRITE_AUX(DMA_C_LEN_AUX, len);
}

static inline void cdma_start(u32 c, /* Channel ID */
				dma_addr_t src, /* From byte address */
				dma_addr_t dst, /* To byte address */
				u32 len, /* DMA length in bytes */
				struct cdma_c_attr_t a) /* Attributes */
{
	/* R/W accesses to this register will stall while DMA_C_STATUS_AUX.B bit is set */
	WRITE_AUX(DMA_C_CHAN_AUX, c);
	cdma_next(src, dst, len, a);
}

/* Is called in channel locked context */
static inline void cdma_chan_xfer_continue(struct c_dma_chan *chan, struct c_dma_desc *desc)
{
	struct cdma_c_attr_t attr;
	struct cdma_hw_desc *hw_desc;

	hw_desc = list_first_entry_or_null(&desc->hw_desc_alloc_list, struct cdma_hw_desc, list);
	if (unlikely(hw_desc == NULL))
		return;

	if (unlikely(hw_desc->handle != -1)) {
		dev_warn(chan2dev(desc->chan), "Was the descriptor already issued? handle=%d\n",
			hw_desc->handle);
		return;
	}

	attr.d = 1; /* Will set DMA_S_DONESTATD_AUX when DMA server is done processing the descriptor */
	attr.i = 1; /* Trigger the interrupt when done + setup DMA_S_DONESTATD_AUX */
	attr.e = 0; /* Disable event mode */
	attr.sdom = 1; /* Source memory access- inner shareable */
	attr.ddom = 1; /* Destination memory access- inner shareable */
	attr.qosd = 0x0; /* Resource domain used with QoS feature */
	attr.pld = 0; /* Support L2 preloading */
	attr.arcache = 0x2; /* 0x2 DMA read transactions - modifiable (cacheable) */
	attr.awcache = 0x2; /* 0x2 DMA write transactions - modifiable (cacheable) */

	cdma_enable_ch(chan->id); /* Enable channel */
	cdma_start(chan->id, hw_desc->src_adr, hw_desc->dst_adr, hw_desc->length, attr);
	hw_desc->handle = cdma_get_handle(); /* Get the handle for the most recently pusshed descriptor */

	list_move_tail(&hw_desc->list, &desc->hw_desc_issued_list);
}

/* Is called in channel locked context */
static void cdma_chan_start_first_queued(struct c_dma_chan *chan)
{
	struct virt_dma_desc *vd;
	struct c_dma_desc *desc;

	/* Peek at the next descriptor to be processed */
	vd = vchan_next_desc(&chan->vc);
	if (unlikely(!vd))
		return; /* Descriptor queue is empty */

	desc = vd_to_cdma_desc(vd);
	cdma_chan_xfer_continue(chan, desc);
}

/* Is called from interrupt */
static inline void cdma_chan_xfer_complete(struct c_dma_chan *chan, u32 handle)
{
	struct virt_dma_desc *vd;
	struct c_dma_desc *desc;
	struct cdma_hw_desc *hw_desc;
	unsigned long flags;
	bool done_flg;
	bool entry_notfound = true;

	spin_lock_irqsave(&chan->vc.lock, flags);

	/* The completed descriptor currently is in the head of vc list */
	vd = vchan_next_desc(&chan->vc);
	if (unlikely(!vd)) {
		spin_unlock_irqrestore(&chan->vc.lock, flags);
		dev_warn(chan2dev(chan), "Completed descriptor list is empty!\n");
		return;
	}
	desc = vd_to_cdma_desc(vd);

	list_for_each_entry(hw_desc, &desc->hw_desc_issued_list, list) {
		if (hw_desc->handle == handle) {
			list_move_tail(&hw_desc->list, &desc->hw_desc_finished_list);
			entry_notfound = false;
			break;
		}
	}

	if (unlikely(entry_notfound))
		dev_warn(chan2dev(chan), "Didn't find an issued descriptor to complete.");

	done_flg = list_empty(&desc->hw_desc_alloc_list) && list_empty(&desc->hw_desc_issued_list);
	if (done_flg) {
		list_del(&vd->node);
		vchan_cookie_complete(vd);
	}

	/* Submit queued descriptors after processing the completed ones */
	cdma_chan_start_first_queued(chan);

	spin_unlock_irqrestore(&chan->vc.lock, flags);
}

static enum dma_status cdma_chan_tx_status(struct dma_chan *dchan, dma_cookie_t cookie,
		  struct dma_tx_state *txstate)
{
	return dma_cookie_status(dchan, cookie, txstate);
}

static void process_error_chan(struct c_dma_chan *chan)
{
	struct virt_dma_desc *vd;
	struct c_dma_desc *desc;
	unsigned long flags;

	spin_lock_irqsave(&chan->vc.lock, flags);

	cdma_reset_ch(chan->id);

	/* The bad descriptor currently is in the head of vc list */
	vd = vchan_next_desc(&chan->vc);
	/* Remove the completed descriptor from issued list */
	list_del(&vd->node);

	desc = vd_to_cdma_desc(vd);
	list_splice_tail(&desc->hw_desc_alloc_list, &desc->hw_desc_finished_list);
	list_splice_tail(&desc->hw_desc_issued_list, &desc->hw_desc_finished_list);

	/* WARN about bad descriptor */
	dev_warn(chan2dev(chan),
		"Bad descriptor submitted for cookie: %d\n", vd->tx.cookie);

	vchan_cookie_complete(vd);

	/* Try to restart the controller */
	cdma_chan_start_first_queued(chan);

	spin_unlock_irqrestore(&chan->vc.lock, flags);
}

static noinline void cdma_chan_handle_err(struct dw_cluster_dma *dw, u32 err_handle)
{
	struct c_dma_chan *chan, *err_chan = NULL;
	int ii;

	if (err_handle != -1) {
		/* Handle bus error */
		for (ii = 0; ii < dw->nr_channels; ii++) {
			chan = &dw->channels[ii];
			if (err_handle < chan->desc_base_n || err_handle > chan->desc_last_n)
				continue;
			dev_warn(chan2dev(chan), "Bus error.\n");
			process_error_chan(chan);
			err_chan = chan;
			break;
		}
		if (err_chan == NULL) {
			for (ii = 0; ii < dw->nr_channels; ii++) {
				chan = &dw->channels[ii];
				dev_warn(chan2dev(chan), "Bus error.\n");
				process_error_chan(chan);
			}
		}
	} else {
		/* Handle overflow.
		 * Since we don't know from HW which channel caused overflow,
		 * terminate them all
		 */
		for (ii = 0; ii < dw->nr_channels; ii++) {
			chan = &dw->channels[ii];
			dev_warn(chan2dev(chan), "Channel is overflowed.\n");
			process_error_chan(chan);
		}
	}
}

static irqreturn_t cdma_interrupt(int irq, void *data)
{
	struct dw_cluster_dma *dw = chip.dw;
	struct cdma_c_intstat_t intstat;
	struct c_dma_chan *chan;
	u32 err_handle;
	int ii, jj;
	int done;

	READ_BCR(DMA_C_INTSTAT_AUX, intstat);
	if (unlikely(intstat.b)) {
		READ_BCR(DMA_C_ERRHANDLE_AUX, err_handle);
		cdma_chan_handle_err(dw, err_handle);
		return IRQ_HANDLED;
	}
	if (unlikely(intstat.o)) {
		cdma_chan_handle_err(dw, -1);
		return IRQ_HANDLED;
	}
	if (unlikely((intstat.b == 0) && (intstat.o == 0) && (intstat.d == 0))) {
		/* Shouldn't happen */
		for (ii = 0; ii < dw->nr_channels; ii++) {
			chan = &dw->channels[ii];
			dev_warn(chan2dev(chan), "Interrupt flags are not aligned.\n");
		}
	}
	WRITE_AUX(DMA_C_INTSTAT_CLR_AUX, intstat);

	for (ii = 0; ii < dw->nr_channels; ii++) {
		chan = &dw->channels[ii];
		for (jj = chan->desc_base_n; jj <= chan->desc_last_n; jj++) {
			done = cdma_get_bit_done(jj);
			if (done) {
				cdma_clear_bit_done(jj);
				cdma_chan_xfer_complete(chan, jj);
			}
		}
	}

	return IRQ_HANDLED;
}

static void cdma_chan_issue_pending(struct dma_chan *dchan)
{
	struct c_dma_chan *chan = dchan_to_cdma_chan(dchan);
	unsigned long flags;

	spin_lock_irqsave(&chan->vc.lock, flags);
	if (vchan_issue_pending(&chan->vc))
		cdma_chan_start_first_queued(chan);
	spin_unlock_irqrestore(&chan->vc.lock, flags);
}

static int cdma_chan_terminate_all(struct dma_chan *dchan)
{
	struct c_dma_chan *chan = dchan_to_cdma_chan(dchan);
	unsigned long flags;
	int desc_done;
	LIST_HEAD(head);

	spin_lock_irqsave(&chan->vc.lock, flags);
	desc_done = list_empty(&chan->vc.desc_allocated) &&
			list_empty(&chan->vc.desc_submitted) &&
			list_empty(&chan->vc.desc_issued);
	if (!desc_done) {
		spin_unlock_irqrestore(&chan->vc.lock, flags);
		return 0;
	}

	cdma_reset_ch(chan->id);

	/* Obtain all submitted and issued descriptors, vc.lock must be held by caller */
	vchan_get_all_descriptors(&chan->vc, &head);
	spin_unlock_irqrestore(&chan->vc.lock, flags);

	vchan_dma_desc_free_list(&chan->vc, &head);

	return 0;
}

static void cdma_chan_free_chan_resources(struct dma_chan *dchan)
{
	struct c_dma_chan *chan = dchan_to_cdma_chan(dchan);

	cdma_disable_ch(chan->id);
	vchan_free_chan_resources(&chan->vc);
}

static struct dma_async_tx_descriptor *cdma_chan_prep_memcpy(struct dma_chan *dchan,
			dma_addr_t dst_adr, dma_addr_t src_adr, size_t len, unsigned long flags)
{
	struct c_dma_chan *chan = dchan_to_cdma_chan(dchan);
	struct c_dma_desc *desc;
	struct cdma_hw_desc *hw_desc = NULL;
	size_t desc_limit = chan->chip->dw->max_desc_len;
	size_t cur_len;

	desc = kzalloc(sizeof(*desc), GFP_NOWAIT);
	if (unlikely(!desc))
		return NULL;

	desc->chan = chan;
	INIT_LIST_HEAD(&desc->hw_desc_alloc_list);
	INIT_LIST_HEAD(&desc->hw_desc_issued_list);
	INIT_LIST_HEAD(&desc->hw_desc_finished_list);

	while (len > 0) {
		hw_desc = kzalloc(sizeof(*hw_desc), GFP_NOWAIT);
		if (!hw_desc) {
			free_hw_desc_list(&desc->hw_desc_alloc_list);
			kfree(desc);
			return NULL;
		}

		cur_len = len;
		if (cur_len > desc_limit)
			cur_len = desc_limit;

		hw_desc->src_adr = src_adr;
		hw_desc->dst_adr = dst_adr;
		hw_desc->length = cur_len;
		hw_desc->handle = -1;
		list_add_tail(&hw_desc->list, &desc->hw_desc_alloc_list);

		len -= cur_len;
		src_adr += cur_len;
		dst_adr += cur_len;
	}

	return vchan_tx_prep(&chan->vc, &desc->vd, flags);
}

static void cdma_synchronize(struct dma_chan *dchan)
{
	struct c_dma_chan *chan = dchan_to_cdma_chan(dchan);

	vchan_synchronize(&chan->vc);
}

static int read_config(struct cdma_chip *chip)
{
	struct device *dev = chip->dev;
	union cdma_build_t bcr;
	struct dw_cluster_dma *dw = chip->dw;
	int ret;
	u32 tmp;

	bcr.val = read_aux_reg(DMA_BUILD);
	if (bcr.ver < DW_CDMA_MIN_VERSION)
		return -1;

	dw->nr_channels = 1 << bcr.cnum;
	dw->nr_descr = 1 << bcr.dnum;
	dw->nr_max_brst = (1 << bcr.mlen) * 4;
	dw->nr_trans = (1 << bcr.ntrans) * 4;

	ret = device_property_read_u32(dev, "cdma-max-desc-len", &tmp);
	if (ret)
		return ret;

	/* The maximum transfer length for the cdma descriptor */
	dw->max_desc_len = tmp;

	return 0;
}

static void cdma_hw_init(struct cdma_chip *chip)
{
	int ret;

	cdma_setup(chip);
#ifdef CONFIG_64BIT
	ret = dma_set_mask_and_coherent(chip->dev, DMA_BIT_MASK(64));
#else
	ret = dma_set_mask_and_coherent(chip->dev, DMA_BIT_MASK(32));
#endif
	if (ret)
		dev_warn(chip->dev, "Unable to set coherent mask\n");
}

static void cdma_cpu_irq_init(void *data)
{
	int irq = *(int *)data;

	enable_percpu_irq(irq, IRQ_TYPE_NONE);
}

static int dw_cdma_probe(struct platform_device *pdev)
{
	struct dw_cluster_dma *dw = NULL;
	int ret;

	dw = devm_kzalloc(&pdev->dev, sizeof(*dw), GFP_KERNEL);
	if (!dw) {
		ret = -ENOMEM;
		goto exit;
	}

	chip.dw = dw;
	chip.dev = &pdev->dev;

	ret = read_config(&chip);
	if (ret != 0) {
		ret = -ENODEV;
		goto exit;
	}

	chip.irq = platform_get_irq(pdev, 0);
	if (chip.irq < 0) {
		ret = chip.irq;
		goto exit;
	}

	ret = request_percpu_irq(chip.irq, cdma_interrupt, "CDMA", &chip.pcpu);
	if (!ret) {
		on_each_cpu(cdma_cpu_irq_init, &chip.irq, 1);
	} else {
		dev_warn(&pdev->dev, "Failed to request IRQ per cpu.\n");
		goto exit;
	}

	dw->channels = devm_kcalloc(chip.dev, dw->nr_channels, sizeof(*dw->channels), GFP_KERNEL);
	if (!dw->channels) {
		ret = -ENOMEM;
		goto exit;
	}

	INIT_LIST_HEAD(&dw->dma.channels);

	/* The device is only able to perform memory to memory copies */
	dma_cap_set(DMA_MEMCPY, dw->dma.cap_mask);

	/* DMA capabilities */
	dw->dma.dev = chip.dev;
	dw->dma.chancnt = dw->nr_channels;
	dw->dma.max_burst = dw->nr_max_brst;
	dw->dma.dev->dma_parms = &dw->dma_parms;
	dw->dma.src_addr_widths = CDMA_BUSWIDTHS;
	dw->dma.dst_addr_widths = CDMA_BUSWIDTHS;
	dw->dma.directions = BIT(DMA_MEM_TO_MEM);
	/* No support for residue reporting */
	dw->dma.residue_granularity = DMA_RESIDUE_GRANULARITY_DESCRIPTOR;

	dw->dma.device_tx_status = cdma_chan_tx_status;
	dw->dma.device_issue_pending = cdma_chan_issue_pending;
	dw->dma.device_terminate_all = cdma_chan_terminate_all;
	dw->dma.device_free_chan_resources = cdma_chan_free_chan_resources;
	dw->dma.device_prep_dma_memcpy = cdma_chan_prep_memcpy;
	dw->dma.device_synchronize = cdma_synchronize;

	cdma_hw_init(&chip);

	platform_set_drvdata(pdev, dw);

	ret = dma_async_device_register(&dw->dma);
	if (ret) {
		dev_warn(&pdev->dev, "Failed to register Cluster DMA\n");
		goto exit;
	}

	dev_info(chip.dev, "DesignWare Cluster DMA, %d channel(s), IRQ# %d\n",
		dw->nr_channels, chip.irq);

	return 0;

exit:
	devm_kfree(&pdev->dev, dw->channels);
	devm_kfree(&pdev->dev, dw);
	return ret;
}

static const struct of_device_id dw_cdma_of_id_table[] = {
	{ .compatible = "snps,cluster-dma-1.0" },
	{}
};
MODULE_DEVICE_TABLE(of, dw_dma_of_id_table);

static struct platform_driver dw_cdma_driver = {
	.probe		= dw_cdma_probe,
	.driver = {
		.name	= KBUILD_MODNAME,
		.of_match_table = dw_cdma_of_id_table,
	},
};
module_platform_driver(dw_cdma_driver);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Synopsys DesignWare ARC HS Hammerhead Cluster DMA driver");
MODULE_AUTHOR("Stanislav Bolshakov <Stanislav.Bolshakov@synopsys.com>");
