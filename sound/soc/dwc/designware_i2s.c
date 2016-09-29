/*
 * ALSA SoC Synopsys I2S Audio Layer
 *
 * sound/soc/dwc/designware_i2s.c
 *
 * Copyright (C) 2010 ST Microelectronics
 * Rajeev Kumar <rajeevkumar.linux@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/clk.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pm_runtime.h>
#include <sound/designware_i2s.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/dmaengine_pcm.h>

/* common register for all channel */
#define IER		0x000
#define IRER		0x004
#define ITER		0x008
#define CER		0x00C
#define CCR		0x010
#define RXFFR		0x014
#define TXFFR		0x018

/* I2STxRxRegisters for all channels */
#define LRBR_LTHR(x)	(0x40 * x + 0x020)
#define RRBR_RTHR(x)	(0x40 * x + 0x024)
#define RER(x)		(0x40 * x + 0x028)
#define TER(x)		(0x40 * x + 0x02C)
#define RCR(x)		(0x40 * x + 0x030)
#define TCR(x)		(0x40 * x + 0x034)
#define ISR(x)		(0x40 * x + 0x038)
#define IMR(x)		(0x40 * x + 0x03C)
#define ROR(x)		(0x40 * x + 0x040)
#define TOR(x)		(0x40 * x + 0x044)
#define RFCR(x)		(0x40 * x + 0x048)
#define TFCR(x)		(0x40 * x + 0x04C)
#define RFF(x)		(0x40 * x + 0x050)
#define TFF(x)		(0x40 * x + 0x054)

/* I2SCOMPRegisters */
#define I2S_COMP_PARAM_2	0x01F0
#define I2S_COMP_PARAM_1	0x01F4
#define I2S_COMP_VERSION	0x01F8
#define I2S_COMP_TYPE		0x01FC

/*
 * Component parameter register fields - define the I2S block's
 * configuration.
 */
#define	COMP1_TX_WORDSIZE_3(r)	(((r) & GENMASK(27, 25)) >> 25)
#define	COMP1_TX_WORDSIZE_2(r)	(((r) & GENMASK(24, 22)) >> 22)
#define	COMP1_TX_WORDSIZE_1(r)	(((r) & GENMASK(21, 19)) >> 19)
#define	COMP1_TX_WORDSIZE_0(r)	(((r) & GENMASK(18, 16)) >> 16)
#define	COMP1_TX_CHANNELS(r)	(((r) & GENMASK(10, 9)) >> 9)
#define	COMP1_RX_CHANNELS(r)	(((r) & GENMASK(8, 7)) >> 7)
#define	COMP1_RX_ENABLED(r)	(((r) & BIT(6)) >> 6)
#define	COMP1_TX_ENABLED(r)	(((r) & BIT(5)) >> 5)
#define	COMP1_MODE_EN(r)	(((r) & BIT(4)) >> 4)
#define	COMP1_FIFO_DEPTH_GLOBAL(r)	(((r) & GENMASK(3, 2)) >> 2)
#define	COMP1_APB_DATA_WIDTH(r)	(((r) & GENMASK(1, 0)) >> 0)

#define	COMP2_RX_WORDSIZE_3(r)	(((r) & GENMASK(12, 10)) >> 10)
#define	COMP2_RX_WORDSIZE_2(r)	(((r) & GENMASK(9, 7)) >> 7)
#define	COMP2_RX_WORDSIZE_1(r)	(((r) & GENMASK(5, 3)) >> 3)
#define	COMP2_RX_WORDSIZE_0(r)	(((r) & GENMASK(2, 0)) >> 0)

/* Number of entries in WORDSIZE and DATA_WIDTH parameter registers */
#define	COMP_MAX_WORDSIZE	(1 << 3)
#define	COMP_MAX_DATA_WIDTH	(1 << 2)

#define MAX_CHANNEL_NUM		8
#define MIN_CHANNEL_NUM		2

/* FPGA Version Info */
#define FPGA_VER_INFO	0xE0011230
#define FPGA_VER_27M	0x000FBED9

/* PLL registers addresses */
#define PLL_IDIV_ADDR	0xE00100A0
#define PLL_FBDIV_ADDR	0xE00100A4
#define PLL_ODIV0_ADDR	0xE00100A8
#define PLL_ODIV1_ADDR	0xE00100AC

/* PCM definitions */
#define BUFFER_BYTES_MAX	384000
#define PERIOD_BYTES_MIN	2048
#define PERIODS_MIN		8

union dw_i2s_snd_dma_data {
	struct i2s_dma_data pd;
	struct snd_dmaengine_dai_dma_data dt;
};

struct dw_pcm_binfo {
	struct snd_pcm_substream *stream;
	unsigned char *dma_base;
	unsigned char *dma_pointer;
	unsigned int period_size_frames;
	unsigned int size;
	snd_pcm_uframes_t period_pointer;
	unsigned int total_periods;
	unsigned int current_period;
};

struct dw_i2s_dev {
	void __iomem *i2s_base;
	struct clk *clk;
	int active;
	unsigned int capability;
	unsigned int quirks;
	unsigned int i2s_reg_comp1;
	unsigned int i2s_reg_comp2;
	struct device *dev;
	u32 ccr;
	u32 xfer_resolution;
	u32 xfer_bytes;
	u32 fifo_th;

	/* data related to DMA transfers b/w i2s and DMAC */
	union dw_i2s_snd_dma_data play_dma_data;
	union dw_i2s_snd_dma_data capture_dma_data;
	struct i2s_clk_config_data config;
	int (*i2s_clk_cfg)(struct i2s_clk_config_data *config);
	struct dw_pcm_binfo binfo;
};

struct dw_i2s_pll {
	unsigned int rate;
	unsigned int data_width;
	unsigned int idiv;
	unsigned int fbdiv;
	unsigned int odiv0;
	unsigned int odiv1;
};

static const struct dw_i2s_pll dw_i2s_pll_cfg_27m[] = {
	/* 27Mhz */
	{ 32000, 16, 0x104, 0x451, 0x10E38, 0x2000 },
	{ 44100, 16, 0x104, 0x596, 0x10D35, 0x2000 },
	{ 48000, 16, 0x208, 0xA28, 0x10B2C, 0x2000 },
	{ 0, 0, 0, 0, 0, 0 },
};

static const struct dw_i2s_pll dw_i2s_pll_cfg_28m[] = {
	/* 28.224Mhz */
	{ 32000, 16, 0x82, 0x105, 0x107DF, 0x2000 },
	{ 44100, 16, 0x28A, 0x1, 0x10001, 0x2000 },
	{ 48000, 16, 0xA28, 0x187, 0x10042, 0x2000 },
	{ 0, 0, 0, 0, 0, 0 },
};

static const struct snd_pcm_hardware dw_pcm_hw = {
	.info       = SNDRV_PCM_INFO_INTERLEAVED |
			SNDRV_PCM_INFO_MMAP |
			SNDRV_PCM_INFO_MMAP_VALID |
			SNDRV_PCM_INFO_BLOCK_TRANSFER,
	.rates      = SNDRV_PCM_RATE_32000 |
			SNDRV_PCM_RATE_44100 |
			SNDRV_PCM_RATE_48000,
	.rate_min   = 32000,
	.rate_max   = 48000,
	.formats    = SNDRV_PCM_FMTBIT_S16_LE,
	.channels_min = 2,
	.channels_max = 2,
	.buffer_bytes_max = BUFFER_BYTES_MAX,
	.period_bytes_min = PERIOD_BYTES_MIN,
	.period_bytes_max = BUFFER_BYTES_MAX / PERIODS_MIN,
	.periods_min      = PERIODS_MIN,
	.periods_max      = BUFFER_BYTES_MAX / PERIOD_BYTES_MIN,
};

static int dw_pcm_transfer(u32 *lsample, u32 *rsample, int bytes, int buf_size,
		struct dw_pcm_binfo *bi)
{
	struct snd_pcm_runtime *rt = NULL;
	int i;

	if (!bi)
		return -EINVAL;

	rt = bi->stream->runtime;

	for (i = 0; i < buf_size; i++) {
		if (bi->stream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
			memcpy(&lsample[i], bi->dma_pointer, bytes);
			bi->dma_pointer += bytes;
			memcpy(&rsample[i], bi->dma_pointer, bytes);
			bi->dma_pointer += bytes;
		} else {
			memcpy(bi->dma_pointer, &lsample[i], bytes);
			bi->dma_pointer += bytes;
			memcpy(bi->dma_pointer, &rsample[i], bytes);
			bi->dma_pointer += bytes;
		}
	}
	bi->period_pointer += bytes_to_frames(rt, bytes * 2 * buf_size);

	if (bi->period_pointer >=
			(bi->period_size_frames * bi->current_period)) {
		bi->current_period++;
		if (bi->current_period > bi->total_periods) {
			bi->dma_pointer = bi->dma_base;
			bi->period_pointer = 0;
			bi->current_period = 1;
		}

		snd_pcm_period_elapsed(bi->stream);
	}

	return 0;
}

static inline void i2s_write_reg(void __iomem *io_base, int reg, u32 val)
{
	writel(val, io_base + reg);
}

static inline u32 i2s_read_reg(void __iomem *io_base, int reg)
{
	return readl(io_base + reg);
}

static inline void i2s_disable_channels(struct dw_i2s_dev *dev, u32 stream)
{
	u32 i = 0;

	if (stream == SNDRV_PCM_STREAM_PLAYBACK) {
		for (i = 0; i < 4; i++)
			i2s_write_reg(dev->i2s_base, TER(i), 0);
	} else {
		for (i = 0; i < 4; i++)
			i2s_write_reg(dev->i2s_base, RER(i), 0);
	}
}

static inline void i2s_clear_irqs(struct dw_i2s_dev *dev, u32 stream)
{
	u32 i = 0;

	if (stream == SNDRV_PCM_STREAM_PLAYBACK) {
		for (i = 0; i < 4; i++)
			i2s_read_reg(dev->i2s_base, TOR(i));
	} else {
		for (i = 0; i < 4; i++)
			i2s_read_reg(dev->i2s_base, ROR(i));
	}
}

static irqreturn_t i2s_irq_handler(int irq, void *dev_id)
{
	struct dw_i2s_dev *dev = dev_id;
	u32 isr[4], sleft[dev->fifo_th], sright[dev->fifo_th];
	int i, j;

	for (i = 0; i < 4; i++)
		isr[i] = i2s_read_reg(dev->i2s_base, ISR(i));

	for (i = 0; i < 4; i++) {
		/* Copy only to/from first two channels.
		   TODO: Remaining channels */
		if ((isr[i] & 0x10) && (i == 0) && (dev->binfo.stream->stream ==
					SNDRV_PCM_STREAM_PLAYBACK)) {
			/* TXFE - TX FIFO is empty */
			dw_pcm_transfer(sleft, sright, dev->xfer_bytes,
					dev->fifo_th, &dev->binfo);

			for (j = 0; j < dev->fifo_th; j++) {
				i2s_write_reg(dev->i2s_base, LRBR_LTHR(i),
						sleft[j]);
				i2s_write_reg(dev->i2s_base, RRBR_RTHR(i),
						sright[j]);
			}
		} else if ((isr[i] & 0x1) && (i == 0) &&
					(dev->binfo.stream->stream ==
					SNDRV_PCM_STREAM_CAPTURE)) {
			/* RSFE - RX FIFO is full */
			for (j = 0; j < dev->fifo_th; j++) {
				sleft[j] = i2s_read_reg(dev->i2s_base,
						LRBR_LTHR(i));
				sright[j] = i2s_read_reg(dev->i2s_base,
						RRBR_RTHR(i));
			}

			dw_pcm_transfer(sleft, sright, dev->xfer_bytes,
					dev->fifo_th, &dev->binfo);
		}
	}

	i2s_clear_irqs(dev, SNDRV_PCM_STREAM_PLAYBACK);
	i2s_clear_irqs(dev, SNDRV_PCM_STREAM_CAPTURE);

	return IRQ_HANDLED;
}

static int i2s_pll_cfg(struct i2s_clk_config_data *config)
{
	const struct dw_i2s_pll *pll_cfg;
	u32 rate = config->sample_rate;
	u32 data_width = config->data_width;
	int i;

	if (readl((void *)FPGA_VER_INFO) <= FPGA_VER_27M)
		pll_cfg = dw_i2s_pll_cfg_27m;
	else
		pll_cfg = dw_i2s_pll_cfg_28m;

	for (i = 0; pll_cfg[i].rate != 0; i++) {
		if ((pll_cfg[i].rate == rate) &&
				(pll_cfg[i].data_width == data_width)) {
			writel(pll_cfg[i].idiv, (void *)PLL_IDIV_ADDR);
			writel(pll_cfg[i].fbdiv, (void *)PLL_FBDIV_ADDR);
			writel(pll_cfg[i].odiv0, (void *)PLL_ODIV0_ADDR);
			writel(pll_cfg[i].odiv1, (void *)PLL_ODIV1_ADDR);
			return 0;
		}
	}

	return -EINVAL;
}

static void i2s_start(struct dw_i2s_dev *dev,
		      struct snd_pcm_substream *substream)
{
	struct i2s_clk_config_data *config = &dev->config;
	u32 i, irq;
	i2s_write_reg(dev->i2s_base, IER, 1);

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		for (i = 0; i < (config->chan_nr / 2); i++) {
			irq = i2s_read_reg(dev->i2s_base, IMR(i));
			i2s_write_reg(dev->i2s_base, IMR(i), irq & ~0x30);
		}
		i2s_write_reg(dev->i2s_base, ITER, 1);
	} else {
		for (i = 0; i < (config->chan_nr / 2); i++) {
			irq = i2s_read_reg(dev->i2s_base, IMR(i));
			i2s_write_reg(dev->i2s_base, IMR(i), irq & ~0x03);
		}
		i2s_write_reg(dev->i2s_base, IRER, 1);
	}

	i2s_write_reg(dev->i2s_base, CER, 1);
}

static void i2s_stop(struct dw_i2s_dev *dev,
		struct snd_pcm_substream *substream)
{
	u32 i = 0, irq;

	i2s_clear_irqs(dev, substream->stream);
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		i2s_write_reg(dev->i2s_base, ITER, 0);

		for (i = 0; i < 4; i++) {
			irq = i2s_read_reg(dev->i2s_base, IMR(i));
			i2s_write_reg(dev->i2s_base, IMR(i), irq | 0x30);
		}
	} else {
		i2s_write_reg(dev->i2s_base, IRER, 0);

		for (i = 0; i < 4; i++) {
			irq = i2s_read_reg(dev->i2s_base, IMR(i));
			i2s_write_reg(dev->i2s_base, IMR(i), irq | 0x03);
		}
	}

	if (!dev->active) {
		i2s_write_reg(dev->i2s_base, CER, 0);
		i2s_write_reg(dev->i2s_base, IER, 0);
	}
}

static int dw_pcm_open(struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct snd_pcm_runtime *rt = substream->runtime;
	struct dw_i2s_dev *dev = snd_soc_dai_get_drvdata(rtd->cpu_dai);

	snd_soc_set_runtime_hwparams(substream, &dw_pcm_hw);
	snd_pcm_hw_constraint_integer(rt, SNDRV_PCM_HW_PARAM_PERIODS);

	rt->hw.rate_min = 32000;
	rt->hw.rate_max = 48000;

	dev->binfo.stream = substream;
	rt->private_data = &dev->binfo;
	return 0;
}

static int dw_pcm_close(struct snd_pcm_substream *substream)
{
	return 0;
}

static int dw_pcm_hw_params(struct snd_pcm_substream *substream,
			    struct snd_pcm_hw_params *hw_params)
{
	struct snd_pcm_runtime *rt = substream->runtime;
	struct dw_pcm_binfo *bi = rt->private_data;
	int ret;

	ret = snd_pcm_lib_alloc_vmalloc_buffer(substream,
			params_buffer_bytes(hw_params));
	if (ret < 0)
		return ret;

	memset(rt->dma_area, 0, params_buffer_bytes(hw_params));
	bi->dma_base = rt->dma_area;
	bi->dma_pointer = bi->dma_base;

	return 0;
}

static int dw_pcm_hw_free(struct snd_pcm_substream *substream)
{
	int ret;

	ret = snd_pcm_lib_free_vmalloc_buffer(substream);
	if (ret < 0)
		return ret;

	return 0;
}

static int dw_pcm_prepare(struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *rt = substream->runtime;
	struct dw_pcm_binfo *bi = rt->private_data;
	u32 buffer_size_frames = 0;

	bi->period_size_frames = bytes_to_frames(rt,
			snd_pcm_lib_period_bytes(substream));
	bi->size = snd_pcm_lib_buffer_bytes(substream);
	buffer_size_frames = bytes_to_frames(rt, bi->size);
	bi->total_periods = buffer_size_frames / bi->period_size_frames;
	bi->current_period = 1;

	if ((buffer_size_frames % bi->period_size_frames) != 0)
		return -EINVAL;

	return 0;
}

static int dw_pcm_trigger(struct snd_pcm_substream *substream, int cmd)
{
	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
		break;
	case SNDRV_PCM_TRIGGER_STOP:
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static snd_pcm_uframes_t dw_pcm_pointer(struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *rt = substream->runtime;
	struct dw_pcm_binfo *bi = rt->private_data;

	return bi->period_pointer;
}

static struct snd_pcm_ops dw_pcm_ops = {
	.open      = dw_pcm_open,
	.close     = dw_pcm_close,
	.ioctl     = snd_pcm_lib_ioctl,
	.hw_params = dw_pcm_hw_params,
	.hw_free   = dw_pcm_hw_free,
	.prepare   = dw_pcm_prepare,
	.trigger   = dw_pcm_trigger,
	.pointer   = dw_pcm_pointer,
	.page      = snd_pcm_lib_get_vmalloc_page,
	.mmap      = snd_pcm_lib_mmap_vmalloc,
};

static int dw_pcm_new(struct snd_soc_pcm_runtime *runtime)
{
	struct snd_pcm *pcm = runtime->pcm;
	int ret;

	ret =  snd_pcm_lib_preallocate_pages_for_all(pcm,
			SNDRV_DMA_TYPE_DEV,
			snd_dma_continuous_data(GFP_KERNEL),
			dw_pcm_hw.buffer_bytes_max,
			dw_pcm_hw.buffer_bytes_max);
	if (ret < 0)
		return ret;

	return 0;
}

static void dw_pcm_free(struct snd_pcm *pcm)
{
	snd_pcm_lib_preallocate_free_for_all(pcm);
}

static struct snd_soc_platform_driver dw_pcm_soc_platform = {
	.pcm_new  = dw_pcm_new,
	.pcm_free = dw_pcm_free,
	.ops = &dw_pcm_ops,
};

static int dw_i2s_startup(struct snd_pcm_substream *substream,
		struct snd_soc_dai *cpu_dai)
{
	struct dw_i2s_dev *dev = snd_soc_dai_get_drvdata(cpu_dai);
	union dw_i2s_snd_dma_data *dma_data = NULL;

	if (!(dev->capability & DWC_I2S_RECORD) &&
			(substream->stream == SNDRV_PCM_STREAM_CAPTURE))
		return -EINVAL;

	if (!(dev->capability & DWC_I2S_PLAY) &&
			(substream->stream == SNDRV_PCM_STREAM_PLAYBACK))
		return -EINVAL;

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		dma_data = &dev->play_dma_data;
	else if (substream->stream == SNDRV_PCM_STREAM_CAPTURE)
		dma_data = &dev->capture_dma_data;

	snd_soc_dai_set_dma_data(cpu_dai, substream, (void *)dma_data);

	return 0;
}

static void dw_i2s_config(struct dw_i2s_dev *dev, int stream)
{
	u32 ch_reg, irq;
	struct i2s_clk_config_data *config = &dev->config;


	i2s_disable_channels(dev, stream);

	for (ch_reg = 0; ch_reg < (config->chan_nr / 2); ch_reg++) {
		if (stream == SNDRV_PCM_STREAM_PLAYBACK) {
			i2s_write_reg(dev->i2s_base, TCR(ch_reg),
				      dev->xfer_resolution);
			i2s_write_reg(dev->i2s_base, TFCR(ch_reg),
				      dev->fifo_th - 1);
			irq = i2s_read_reg(dev->i2s_base, IMR(ch_reg));
			i2s_write_reg(dev->i2s_base, IMR(ch_reg), irq & ~0x30);
			i2s_write_reg(dev->i2s_base, TER(ch_reg), 1);
		} else {
			i2s_write_reg(dev->i2s_base, RCR(ch_reg),
				      dev->xfer_resolution);
			i2s_write_reg(dev->i2s_base, RFCR(ch_reg),
				      dev->fifo_th - 1);
			irq = i2s_read_reg(dev->i2s_base, IMR(ch_reg));
			i2s_write_reg(dev->i2s_base, IMR(ch_reg), irq & ~0x03);
			i2s_write_reg(dev->i2s_base, RER(ch_reg), 1);
		}

	}
}

static int dw_i2s_hw_params(struct snd_pcm_substream *substream,
		struct snd_pcm_hw_params *params, struct snd_soc_dai *dai)
{
	struct dw_i2s_dev *dev = snd_soc_dai_get_drvdata(dai);
	struct i2s_clk_config_data *config = &dev->config;
	int ret;

	switch (params_format(params)) {
	case SNDRV_PCM_FORMAT_S16_LE:
		config->data_width = 16;
		dev->ccr = 0x00;
		dev->xfer_resolution = 0x02;
		dev->xfer_bytes = 0x02;
		break;

	case SNDRV_PCM_FORMAT_S24_LE:
		config->data_width = 24;
		dev->ccr = 0x08;
		dev->xfer_resolution = 0x04;
		dev->xfer_bytes = 0x03;
		break;

	case SNDRV_PCM_FORMAT_S32_LE:
		config->data_width = 32;
		dev->ccr = 0x10;
		dev->xfer_resolution = 0x05;
		dev->xfer_bytes = 0x04;
		break;

	default:
		dev_err(dev->dev, "designware-i2s: unsupported PCM fmt");
		return -EINVAL;
	}

	config->chan_nr = params_channels(params);

	switch (config->chan_nr) {
	case EIGHT_CHANNEL_SUPPORT:
	case SIX_CHANNEL_SUPPORT:
	case FOUR_CHANNEL_SUPPORT:
	case TWO_CHANNEL_SUPPORT:
		break;
	default:
		dev_err(dev->dev, "channel not supported\n");
		return -EINVAL;
	}

	dw_i2s_config(dev, substream->stream);

	i2s_write_reg(dev->i2s_base, CCR, dev->ccr);

	config->sample_rate = params_rate(params);

	if (dev->capability & DW_I2S_MASTER) {
		if (dev->i2s_clk_cfg) {
			ret = dev->i2s_clk_cfg(config);
			if (ret < 0) {
				dev_err(dev->dev, "runtime audio clk config fail\n");
				return ret;
			}
		} else {
			u32 bitclk = config->sample_rate *
					config->data_width * 2;

			ret = clk_set_rate(dev->clk, bitclk);
			if (ret) {
				dev_err(dev->dev, "Can't set I2S clock rate: %d\n",
					ret);
				return ret;
			}
		}
	}

	return 0;
}

static void dw_i2s_shutdown(struct snd_pcm_substream *substream,
		struct snd_soc_dai *dai)
{
	snd_soc_dai_set_dma_data(dai, substream, NULL);
}

static int dw_i2s_prepare(struct snd_pcm_substream *substream,
			  struct snd_soc_dai *dai)
{
	struct dw_i2s_dev *dev = snd_soc_dai_get_drvdata(dai);

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		i2s_write_reg(dev->i2s_base, TXFFR, 1);
	else
		i2s_write_reg(dev->i2s_base, RXFFR, 1);

	return 0;
}

static int dw_i2s_trigger(struct snd_pcm_substream *substream,
		int cmd, struct snd_soc_dai *dai)
{
	struct dw_i2s_dev *dev = snd_soc_dai_get_drvdata(dai);
	int ret = 0;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_RESUME:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
		dev->active++;
		i2s_start(dev, substream);
		break;

	case SNDRV_PCM_TRIGGER_STOP:
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
		dev->active--;
		i2s_stop(dev, substream);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int dw_i2s_set_fmt(struct snd_soc_dai *cpu_dai, unsigned int fmt)
{
	struct dw_i2s_dev *dev = snd_soc_dai_get_drvdata(cpu_dai);
	int ret = 0;

	switch (fmt & SND_SOC_DAIFMT_MASTER_MASK) {
	case SND_SOC_DAIFMT_CBM_CFM:
		if (dev->capability & DW_I2S_SLAVE)
			ret = 0;
		else
			ret = -EINVAL;
		break;
	case SND_SOC_DAIFMT_CBS_CFS:
		if (dev->capability & DW_I2S_MASTER)
			ret = 0;
		else
			ret = -EINVAL;
		break;
	case SND_SOC_DAIFMT_CBM_CFS:
	case SND_SOC_DAIFMT_CBS_CFM:
		ret = -EINVAL;
		break;
	default:
		dev_dbg(dev->dev, "dwc : Invalid master/slave format\n");
		ret = -EINVAL;
		break;
	}
	return ret;
}

static struct snd_soc_dai_ops dw_i2s_dai_ops = {
	.startup	= dw_i2s_startup,
	.shutdown	= dw_i2s_shutdown,
	.hw_params	= dw_i2s_hw_params,
	.prepare	= dw_i2s_prepare,
	.trigger	= dw_i2s_trigger,
	.set_fmt	= dw_i2s_set_fmt,
};

static const struct snd_soc_component_driver dw_i2s_component = {
	.name		= "dw-i2s",
};

#ifdef CONFIG_PM
static int dw_i2s_runtime_suspend(struct device *dev)
{
	struct dw_i2s_dev *dw_dev = dev_get_drvdata(dev);

	if (dw_dev->capability & DW_I2S_MASTER)
		clk_disable(dw_dev->clk);
	return 0;
}

static int dw_i2s_runtime_resume(struct device *dev)
{
	struct dw_i2s_dev *dw_dev = dev_get_drvdata(dev);

	if (dw_dev->capability & DW_I2S_MASTER)
		clk_enable(dw_dev->clk);
	return 0;
}

static int dw_i2s_suspend(struct snd_soc_dai *dai)
{
	struct dw_i2s_dev *dev = snd_soc_dai_get_drvdata(dai);

	if (dev->capability & DW_I2S_MASTER)
		clk_disable(dev->clk);
	return 0;
}

static int dw_i2s_resume(struct snd_soc_dai *dai)
{
	struct dw_i2s_dev *dev = snd_soc_dai_get_drvdata(dai);

	if (dev->capability & DW_I2S_MASTER)
		clk_enable(dev->clk);

	if (dai->playback_active)
		dw_i2s_config(dev, SNDRV_PCM_STREAM_PLAYBACK);
	if (dai->capture_active)
		dw_i2s_config(dev, SNDRV_PCM_STREAM_CAPTURE);
	return 0;
}

#else
#define dw_i2s_suspend	NULL
#define dw_i2s_resume	NULL
#endif

/*
 * The following tables allow a direct lookup of various parameters
 * defined in the I2S block's configuration in terms of sound system
 * parameters.  Each table is sized to the number of entries possible
 * according to the number of configuration bits describing an I2S
 * block parameter.
 */

/* Maximum bit resolution of a channel - not uniformly spaced */
static const u32 fifo_width[COMP_MAX_WORDSIZE] = {
	12, 16, 20, 24, 32, 0, 0, 0
};

/* Width of (DMA) bus */
static const u32 bus_widths[COMP_MAX_DATA_WIDTH] = {
	DMA_SLAVE_BUSWIDTH_1_BYTE,
	DMA_SLAVE_BUSWIDTH_2_BYTES,
	DMA_SLAVE_BUSWIDTH_4_BYTES,
	DMA_SLAVE_BUSWIDTH_UNDEFINED
};

static int dw_configure_dai(struct dw_i2s_dev *dev,
				   struct snd_soc_dai_driver *dw_i2s_dai,
				   unsigned int rates)
{
	/*
	 * Read component parameter registers to extract
	 * the I2S block's configuration.
	 */
	u32 comp1 = i2s_read_reg(dev->i2s_base, dev->i2s_reg_comp1);
	u32 fifo_depth = 1 << (1 + COMP1_FIFO_DEPTH_GLOBAL(comp1));

	if (dev->capability & DWC_I2S_RECORD &&
			dev->quirks & DW_I2S_QUIRK_COMP_PARAM1)
		comp1 = comp1 & ~BIT(5);

	if (COMP1_TX_ENABLED(comp1)) {
		dev_dbg(dev->dev, " designware: play supported\n");
		dw_i2s_dai->playback.channels_min = MIN_CHANNEL_NUM;
		dw_i2s_dai->playback.channels_max =
				1 << (COMP1_TX_CHANNELS(comp1) + 1);
		dw_i2s_dai->playback.formats = SNDRV_PCM_FMTBIT_S16_LE |
				SNDRV_PCM_FMTBIT_S24_LE |
				SNDRV_PCM_FMTBIT_S32_LE;
		dw_i2s_dai->playback.rates = rates;
	}

	if (COMP1_RX_ENABLED(comp1)) {
		dev_dbg(dev->dev, "designware: record supported\n");
		dw_i2s_dai->capture.channels_min = MIN_CHANNEL_NUM;
		dw_i2s_dai->capture.channels_max =
				1 << (COMP1_RX_CHANNELS(comp1) + 1);
		dw_i2s_dai->capture.formats = SNDRV_PCM_FMTBIT_S16_LE |
				SNDRV_PCM_FMTBIT_S24_LE |
				SNDRV_PCM_FMTBIT_S32_LE;
		dw_i2s_dai->capture.rates = rates;
	}

	if (COMP1_MODE_EN(comp1)) {
		dev_dbg(dev->dev, "designware: i2s master mode supported\n");
		dev->capability |= DW_I2S_MASTER;
	} else {
		dev_dbg(dev->dev, "designware: i2s slave mode supported\n");
		dev->capability |= DW_I2S_SLAVE;
	}

	dev->fifo_th = fifo_depth / 2;
	return 0;
}

static int dw_configure_dai_by_pd(struct dw_i2s_dev *dev,
				   struct snd_soc_dai_driver *dw_i2s_dai,
				   struct resource *res,
				   const struct i2s_platform_data *pdata)
{
	u32 comp1 = i2s_read_reg(dev->i2s_base, dev->i2s_reg_comp1);
	u32 idx = COMP1_APB_DATA_WIDTH(comp1);
	int ret;

	if (WARN_ON(idx >= ARRAY_SIZE(bus_widths)))
		return -EINVAL;

	ret = dw_configure_dai(dev, dw_i2s_dai, pdata->snd_rates);
	if (ret < 0)
		return ret;

	/* Set DMA slaves info */
	dev->play_dma_data.pd.data = pdata->play_dma_data;
	dev->capture_dma_data.pd.data = pdata->capture_dma_data;
	dev->play_dma_data.pd.addr = res->start + I2S_TXDMA;
	dev->capture_dma_data.pd.addr = res->start + I2S_RXDMA;
	dev->play_dma_data.pd.max_burst = 16;
	dev->capture_dma_data.pd.max_burst = 16;
	dev->play_dma_data.pd.addr_width = bus_widths[idx];
	dev->capture_dma_data.pd.addr_width = bus_widths[idx];
	dev->play_dma_data.pd.filter = pdata->filter;
	dev->capture_dma_data.pd.filter = pdata->filter;

	return 0;
}

static int dw_configure_dai_by_dt(struct dw_i2s_dev *dev,
				   struct snd_soc_dai_driver *dw_i2s_dai,
				   struct resource *res)
{
	u32 comp1 = i2s_read_reg(dev->i2s_base, I2S_COMP_PARAM_1);
	u32 comp2 = i2s_read_reg(dev->i2s_base, I2S_COMP_PARAM_2);
	u32 fifo_depth = 1 << (1 + COMP1_FIFO_DEPTH_GLOBAL(comp1));
	u32 idx = COMP1_APB_DATA_WIDTH(comp1);
	u32 idx2;
	int ret;

	if (WARN_ON(idx >= ARRAY_SIZE(bus_widths)))
		return -EINVAL;

	ret = dw_configure_dai(dev, dw_i2s_dai, SNDRV_PCM_RATE_8000_192000);
	if (ret < 0)
		return ret;

	if (COMP1_TX_ENABLED(comp1)) {
		idx2 = COMP1_TX_WORDSIZE_0(comp1);

		dev->capability |= DWC_I2S_PLAY;
		dev->play_dma_data.dt.addr = res->start + I2S_TXDMA;
		dev->play_dma_data.dt.addr_width = bus_widths[idx];
		dev->play_dma_data.dt.chan_name = "TX";
		dev->play_dma_data.dt.fifo_size = fifo_depth *
			(fifo_width[idx2]) >> 8;
		dev->play_dma_data.dt.maxburst = 16;
	}
	if (COMP1_RX_ENABLED(comp1)) {
		idx2 = COMP2_RX_WORDSIZE_0(comp2);

		dev->capability |= DWC_I2S_RECORD;
		dev->capture_dma_data.dt.addr = res->start + I2S_RXDMA;
		dev->capture_dma_data.dt.addr_width = bus_widths[idx];
		dev->capture_dma_data.dt.chan_name = "RX";
		dev->capture_dma_data.dt.fifo_size = fifo_depth *
			(fifo_width[idx2] >> 8);
		dev->capture_dma_data.dt.maxburst = 16;
	}

	return 0;

}

static int dw_i2s_probe(struct platform_device *pdev)
{
	const struct i2s_platform_data *pdata = pdev->dev.platform_data;
	struct dw_i2s_dev *dev;
	struct resource *res;
	int ret, irq_number;
	struct snd_soc_dai_driver *dw_i2s_dai;
	const char *clk_id;

	dev = devm_kzalloc(&pdev->dev, sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		dev_warn(&pdev->dev, "kzalloc fail\n");
		return -ENOMEM;
	}

	dw_i2s_dai = devm_kzalloc(&pdev->dev, sizeof(*dw_i2s_dai), GFP_KERNEL);
	if (!dw_i2s_dai)
		return -ENOMEM;

	dw_i2s_dai->ops = &dw_i2s_dai_ops;
	dw_i2s_dai->suspend = dw_i2s_suspend;
	dw_i2s_dai->resume = dw_i2s_resume;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	dev->i2s_base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(dev->i2s_base))
		return PTR_ERR(dev->i2s_base);

	irq_number = platform_get_irq(pdev, 0);
	if (irq_number <= 0) {
		dev_err(&pdev->dev, "get irq fail\n");
		return -EINVAL;
	}

	ret = devm_request_irq(&pdev->dev, irq_number, i2s_irq_handler,
			IRQF_SHARED, "dw_i2s_irq_handler", dev);
	if (ret < 0) {
		dev_err(&pdev->dev, "request irq fail\n");
		return ret;
	}

	dev->dev = &pdev->dev;

	dev->i2s_reg_comp1 = I2S_COMP_PARAM_1;
	dev->i2s_reg_comp2 = I2S_COMP_PARAM_2;
	if (pdata) {
		dev->capability = pdata->cap;
		clk_id = NULL;
		dev->quirks = pdata->quirks;
		if (dev->quirks & DW_I2S_QUIRK_COMP_REG_OFFSET) {
			dev->i2s_reg_comp1 = pdata->i2s_reg_comp1;
			dev->i2s_reg_comp2 = pdata->i2s_reg_comp2;
		}
		ret = dw_configure_dai_by_pd(dev, dw_i2s_dai, res, pdata);
	} else {
		clk_id = "i2sclk";
		ret = dw_configure_dai_by_dt(dev, dw_i2s_dai, res);
	}
	if (ret < 0)
		return ret;

	if (dev->capability & DW_I2S_MASTER) {
		if (pdata) {
			dev->i2s_clk_cfg = pdata->i2s_clk_cfg;
			if (!dev->i2s_clk_cfg) {
				dev_err(&pdev->dev, "no clock configure method\n");
				return -ENODEV;
			}
		}

		if (dev->i2s_clk_cfg ||
				of_get_property(pdev->dev.of_node, "clocks", NULL)) {
			dev->clk = devm_clk_get(&pdev->dev, clk_id);

			if (IS_ERR(dev->clk))
				return PTR_ERR(dev->clk);

			ret = clk_prepare_enable(dev->clk);
			if (ret < 0)
				return ret;
		} else {
			/* Use internal PLL config */
			dev->i2s_clk_cfg = i2s_pll_cfg;
			dev->clk = NULL;
		}
	}

	dev_set_drvdata(&pdev->dev, dev);
	ret = devm_snd_soc_register_component(&pdev->dev, &dw_i2s_component,
					 dw_i2s_dai, 1);
	if (ret != 0) {
		dev_err(&pdev->dev, "not able to register dai\n");
		goto err_clk_disable;
	}

	if (!pdata) {
		if (of_get_property(pdev->dev.of_node, "dmas", NULL)) {
			/* Using DMA */
			ret = devm_snd_dmaengine_pcm_register(&pdev->dev, NULL, 0);
		} else {
			ret = snd_soc_register_platform(&pdev->dev,
					&dw_pcm_soc_platform);
		}

		if (ret) {
			dev_err(&pdev->dev,
				"Could not register PCM: %d\n", ret);
			goto err_clk_disable;
		}
	}
	pm_runtime_enable(&pdev->dev);
	return 0;

err_clk_disable:
	if (dev->capability & DW_I2S_MASTER)
		clk_disable_unprepare(dev->clk);
	return ret;
}

static int dw_i2s_remove(struct platform_device *pdev)
{
	struct dw_i2s_dev *dev = dev_get_drvdata(&pdev->dev);

	if (dev->capability & DW_I2S_MASTER)
		clk_disable_unprepare(dev->clk);

	pm_runtime_disable(&pdev->dev);
	snd_soc_unregister_platform(&pdev->dev);
	return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id dw_i2s_of_match[] = {
	{ .compatible = "snps,designware-i2s", },
	{},
};

MODULE_DEVICE_TABLE(of, dw_i2s_of_match);
#endif

static const struct dev_pm_ops dwc_pm_ops = {
	SET_RUNTIME_PM_OPS(dw_i2s_runtime_suspend, dw_i2s_runtime_resume, NULL)
};

static struct platform_driver dw_i2s_driver = {
	.probe		= dw_i2s_probe,
	.remove		= dw_i2s_remove,
	.driver		= {
		.name	= "designware-i2s",
		.of_match_table = of_match_ptr(dw_i2s_of_match),
		.pm = &dwc_pm_ops,
	},
};

module_platform_driver(dw_i2s_driver);

MODULE_AUTHOR("Rajeev Kumar <rajeevkumar.linux@gmail.com>");
MODULE_DESCRIPTION("DESIGNWARE I2S SoC Interface");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:designware_i2s");
