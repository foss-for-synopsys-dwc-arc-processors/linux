/*******************************************************************************

  Copyright(c) 2012 EZchip Technologies.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

*******************************************************************************/

/* Some notes on DMA <=> kernel address generation
 *
 * A simplistic implementation will generate 0 based bus address.
 * For e.g. 0x8AAA_0000 becomes 0x0AAA_0000 bus addr
 *
 * As a small optimisation, if PCI is not enabled we can simply return
 * 0 based bus addr hence the CONFIG_xx check for PCI Host Bridge
 */

#ifndef __PLAT_DMA_ADDR_H
#define __PLAT_DMA_ADDR_H

#include <linux/device.h>

static inline unsigned long plat_dma_addr_to_kernel(struct device *dev,
						    dma_addr_t dma_addr)
{
	return dma_addr + PAGE_OFFSET;
}

static inline dma_addr_t plat_kernel_addr_to_dma(struct device *dev, void *ptr)
{
	unsigned long addr = (unsigned long)ptr;
	/*
	 * To Catch buggy drivers which can call DMA map API with kernel vaddr
	 * i.e. for buffers alloc via vmalloc or ioremap which are not
	 * gaurnateed to be PHY contiguous and hence unfit for DMA anyways.
	 * On ARC kernel virtual address is 0x7000_0000 to 0x7FFF_FFFF, so
	 * ideally we want to check this range here, but our implementation is
	 * better as it checks for even worse user virtual address as well.
	 */
	BUG_ON(addr < PAGE_OFFSET);

	return addr - PAGE_OFFSET;
}

#endif
