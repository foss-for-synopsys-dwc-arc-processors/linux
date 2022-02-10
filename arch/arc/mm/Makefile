# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
#

obj-y	:= extable.o ioremap.o dma.o fault.o init.o mmap.o

ifdef CONFIG_ARC_MMU_HW_WALK
obj-y	+= tlb-hwalk.o
else
obj-y	+= tlb.o tlbex.o
endif

ifdef CONFIG_ISA_ARCV3
obj-y	+= cache-hwalk.o
else
obj-y	+= cache.o
endif

obj-$(CONFIG_HIGHMEM)	+= highmem.o
