# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
#

KBUILD_DEFCONFIG := haps_hs_smp_defconfig

ifdef cross_compiling
ifeq ($(CROSS_COMPILE),)
ifdef CONFIG_ISA_ARCV3
ifdef CONFIG_64BIT
CROSS_COMPILE := $(call cc-cross-prefix, arc64-elf- arc64-linux-gnu- arc64-linux- arc64-unknown-linux-gnu-)
else
CROSS_COMPILE := $(call cc-cross-prefix, arc64-elf- arc32-linux-gnu- arc32-linux- arc32-unknown-linux-gnu-)
endif
else
CROSS_COMPILE := $(call cc-cross-prefix, arc-elf32- arc-linux- arceb-linux-)
endif
endif
endif

ifdef CONFIG_ISA_ARCV3
ifdef CONFIG_64BIT
UTS_MACHINE	:= arc64
else
UTS_MACHINE	:= arc32
endif
endif

tune-mcpu-def-$(CONFIG_ISA_ARCOMPACT)	:= -mcpu=arc700
tune-mcpu-def-$(CONFIG_ISA_ARCV2)	:= -mcpu=hs38
ifdef CONFIG_64BIT
tune-mcpu-def-$(CONFIG_ISA_ARCV3)	:= -mcpu=hs6x
else
tune-mcpu-def-$(CONFIG_ISA_ARCV3)	:= -mcpu=hs5x
ldflags-$(CONFIG_ISA_ARCV3)		+= -marc64elf32
endif

tune-mcpu				:= $(shell echo $(CONFIG_ARC_TUNE_MCPU))
ifneq ($(tune-mcpu),)
ifeq ($(call cc-option,$(tune-mcpu)),)
# The flag provided by 'CONFIG_ARC_TUNE_MCPU' option isn't known by this compiler
# (probably the compiler is too old). Use ISA default mcpu flag instead as a safe option.
$(warning ** WARNING ** CONFIG_ARC_TUNE_MCPU flag '$(tune-mcpu)' is unknown, fallback to '$(tune-mcpu-def-y)')
tune-mcpu				:= $(tune-mcpu-def-y)
endif
else
tune-mcpu				:= $(tune-mcpu-def-y)
endif

cflags-y				+= $(tune-mcpu)

cflags-y	+= -fno-common -pipe -fno-builtin -D__linux__

ifneq ($(filter y,$(CONFIG_ISA_ARCOMPACT)  $(CONFIG_ISA_ARCV2)),)
cflags-y	+= -fsection-anchors -mno-sdata -mmedium-calls
endif

ifdef CONFIG_ISA_ARCV3
cflags-$(CONFIG_64BIT)		+= 	-mcmodel=large
cflags-$(CONFIG_ARC_HAS_LL128)	+= 	-m128
endif

cflags-y	+= -Wa,-I$(srctree)/arch/arc/include

ifdef CONFIG_ARC_CURR_IN_REG
# For a global register definition, make sure it gets passed to every file
# We had a customer reported bug where some code built in kernel was NOT using
# any kernel headers, and missing the global register
# Can't do unconditionally because of recursive include issues
# due to <linux/thread_info.h>
LINUXINCLUDE	+=  -include $(srctree)/arch/arc/include/asm/current.h
cflags-y	+= -ffixed-gp
endif

ifndef CONFIG_ISA_ARCV3
cflags-$(CONFIG_ARC_HAS_LLSC)		+= -mlock
cflags-$(CONFIG_ARC_HAS_SWAPE)		+= -mswape
endif

cflags-$(CONFIG_ARC_LACKS_ZOL)		+= -fno-branch-count-reg

ifdef CONFIG_ARC_HAS_DIV_REM
cflags-y				+= -mdiv-rem
else
cflags-y				+= -mno-div-rem
endif

ifneq ($(filter y,$(CONFIG_ISA_ARCV2)  $(CONFIG_ISA_ARCV3)),)

ifdef CONFIG_ARC_USE_UNALIGNED_MEM_ACCESS
cflags-y				+= -munaligned-access
else
cflags-y				+= -mno-unaligned-access
endif

ifndef CONFIG_ARC_HAS_LL64
cflags-y				+= -mno-ll64
endif

endif

cfi := $(call as-instr,.cfi_startproc\n.cfi_endproc,-DARC_DW2_UNWIND_AS_CFI)
cflags-$(CONFIG_ARC_DW2_UNWIND)		+= -fasynchronous-unwind-tables $(cfi)

cflags-$(CONFIG_CPU_BIG_ENDIAN)		+= -mbig-endian
ldflags-$(CONFIG_CPU_BIG_ENDIAN)	+= -EB

LIBGCC	= $(shell $(CC) $(cflags-y) --print-libgcc-file-name)

# Modules with short calls might break for calls into builtin-kernel
ifndef CONFIG_ISA_ARCV3
KBUILD_CFLAGS_MODULE	+= -mlong-calls -mno-millicode
else
KBUILD_CFLAGS_MODULE	+= -mcmodel=large
endif

# Finally dump eveything into kernel build system
KBUILD_CFLAGS	+= $(cflags-y)
KBUILD_AFLAGS	+= $(KBUILD_CFLAGS)
KBUILD_LDFLAGS	+= $(ldflags-y)

head-y		:= arch/arc/kernel/head.o

# w/o this dtb won't embed into kernel binary
core-y		+= arch/arc/boot/dts/

core-y				+= arch/arc/plat-sim/
core-$(CONFIG_ARC_PLAT_TB10X)	+= arch/arc/plat-tb10x/
core-$(CONFIG_ARC_PLAT_AXS10X)	+= arch/arc/plat-axs10x/
core-$(CONFIG_ARC_SOC_HSDK)	+= arch/arc/plat-hsdk/

libs-y		+= arch/arc/lib/ $(LIBGCC)

boot		:= arch/arc/boot

boot_targets := uImage.bin uImage.gz uImage.lzma loader

PHONY += $(boot_targets)
$(boot_targets): vmlinux
	$(Q)$(MAKE) $(build)=$(boot) $(boot)/$@

uimage-default-y			:= uImage.bin
uimage-default-$(CONFIG_KERNEL_GZIP)	:= uImage.gz
uimage-default-$(CONFIG_KERNEL_LZMA)	:= uImage.lzma

PHONY += uImage
uImage: $(uimage-default-y)
	@ln -sf $< $(boot)/uImage
	@$(kecho) '  Image $(boot)/uImage is ready'

CLEAN_FILES += $(boot)/uImage
