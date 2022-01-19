# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
#

KBUILD_DEFCONFIG := haps_hs_smp_defconfig

ifeq ($(CROSS_COMPILE),)
ifdef CONFIG_ISA_ARCV3
CROSS_COMPILE := $(call cc-cross-prefix, arc64-elf- arc64-linux-gnu- arc64-linux- arc64-unknown-linux-gnu-)
ifdef CONFIG_64BIT
UTS_MACHINE	:= arc64
else
UTS_MACHINE	:= arc32
endif
else
CROSS_COMPILE := $(call cc-cross-prefix, arc-elf32- arc-linux- arceb-linux-)
endif
endif

tune-mcpu-def-$(CONFIG_ISA_ARCOMPACT)	:= -mA7
tune-mcpu-def-$(CONFIG_ISA_ARCV2)	:= -mcpu=hs38

ifdef CONFIG_64BIT
tune-mcpu-def-$(CONFIG_ISA_ARCV3)	:= -mcpu=hs6x
else
tune-mcpu-def-$(CONFIG_ISA_ARCV3)	:= -mcpu=hs5x
ldflags-$(CONFIG_ISA_ARCV3)		+= -marc64elf32
endif

ifeq ($(CONFIG_ARC_TUNE_MCPU),"")
cflags-y				+= $(tune-mcpu-def-y)
else
tune-mcpu				:= $(shell echo $(CONFIG_ARC_TUNE_MCPU))
tune-mcpu-ok 				:= $(call cc-option-yn, $(tune-mcpu))
ifeq ($(tune-mcpu-ok),y)
cflags-y				+= $(tune-mcpu)
else
# The flag provided by 'CONFIG_ARC_TUNE_MCPU' option isn't known by this compiler
# (probably the compiler is too old). Use ISA default mcpu flag instead as a safe option.
$(warning ** WARNING ** CONFIG_ARC_TUNE_MCPU flag '$(tune-mcpu)' is unknown, fallback to '$(tune-mcpu-def-y)')
cflags-y				+= $(tune-mcpu-def-y)
endif
endif

cflags-y	+= -fno-common -pipe -fno-builtin -D__linux__
ifndef CONFIG_ISA_ARCV3
cflags-y	+= -fsection-anchors -mno-sdata -mmedium-calls
else
cflags-$(CONFIG_64BIT)		+= 	-mcmodel=large
cflags-$(CONFIG_ARC_HAS_LL128)	+= 	-m128
endif
cflags-y	+= -Wa,-I$(srctree)/arch/arc/include

ifdef CONFIG_ARC_CURR_IN_REG
# For a global register defintion, make sure it gets passed to every file
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

ifdef CONFIG_ISA_ARCV2

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

# See arch/arc/Kbuild for content of core part of the kernel
core-y		+= arch/arc/

# w/o this dtb won't embed into kernel binary
core-y		+= arch/arc/boot/dts/

core-y				+= arch/arc/plat-sim/
core-$(CONFIG_ARC_PLAT_TB10X)	+= arch/arc/plat-tb10x/
core-$(CONFIG_ARC_PLAT_AXS10X)	+= arch/arc/plat-axs10x/
core-$(CONFIG_ARC_PLAT_EZNPS)	+= arch/arc/plat-eznps/
core-$(CONFIG_ARC_SOC_HSDK)	+= arch/arc/plat-hsdk/

ifdef CONFIG_ARC_PLAT_EZNPS
KBUILD_CPPFLAGS += -I$(srctree)/arch/arc/plat-eznps/include
endif

drivers-$(CONFIG_OPROFILE)	+= arch/arc/oprofile/

libs-y		+= arch/arc/lib/ $(LIBGCC)

boot		:= arch/arc/boot

#default target for make without any arguments.
KBUILD_IMAGE	:= $(boot)/bootpImage

all:	bootpImage
bootpImage: vmlinux

boot_targets += uImage uImage.bin uImage.gz loader

$(boot_targets): vmlinux
	$(Q)$(MAKE) $(build)=$(boot) $(boot)/$@

archclean:
	$(Q)$(MAKE) $(clean)=$(boot)
