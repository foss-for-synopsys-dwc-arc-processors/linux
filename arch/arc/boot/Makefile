# SPDX-License-Identifier: GPL-2.0
targets := vmlinux.bin vmlinux.bin.gz uImage loader

# uImage build relies on mkimage being availble on your host for ARC target
# You will need to build u-boot for ARC, rename mkimage to arc-elf32-mkimage
# and make sure it's reacable from your PATH

OBJCOPYFLAGS= -O binary -R .note -R .note.gnu.build-id -R .comment -S

LINUX_ENTRY_VIRT = 0x$(shell $(NM) vmlinux | awk '$$NF == "res_service" {print $$1}')

ifeq ($(CONFIG_ISA_ARCV3),y)
$(obj)/uImage*: $(obj)/loader
LINUX_ENTRY_PHY = 0x$(shell $(NM) $(obj)/loader | awk '$$NF == "_entry_point" {print $$1}')
else
LINUX_ENTRY_PHY = $(LINUX_ENTRY_VIRT)
endif

UIMAGE_LOADADDR    = $(CONFIG_LINUX_LINK_BASE)
UIMAGE_ENTRYADDR   = $(LINUX_ENTRY_PHY)

suffix-y := bin
suffix-$(CONFIG_KERNEL_GZIP)	:= gz
suffix-$(CONFIG_KERNEL_LZMA)	:= lzma

targets += uImage
targets += uImage.bin
targets += uImage.gz
targets += uImage.lzma
extra-y += vmlinux.bin
extra-y += vmlinux.bin.gz
extra-y += vmlinux.bin.lzma

$(obj)/vmlinux.bin: vmlinux FORCE
	$(call if_changed,objcopy)

$(obj)/vmlinux.bin.gz: $(obj)/vmlinux.bin FORCE
	$(call if_changed,gzip)

$(obj)/vmlinux.bin.lzma: $(obj)/vmlinux.bin FORCE
	$(call if_changed,lzma)

$(obj)/uImage.bin: $(obj)/vmlinux.bin FORCE
	$(call if_changed,uimage,none)

$(obj)/uImage.gz: $(obj)/vmlinux.bin.gz FORCE
	$(call if_changed,uimage,gzip)

$(obj)/uImage.lzma: $(obj)/vmlinux.bin.lzma FORCE
	$(call if_changed,uimage,lzma)

$(obj)/uImage: $(obj)/uImage.$(suffix-y)
	@ln -sf $(notdir $<) $@
	@echo '  Image $@ is ready'

$(obj)/loader.o: $(src)/loader.S $(obj)/vmlinux.bin

$(obj)/loader: $(obj)/loader.o $(obj)/vmlinux.bin $(obj)/loader.lds FORCE
	$(Q)$(LD)  --defsym=_entry_point_virt=$(LINUX_ENTRY_VIRT) -T $(obj)/loader.lds -o $@ $(obj)/loader.o
