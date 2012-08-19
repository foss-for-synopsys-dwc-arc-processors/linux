targets := vmlinux.bin vmlinux.bin.gz uImage

# uImage build relies on mkimage being availble on your host for ARC target
# You will need to build u-boot for ARC, rename mkimage to arc-elf32-mkimage
# and make sure it's reacable from your PATH
MKIMAGE := $(srctree)/scripts/mkuboot.sh

OBJCOPYFLAGS= -O binary -R .note -R .note.gnu.build-id -R .comment -S

LINUX_START_TEXT = $$(readelf -h vmlinux | \
			grep "Entry point address" | grep -o 0x.*)

quiet_cmd_uimage = UIMAGE $@
	cmd_uimage = $(CONFIG_SHELL) $(MKIMAGE) -A arc -O linux -T kernel \
			-C gzip -a $(CONFIG_LINUX_LINK_BASE) \
			-e $(LINUX_START_TEXT) -d $< $@

$(obj)/vmlinux.bin: vmlinux FORCE
	$(call if_changed,objcopy)

$(obj)/vmlinux.bin.gz: $(obj)/vmlinux.bin FORCE
	$(call if_changed,gzip)

$(obj)/uImage: $(obj)/vmlinux.bin.gz FORCE
	$(call if_changed,uimage)

# build targets above don't need $(objtree) prefix for setting Dest folder to
# be top-level. However clean-files does
clean-files := $(objtree)/vmlinux.bin $(objtree)/vmlinux.bin.gz $(objtree)/uImage

PHONY += FORCE
