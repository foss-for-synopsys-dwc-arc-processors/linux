# SPDX-License-Identifier: GPL-2.0-only

ifeq ($(CONFIG_ISA_ARCV2),y)
	obj-$(CONFIG_BPF_JIT) += bpf_jit_core.o
	obj-$(CONFIG_BPF_JIT) += bpf_jit_arcv2.o

	CFLAGS_bpf_jit_core.o += -Og -g3
	CFLAGS_bpf_jit_arcv2.o += -Og -g3
endif
