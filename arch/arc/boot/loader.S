/* SPDX-License-Identifier: GPL-2.0 */

	.align 4
	.section .payload, "ax", %progbits
	.incbin "arch/arc/boot/vmlinux.bin"

