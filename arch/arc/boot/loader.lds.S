/* SPDX-License-Identifier: GPL-2.0 */

#include <asm/page.h>

OUTPUT_ARCH(arc)
ENTRY(_entry_point)

_entry_point = (_entry_point_virt - PAGE_OFFSET) + CONFIG_LINUX_LINK_BASE;

SECTIONS
{
	. = CONFIG_LINUX_LINK_BASE;

	.payload : {
		*(.payload)
		. = ALIGN(8);
	}
}
