/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Synopsys, Inc. (www.synopsys.com)
 */

#ifndef __ASM_ARC_FIXMAP_H
#define __ASM_ARC_FIXMAP_H

#ifndef __ASSEMBLY__
#include <linux/sizes.h>
#include <asm/page.h>
#include <asm/pgtable.h>

#ifdef CONFIG_ISA_ARCV3
enum fixed_addresses {
	FIX_EARLYCON_MEM_BASE,
	__end_of_fixed_addresses
};

#define FIXADDR_SIZE		(__end_of_fixed_addresses * PAGE_SIZE)
#define FIXADDR_TOP		(FIXADDR_START + FIXADDR_SIZE - PAGE_SIZE)

#define FIXMAP_PAGE_IO		pgprot_noncached(PAGE_KERNEL)

void __init early_fixmap_init(void);

#define __early_set_fixmap __set_fixmap

extern void __set_fixmap(enum fixed_addresses idx, phys_addr_t phys,
			 pgprot_t prot);

#include <asm-generic/fixmap.h>

#else

#define FIXADDR_SIZE		PGDIR_SIZE
#define FIXADDR_TOP             (FIXADDR_START + (FIX_KMAP_END << PAGE_SHIFT))

#endif /* CONFIG_ISA_ARCV3 */

#endif /* !__ASSEMBLY__ */
#endif /* __ASM_ARC_FIXMAP_H */
