/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_ARC_ASM_H
#define __ASM_ARC_ASM_H 1

#ifdef __ASSEMBLY__

#ifdef CONFIG_ARC_LACKS_ZOL
#include <asm/asm-macro-dbnz.h>
#else
#include <asm/asm-macro-dbnz-emul.h>
#endif

#else	/* !__ASSEMBLY__ */

/*
 * ARCv2 cores have both LPcc and DBNZ instructions (starting 3.5a release).
 * But in this context, LP present implies DBNZ not available (ARCompact ISA)
 * or just not desirable, so emulate DBNZ with base instructions.
 */
#ifdef CONFIG_ARC_LACKS_ZOL
asm(".include \"asm/asm-macro-dbnz.h\"\n");
#else
asm(".include \"asm/asm-macro-dbnz-emul.h\"\n");
#endif

#endif	/* __ASSEMBLY__ */

#endif
