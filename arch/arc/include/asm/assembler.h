/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_ARC_ASM_H
#define __ASM_ARC_ASM_H 1

#ifdef __ASSEMBLY__

#include <asm/asm-macro-32-bit.h>

#ifdef CONFIG_ARC_HAS_LL64
#include <asm/asm-macro-ll64.h>
#else
#include <asm/asm-macro-ll64-emul.h>
#endif

#ifdef CONFIG_ARC_LACKS_ZOL
#include <asm/asm-macro-dbnz.h>
#else
#include <asm/asm-macro-dbnz-emul.h>
#endif

#else	/* !__ASSEMBLY__ */

asm(".include \"asm/asm-macro-32-bit.h\"\n");

#ifdef CONFIG_ARC_HAS_LL64
asm(".include \"asm/asm-macro-ll64.h\"\n");
#else
asm(".include \"asm/asm-macro-ll64-emul.h\"\n");
#endif

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
