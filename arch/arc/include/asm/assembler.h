/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_ARC_ASM_H
#define __ASM_ARC_ASM_H 1

#ifdef __ASSEMBLY__

#if defined(CONFIG_ISA_ARCV3) && defined(CONFIG_64BIT)
#define ARC_PTR		.xword
#define REGSZASM	8
#include <asm/asm-macro-64-bit.h>
#else
#define ARC_PTR		.word
#define REGSZASM	4
#include <asm/asm-macro-32-bit.h>

#ifdef CONFIG_ARC_HAS_LL64
#include <asm/asm-macro-ll64.h>
#else
#include <asm/asm-macro-ll64-emul.h>
#endif

#endif

#ifdef CONFIG_ARC_LACKS_ZOL
#include <asm/asm-macro-dbnz.h>
#else
#include <asm/asm-macro-dbnz-emul.h>
#endif

#else	/* !__ASSEMBLY__ */

#if defined(CONFIG_ISA_ARCV3) && defined(CONFIG_64BIT)
#define ARC_PTR		" .xword "
#define REGSZASM	" 8 "
asm(".include \"asm/asm-macro-64-bit.h\"\n");
#else
#define ARC_PTR		" .word "
#define REGSZASM	" 4 "
asm(".include \"asm/asm-macro-32-bit.h\"\n");

#ifdef CONFIG_ARC_HAS_LL64
asm(".include \"asm/asm-macro-ll64.h\"\n");
#else
asm(".include \"asm/asm-macro-ll64-emul.h\"\n");
#endif

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
