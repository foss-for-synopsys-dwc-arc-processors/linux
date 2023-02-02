/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 */

#ifndef __ASM_ARC_ELF_H
#define __ASM_ARC_ELF_H

#include <linux/types.h>
#include <linux/elf-em.h>
#include <uapi/asm/elf.h>

#ifdef CONFIG_ISA_ARCOMPACT
#define ELF_ARCH		EM_ARCOMPACT
#elif defined(CONFIG_ISA_ARCV2)
#define ELF_ARCH		EM_ARCV2
#else
#ifdef CONFIG_64BIT
#define ELF_ARCH		EM_ARCV3
#else
#define ELF_ARCH		EM_ARCV3_32
#endif
#endif

#ifdef CONFIG_64BIT

#define ELF_CLASS		ELFCLASS64
struct elf64_hdr;
int elf_check_arch(const struct elf64_hdr *x);

#else

#define ELF_CLASS		ELFCLASS32
struct elf32_hdr;
int elf_check_arch(const struct elf32_hdr *x);

#endif

/* To print warning about wrong architecture. */
#define elf_check_arch	elf_check_arch

#ifdef CONFIG_CPU_BIG_ENDIAN
#define ELF_DATA		ELFDATA2MSB
#else
#define ELF_DATA		ELFDATA2LSB
#endif

/* ARC Relocations (kernel Modules only) */
#define  R_ARC_32		0x4
#define  R_ARC_64		0x5
#define  R_ARC_S25H_PCREL	0x10
#define  R_ARC_32_ME		0x1B
#define  R_ARC_32_PCREL		0x31
#define  R_ARC_LO32_ME		0x5c
#define  R_ARC_HI32_ME		0x5d

#define CORE_DUMP_USE_REGSET

#define ELF_EXEC_PAGESIZE	PAGE_SIZE

/*
 * This is the location that an ET_DYN program is loaded if exec'ed.  Typical
 * use of this is to invoke "./ld.so someprog" to test out a new version of
 * the loader.  We need to make sure that it is out of the way of the program
 * that it will "exec", and that there is sufficient room for the brk.
 */
#define ELF_ET_DYN_BASE		(2UL * TASK_SIZE / 3)

/*
 * When the program starts, a1 contains a pointer to a function to be
 * registered with atexit, as per the SVR4 ABI.  A value of 0 means we
 * have no such handler.
 */
#define ELF_PLAT_INIT(_r, load_addr)	((_r)->r0 = 0)

/*
 * This yields a mask that user programs can use to figure out what
 * instruction set this cpu supports.
 */
#define ELF_HWCAP	(0)

/*
 * This yields a string that ld.so will use to load implementation
 * specific libraries for optimization.  This is more specific in
 * intent than poking at uname or /proc/cpuinfo.
 */
#define ELF_PLATFORM	(NULL)

#if defined(CONFIG_ISA_ARCOMPACT)
#define	ISA_NAME	"ARCompact"
#elif defined(CONFIG_ISA_ARCV2)
#define ISA_NAME        "ARCv2"
#elif defined(CONFIG_ISA_ARCV3) && defined(CONFIG_64BIT)
#define ISA_NAME        "ARCv3 64 bit"
#elif defined(CONFIG_ISA_ARCV3)
#define ISA_NAME        "ARCv3 32 bit"
#else
#define ISA_NAME        "unknown"
#endif

#endif
