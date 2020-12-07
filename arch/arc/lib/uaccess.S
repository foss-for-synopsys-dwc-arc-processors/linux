/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * uaccess for ARCv3: avoids ZOL, uses 64-bit memory ops
 *   ASSUMES unaligned access
 */

#include <linux/linkage.h>
#include <asm/assembler.h>

#ifndef CONFIG_ARC_USE_UNALIGNED_MEM_ACCESS
#error "Unaligned access support needed"
#endif

; Input
;  - r0: dest, kernel
;  - r1: src, user
;  - r2: sz
; Output
;  - r0: Num bytes left to copy, 0 on success

ENTRY_CFI(raw_copy_from_user)

	add    r8, r0, r2

	lsr.f  r3, r2, 4
	bz     .L1dobytes

	; chunks of 16 bytes
10:	LD64.ab r4, r1, 8
11:	LD64.ab r6, r1, 8
	ST64.ab r4, r0, 8
	ST64.ab r6, r0, 8
	DBNZR  r3, 10b

.L1dobytes:
	; last 1-15 bytes
	and.f  r3, r2, 0xf
	bz     .L1done

12:	ldb.ab r4, [r1, 1]
	stb.ab r4, [r0, 1]
	DBNZR  r3, 12b

.L1done:
	; bytes not copied = orig_src + sz - curr_src
	j.d    [blink]
	sub    r0, r8, r0
END_CFI(raw_copy_from_user)

.section __ex_table, "a"
	ARC_PTR 10b, .L1done
	ARC_PTR 11b, .L1done
	ARC_PTR 12b, .L1done
.previous

; Input
;  - r0: dest, user
;  - r1: src, kernel
;  - r2: sz
; Output
;  - r0: Num bytes left to copy, 0 on success

ENTRY_CFI(raw_copy_to_user)

	add    r8, r1, r2

	lsr.f  r3, r2, 4
	bz     .L2dobytes

	; chunks of 16 bytes
2:	LD64.ab r4, r1, 8
	LD64.ab r6, r1, 8
20:	ST64.ab r4, r0, 8
21:	ST64.ab r6, r0, 8
	DBNZR  r3, 2b

.L2dobytes:
	; last 1-15 bytes
	and.f  r3, r2, 0xf
	bz     .L2done

2:	ldb.ab r4, [r1, 1]
22:	stb.ab r4, [r0, 1]
	DBNZR  r3, 2b

.L2done:
	; bytes not copied = orig_src + sz - curr_src
	j.d    [blink]
	sub    r0, r8, r1

END_CFI(raw_copy_to_user)

.section __ex_table, "a"
	ARC_PTR 20b, .L2done
	ARC_PTR 21b, .L2done
	ARC_PTR 22b, .L2done
.previous

ENTRY_CFI(__clear_user)
	add    r8, r0, r1

	mov    r4, 0
	mov    r5, 0

	lsr.f  r3, r1, 4
	bz     .L3dobytes

	; chunks of 16 bytes
30:	ST64.ab r4, r0, 8
31:	ST64.ab r4, r0, 8
	DBNZR  r3, 30b

.L3dobytes:
	; last 1-15 bytes
	and.f  r3, r1, 0xf
	bz     .L3done

32:	stb.ab r4, [r0, 1]
	DBNZR  r3, 32b

.L3done:
	; bytes not copied = orig_src + sz - curr_src
	j.d    [blink]
	sub    r0, r8, r0

END_CFI(__clear_user)

; Note that .fixup section is missing and that is not an omission
;
; .fixup is a level of indirection for user fault handling to do some extra work
; before jumping off to a safe instruction (past the faulting LD/ST) in uaccess
; code. This could be say setting up -EFAULT in return register for caller.
; But if that is not needed (such as above where number of bytes copied/not-copied
; is already in return reg r0) and fault handler only needs to resume to a valid PC
; that label could be placed in __ex_table entry (otherwise be in .fixup)
; do_page_fault() -> fixup_exception() use that to setup pt_regs->ret, which the
; CPU exception handler resumes to. This also makes the handling more efficient
; by removing a level of indirection.

.section __ex_table, "a"
	ARC_PTR 30b, .L3done
	ARC_PTR 31b, .L3done
	ARC_PTR 32b, .L3done
.previous
