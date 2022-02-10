/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ARCv3 ISA Low Level Intr/Traps/Exceptions Handling
 */

#include <linux/linkage.h>   /* ARC_{EXTRY,EXIT} */
#include <asm/entry.h>
#include <asm/errno.h>
#include <asm/arcregs.h>
#include <asm/irqflags.h>

; A maximum number of supported interrupts in the core interrupt controller.
; This number is not equal to the maximum interrupt number (256) because
; first 16 lines are reserved for exceptions and are not configurable.
#define NR_CPU_IRQS	240

#ifdef CONFIG_64BIT
#define VECTOR	.word
#else
#define VECTOR	.word
#endif

;############################ Vector Table #################################

	.section .vector,"a",@progbits
	.align 8

# Initial 16 slots are Exception Vectors
VECTOR	res_service		; Reset Vector
VECTOR	mem_service		; Mem exception
VECTOR	instr_service		; Instrn Error
VECTOR	EV_MachineCheck		; Fatal Machine check
#ifdef CONFIG_ARC_MMU_V4
VECTOR	EV_TLBMissI		; Intruction TLB miss
VECTOR	EV_TLBMissD		; Data TLB miss
#else
VECTOR	EV_IMMUFault		; Translation Fault: Instruction
VECTOR	EV_DMMUFault		; Translation Fault: Data
#endif
VECTOR	EV_TLBProtV		; Protection Violation
VECTOR	EV_PrivilegeV		; Privilege Violation
VECTOR	EV_SWI			; Software Breakpoint
VECTOR	EV_Trap			; Trap exception
VECTOR	EV_Extension		; Extn Instruction Exception
VECTOR	EV_DivZero		; Divide by Zero
VECTOR	reserved
VECTOR	EV_Misaligned		; Misaligned Data Access
VECTOR	reserved
VECTOR	reserved

# Begin Interrupt Vectors
VECTOR	handle_interrupt	; (16) Timer0
VECTOR	handle_interrupt	; unused (Timer1)
VECTOR	handle_interrupt	; unused (WDT)
VECTOR	handle_interrupt	; (19) Inter core Interrupt (IPI)
VECTOR	handle_interrupt	; (20) perf Interrupt
VECTOR	handle_interrupt	; (21) Software Triggered Intr (Self IPI)
VECTOR	handle_interrupt	; unused
VECTOR	handle_interrupt	; (23) unused
# End of fixed IRQs

.rept NR_CPU_IRQS - 8
	VECTOR	handle_interrupt
.endr

	.section .text, "ax",@progbits

reserved:
	flag 1		; Unexpected event, halt

ENTRY(EV_IMMUFault)
	; Read MMU_STATUS reg to find faulting lookup level
END(EV_IMMUFault)

ENTRY(EV_DMMUFault)
END(EV_DMMUFault)

#include "entry-cmn.S"
