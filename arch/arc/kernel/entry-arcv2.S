/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ARCv2 ISA based core Low Level Intr/Traps/Exceptions(non-TLB) Handling
 *
 * Copyright (C) 2013 Synopsys, Inc. (www.synopsys.com)
 */

#include <linux/linkage.h>   /* ARC_{EXTRY,EXIT} */
#include <asm/entry.h>       /* SAVE_ALL_{INT1,INT2,TRAP...} */
#include <asm/errno.h>
#include <asm/arcregs.h>
#include <asm/irqflags.h>
#include <asm/mmu.h>

; A maximum number of supported interrupts in the core interrupt controller.
; This number is not equal to the maximum interrupt number (256) because
; first 16 lines are reserved for exceptions and are not configurable.
#define NR_CPU_IRQS	240

	.cpu HS

#define VECTOR	.word

;############################ Vector Table #################################

	.section .vector,"a",@progbits
	.align 4

# Initial 16 slots are Exception Vectors
VECTOR	res_service		; Reset Vector
VECTOR	mem_service		; Mem exception
VECTOR	instr_service		; Instrn Error
VECTOR	EV_MachineCheck		; Fatal Machine check
VECTOR	EV_TLBMissI		; Intruction TLB miss
VECTOR	EV_TLBMissD		; Data TLB miss
VECTOR	EV_TLBProtV		; Protection Violation
VECTOR	EV_PrivilegeV		; Privilege Violation
VECTOR	EV_SWI			; Software Breakpoint
VECTOR	EV_Trap			; Trap exception
VECTOR	EV_Extension		; Extn Instruction Exception
VECTOR	EV_DivZero		; Divide by Zero
VECTOR	EV_DCError		; Data Cache Error
VECTOR	EV_Misaligned		; Misaligned Data Access
VECTOR	reserved		; Reserved slots
VECTOR	reserved		; Reserved slots

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

#include "entry-cmn.S"
