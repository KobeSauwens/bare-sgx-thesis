/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2016-20 Intel Corporation.
 */
	.section ".tcs", "aw"
	.balign	4096

	.fill	1, 8, 0			# STATE (set by CPU)
	.fill	1, 8, 0			# FLAGS
	.quad	encl_ssa_tcs1		# OSSA
	.fill	1, 4, 0			# CSSA (set by CPU)
	.fill	1, 4, 1			# NSSA
	.quad	encl_entry		# OENTRY
	.fill	1, 8, 0			# AEP (set by EENTER and ERESUME)
	.fill	1, 8, 0			# OFSBASE
	.fill	1, 8, 0			# OGSBASE
	.fill	1, 4, 0xFFFFFFFF 	# FSLIMIT
	.fill	1, 4, 0xFFFFFFFF	# GSLIMIT
	.fill	4024, 1, 0		# Reserved

	.text

encl_entry:
 /*
	mov %rcx,%rbx
	mov $0x4,%eax
	enclu
*/
        
        lea     encl_stack(%rip), %rax
	xchg	%rsp, %rax
	push	%rax

	push	%rcx # push the address after EENTER

        # restore calling convention
        mov     %rsi, %rdi
        mov     %rdx, %rsi

	# NOTE: as the selftest enclave is *not* intended for production,
	# simplify the code by not initializing ABI registers on entry or
	# cleansing caller-save registers on exit.
	call	encl_body

	# Prepare EEXIT target by popping the address of the instruction after
	# EENTER to RBX.
	pop	%rbx

	# Restore the caller stack.
	pop	%rax
	mov	%rax, %rsp

	# EEXIT
	mov	$4, %rax
	enclu
	

	.section ".data", "aw"


encl_ssa_tcs1:
	.space 4096

	.balign 4096
	# Stack of TCS #1
	.space 4096
encl_stack:
