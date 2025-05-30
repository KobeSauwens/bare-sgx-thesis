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

/* Based on https://lkml.org/lkml/2023/7/19/797 */
	.global get_enclave_base
get_enclave_base:
	lea __enclave_base(%rip), %rax
	ret

	.global get_enclave_size
get_enclave_size:
	mov __enclave_size(%rip), %rax
	ret


encl_entry:
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

/* This is filled in by the untrusted loader, contains total size of the loaded enclave how can we trust it then? --> Attestation? */
	.global __enclave_size
__enclave_size:
	.quad 0x0
	
	.section ".data", "aw"

encl_ssa_tcs1:
	.space 4096

	.balign 4096
	# Stack of TCS #1
	.space 4096
encl_stack:
