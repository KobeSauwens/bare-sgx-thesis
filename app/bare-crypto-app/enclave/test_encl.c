// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2016-20 Intel Corporation. */

#include "../../../trts/bare-trts/bare_trts.h"
#include "test_encl.h"
#include "dist/portable-gcc-compatible/Hacl_HMAC.h"
#include "dist/portable-gcc-compatible/Hacl_AEAD_Chacha20Poly1305.h"
//#include "../../../external/hacl-star/dist/portable-gcc-compatible/Hacl_Spec.h"
//#include "../../../external/hacl-star/dist/portable-gcc-compatible/EverCrypt_AEAD.h"
#include "../../../trts/FreeRTOS/FreeRTOS.h"

//#include "../../../trts/klibc-2.0.14/usr/include/malloc.h"
//#include "../../../trts/klibc-2.0.14/usr/include/stdlib.h"
//#include "../../../external/hacl-star/dist/portable-gcc-compatible/Lib_RandomBuffer_System.h"
#define configAPPLICATION_ALLOCATED_HEAP 1

uint8_t ucHeap[configTOTAL_HEAP_SIZE];

static uint8_t AEAD_key[KEY_LEN_AEAD] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

// static uint8_t AES_key[KEY_LEN_AES] = {
// 	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
// 	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
// };

// Dummy `stderr` symbol
FILE *stderr = (void *)0;

// Dummy `exit` that halts or loops forever
void exit(int status) {
    (void)status;
    while (1) { /* trap or halt */ }
}

// Dummy `fprintf` that does nothing
int fprintf(FILE *stream, const char *format, ...) {
    (void)stream;
    (void)format;
    return 0;
}

extern const struct {
    size_t nr_ecall;
    struct {
        void* ecall_addr;
        uint8_t is_priv;
        uint8_t is_switchless;
    } ecall_table[];
} g_ecall_table;



static void do_encl_op_add(void *_op)
{
	struct encl_op_math op;

	SAFE_COPY_STRUCT(_op,&op);
        /* TODO *insecure* ptr dereference: needs a check */
	*op.rv_pt = op.val1 + op.val2;
}

static void do_encl_op_sub(void *_op)
{
	struct encl_op_math op;

	SAFE_COPY_STRUCT(_op,&op);
        /* TODO *insecure* ptr dereference: needs a check */
	*op.rv_pt = op.val1 - op.val2;
}

void do_encl_op_hmac(void *_op)
{
	struct encl_op_hmac *op = _op;

    uint8_t key[KEY_LEN_HMAC] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    Hacl_HMAC_compute_sha2_256(op->digest, key, KEY_LEN_HMAC, op->message, (*op).message_len);
}

static void do_encl_op_AEAD_encrypt(void *_op)
{
	struct encl_op_AEAD *op = _op;

	Hacl_AEAD_Chacha20Poly1305_encrypt(
		op->cipher,
		op->mac,
		op->m,
		op->mlen,
		op->aad,
		op->aadlen,
		AEAD_key,
		op->n
	);
}

static void do_encl_op_AEAD_decrypt(void *_op)
{
	struct encl_op_AEAD *op = _op;
	Hacl_AEAD_Chacha20Poly1305_decrypt(
		op->m,
		op->cipher,
		op->mlen,
		op->aad,
		op->aadlen,
		AEAD_key,
		op->n,
		op->mac
	);
}

// static void do_encl_op_AES_GCM_128_encrypt(void *_op)
// {
	
// 	struct encl_op_AEAD *op = _op;
// 	EverCrypt_AEAD_state_s *dst;
// 	EverCrypt_AEAD_create_in(Spec_Agile_AEAD_AES128_GCM, &dst, AES_key);

// 	EverCrypt_AEAD_encrypt(
// 		dst,
// 		op->n,
// 		NONCE_LEN,
// 		op->aad,
// 		op->aadlen,
// 		op->m,
// 		op->mlen,
// 		op->cipher,
// 		op->mac
// 	);

// 	EverCrypt_AEAD_free(dst);
// }



/*
 * Symbol placed at the start of the enclave image by the linker script.
 * Declare this extern symbol with visibility "hidden" to ensure the compiler
 * does not access it through the GOT and generates position-independent
 * addressing as __encl_base(%rip), so we can get the actual enclave base
 * during runtime.
 */
extern const uint8_t __attribute__((visibility("hidden"))) __enclave_base;

typedef void (*encl_op_t)(void *);

/* NOTE: need to declare this volatile to preven the compiler from inlining the
 * accesses in encl_body and breaking the manual relocation.. */
volatile encl_op_t encl_op_array[ENCL_OP_MAX] = {
	do_encl_op_add,
	do_encl_op_sub,
	do_encl_op_hmac,
	do_encl_op_AEAD_encrypt,
	do_encl_op_AEAD_decrypt,
};


void encl_body(void *rdi, void *rsi)
{
	struct encl_op_header *header = (struct encl_op_header *)rdi;
	encl_op_t op;

	/*TODO *insecure* ptr dereference: needs a check */
	
	if(!is_outside_enclave(header,sizeof(struct encl_op_header)))
	{
	 	panic();
	}

	if (header->type >= ENCL_OP_MAX)
		return;

	/*
	 * The enclave base address needs to be added, as this call site
	 * *cannot be* made rip-relative by the compiler, or fixed up by
	 * any other possible means.
	 */
	//op = ((uint64_t)&__enclave_base) + encl_op_array[header->type];
	op = ((uint64_t)&__enclave_base) + g_ecall_table.ecall_table[0].ecall_addr;


	(*op)(header);
}

// void encl_body(void *rdi, void *rsi)
// {
// 	size_t *number = (size_t *) rdi;
// 	(*number)++;
// }