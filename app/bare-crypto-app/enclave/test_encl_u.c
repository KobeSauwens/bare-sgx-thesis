#include "test_encl_u.h"
#include <errno.h>

typedef struct ms_encl_HMAC_t {
	uint8_t* ms_digest;
	uint8_t* ms_message;
	uint32_t ms_message_len;
} ms_encl_HMAC_t;

typedef struct ms_encl_AEAD_enc_t {
	uint8_t* ms_ciphertext;
	uint8_t* ms_tag;
	uint8_t* ms_plaintext;
	uint32_t ms_plaintext_len;
	uint8_t* ms_data;
	uint32_t ms_data_len;
	uint8_t* ms_nonce;
} ms_encl_AEAD_enc_t;

typedef struct ms_encl_AEAD_dec_t {
	uint8_t* ms_plaintext;
	uint8_t* ms_ciphertext;
	uint32_t ms_ciphertext_len;
	uint8_t* ms_data;
	uint32_t ms_data_len;
	uint8_t* ms_nonce;
	uint8_t* ms_tag;
} ms_encl_AEAD_dec_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_test_encl = {
	0,
	{ NULL },
};
sgx_status_t encl_HMAC(sgx_enclave_id_t eid, uint8_t* digest, uint8_t* message, uint32_t message_len)
{
	sgx_status_t status;
	ms_encl_HMAC_t ms;
	ms.ms_digest = digest;
	ms.ms_message = message;
	ms.ms_message_len = message_len;
	status = sgx_ecall(eid, 0, &ocall_table_test_encl, &ms);
	return status;
}

sgx_status_t encl_AEAD_enc(sgx_enclave_id_t eid, uint8_t* ciphertext, uint8_t* tag, uint8_t* plaintext, uint32_t plaintext_len, uint8_t* data, uint32_t data_len, uint8_t* nonce)
{
	sgx_status_t status;
	ms_encl_AEAD_enc_t ms;
	ms.ms_ciphertext = ciphertext;
	ms.ms_tag = tag;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_len = plaintext_len;
	ms.ms_data = data;
	ms.ms_data_len = data_len;
	ms.ms_nonce = nonce;
	status = sgx_ecall(eid, 1, &ocall_table_test_encl, &ms);
	return status;
}

sgx_status_t encl_AEAD_dec(sgx_enclave_id_t eid, uint8_t* plaintext, uint8_t* ciphertext, uint32_t ciphertext_len, uint8_t* data, uint32_t data_len, uint8_t* nonce, uint8_t* tag)
{
	sgx_status_t status;
	ms_encl_AEAD_dec_t ms;
	ms.ms_plaintext = plaintext;
	ms.ms_ciphertext = ciphertext;
	ms.ms_ciphertext_len = ciphertext_len;
	ms.ms_data = data;
	ms.ms_data_len = data_len;
	ms.ms_nonce = nonce;
	ms.ms_tag = tag;
	status = sgx_ecall(eid, 2, &ocall_table_test_encl, &ms);
	return status;
}

sgx_status_t encl_return(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_test_encl, NULL);
	return status;
}

