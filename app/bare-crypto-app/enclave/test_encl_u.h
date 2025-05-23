#ifndef TEST_ENCL_U_H__
#define TEST_ENCL_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t encl_HMAC(sgx_enclave_id_t eid, uint8_t* digest, uint8_t* message, uint32_t message_len);
sgx_status_t encl_AEAD_enc(sgx_enclave_id_t eid, uint8_t* ciphertext, uint8_t* tag, uint8_t* plaintext, uint32_t plaintext_len, uint8_t* data, uint32_t data_len, uint8_t* nonce);
sgx_status_t encl_AEAD_dec(sgx_enclave_id_t eid, uint8_t* plaintext, uint8_t* ciphertext, uint32_t ciphertext_len, uint8_t* data, uint32_t data_len, uint8_t* nonce, uint8_t* tag);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
