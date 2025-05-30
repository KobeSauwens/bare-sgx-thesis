#ifndef TEST_ENCL_T_H__
#define TEST_ENCL_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void encl_HMAC(uint8_t* digest, uint8_t* message, uint32_t message_len);
void encl_AEAD_enc(uint8_t* ciphertext, uint8_t* tag, uint8_t* plaintext, uint32_t plaintext_len, uint8_t* data, uint32_t data_len, uint8_t* nonce);
void encl_AEAD_dec(uint8_t* plaintext, uint8_t* ciphertext, uint32_t ciphertext_len, uint8_t* data, uint32_t data_len, uint8_t* nonce, uint8_t* tag);
void encl_return(void);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
