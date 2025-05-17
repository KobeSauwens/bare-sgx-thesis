#include "encl_t.h"
#include "secret.h"
#include <string.h>
#include <stdint.h>  // Standard integer types

#include "dist/portable-gcc-compatible/Hacl_HMAC.h"
#include "dist/portable-gcc-compatible/Hacl_AEAD_Chacha20Poly1305.h"

#define KEY_LEN 16  // 128 bits
#define TAG_LEN 32  // 256 bits

/*
 * NOTE: for demonstration purposes, we hard-code secrets at compile time and
 * abstract away how they are securely provisioned at runtime.
 */
int super_secret_constant   = 0xdeadbeef;

int ecall_dummy(int i)
{
    return super_secret_constant + i;
}

typedef struct _fake_file { int dummy; } FILE;
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

// Dummy `stderr` symbol
FILE *stderr = (void *)0;


int printf(const char* format, ...)
{
    // Dummy printf: do nothing, return 0
    (void)format;
    return 0;
}

/* =========================== START SOLUTION =========================== */
int encl_op_hmac(uint8_t *digest, uint8_t *data, uint32_t data_len)
{
    uint8_t key[KEY_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    Hacl_HMAC_compute_sha2_256(digest, key, KEY_LEN, data, data_len);
    ocall_print_uint8_array(digest,TAG_LEN);
    return 1;
}
/* ============================ END SOLUTION ============================ */

int encl_op_chacha20poly1305_enc(uint8_t *ciphertext,
                             uint8_t *tag, 
                             uint8_t *plaintext, 
                             uint32_t pt_len, 
                             uint8_t *aad, 
                             uint32_t aad_len, 
                             uint8_t *nonce)
{
    uint8_t key[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    // Perform encryption
    Hacl_AEAD_Chacha20Poly1305_encrypt(ciphertext, tag, plaintext, pt_len, aad, aad_len, key, nonce);

    return 1;
}

int encl_op_chacha20poly1305_dec(uint8_t *ciphertext,
                             uint8_t *tag, 
                             uint8_t *plaintext, 
                             uint32_t pt_len, 
                             uint8_t *aad, 
                             uint32_t aad_len, 
                             uint8_t *nonce)
{
    uint8_t key[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    // Perform encryption
    Hacl_AEAD_Chacha20Poly1305_decrypt(plaintext, ciphertext, pt_len, aad, aad_len, key, nonce, tag);

    return 1;
}