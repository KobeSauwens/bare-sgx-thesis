#include "encl_t.h"
#include "secret.h"
#include <string.h>
#include <stdint.h>  // Standard integer types

#include "hacl-c/Hacl_HMAC_SHA2_256.h"

/*
 * NOTE: for demonstration purposes, we hard-code secrets at compile time and
 * abstract away how they are securely provisioned at runtime.
 */
int super_secret_constant   = 0xdeadbeef;

int ecall_dummy(int i)
{
    return super_secret_constant + i;
}

#define KEY_LEN 16  // 128 bits
#define TAG_LEN 32  // 256 bits

/* =========================== START SOLUTION =========================== */
int ecall_get_secret(uint8_t *digest, uint8_t *data, uint32_t data_len)
{
    uint8_t key[KEY_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    hmac(digest, key, KEY_LEN, data, data_len);
    return 1;
}
/* ============================ END SOLUTION ============================ */
