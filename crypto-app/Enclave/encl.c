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


/* =========================== START SOLUTION =========================== */
int ecall_get_secret(uint8_t *digest, uint8_t *data, uint32_t data_len)
{

    uint8_t *key = (uint8_t *) SECRET_KEY;
    uint32_t key_len = SECRET_KEY_SIZE;
    //if (check_pwd(password))
    //{
    hmac(digest, key, key_len, data, data_len);
    return 1;
    //}else{
    //    return 0;
    //}
}
/* ============================ END SOLUTION ============================ */
