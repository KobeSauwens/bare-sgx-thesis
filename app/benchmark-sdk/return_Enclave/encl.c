#include "encl_t.h"
#include "secret.h"
#include <string.h>
#include <stdint.h>  // Standard integer types


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
void ecall_return()
{
    return;
}
/* ============================ END SOLUTION ============================ */
