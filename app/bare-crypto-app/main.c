#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../../urts/include/baresgx/urts.h"
#include <openssl/rand.h>

#include "enclave/test_encl.h"
#include "enclave/test_encl_u.h"

#define ENCLAVE_PATH    "enclave/encl.elf"
#define ENCLAVE_DEBUG   0

#define NONCE_LEN       12
#define MAC_LEN         16
#define DIGEST_LEN      32
#define KEY_LEN_AEAD    32
#define BYTES_PER_LINE  30

void print_hex_one_line(const char *label, const uint8_t *data, uint32_t len) {
    printf("%-12s [len=%3u]: ", label, len);
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if (i < len - 1) printf(" ");
    }
    printf("\n");
}

void print_hmac_args(const uint8_t *message, uint32_t message_len, const uint8_t *digest, uint32_t digest_len) {
    printf("=== HMAC Operation ===\n");
    print_hex_one_line("Message", message, message_len);
    print_hex_one_line("Digest", digest, digest_len);
}

void print_aead_args(const uint8_t *nonce, const uint8_t *aad, uint32_t aadlen,
                     const uint8_t *plaintext, const uint8_t *ciphertext,
                     const uint8_t *mac, uint32_t mlen) {
    printf("=== AEAD Operation ===\n");
    print_hex_one_line("Nonce",     nonce,     NONCE_LEN);
    print_hex_one_line("AAD",       aad,       aadlen);
    print_hex_one_line("Message",   plaintext, mlen);
    print_hex_one_line("Ciphertext",ciphertext,mlen);
    print_hex_one_line("MAC",       mac,       MAC_LEN);
}

void dump_hex(const char *str, const uint8_t *buf, int len) {
    printf("%s = ", str);
    for (int i = 0; i < len; i++)
        printf("%02x ", buf[i]);
    printf("\n");
}

void run_hmac(sgx_enclave_id_t eid) {
    uint8_t digest[DIGEST_LEN] = {0};
    const char *message = "Bare-SGX rocks!";
    uint32_t message_len = strlen(message);

    baresgx_info("Running HMAC operation");
    encl_HMAC(eid, digest, (const uint8_t*)message, message_len);

    printf("\nBare SGX currently hashing: \"%s\"\n", message);
    print_hmac_args((const uint8_t*)message, message_len, digest, DIGEST_LEN);
}

void run_aead(sgx_enclave_id_t eid) {
    uint8_t nonce[NONCE_LEN] = {0};
    const char *aad = "TCB should be minimized!";
    uint32_t aadlen = strlen(aad);

    const char *message = "Bare-SGX rocks!";
    uint32_t mlen = strlen(message);

    uint8_t mac[MAC_LEN] = {0};
    uint8_t *ciphertext = malloc(mlen);
    uint8_t *decrypted  = malloc(mlen);

    if (!ciphertext || !decrypted) {
        fprintf(stderr, "Memory allocation failed\n");
    }

    uint8_t key_for_dump[KEY_LEN_AEAD] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    dump_hex("\nKey:", key_for_dump, KEY_LEN_AEAD);

    printf("\nBare SGX currently performing AEAD encryption using ChaCha20 and Poly1305\n");
    encl_AEAD_enc(eid, ciphertext, mac, (const uint8_t*)message, mlen, (const uint8_t*)aad, aadlen, nonce);
    print_aead_args(nonce, (const uint8_t*)aad, aadlen, (const uint8_t*)message, ciphertext, mac, mlen);

    printf("\nBare SGX currently performing AEAD decryption using ChaCha20 and Poly1305\n");
    encl_AEAD_dec(eid, decrypted, ciphertext, mlen, (const uint8_t*)aad, aadlen, nonce, mac);
    print_aead_args(nonce, (const uint8_t*)aad, aadlen, decrypted, ciphertext, mac, mlen);

    decrypted[mlen] = '\0';
    printf("\nDecrypted text: %s\n", decrypted);

    free(ciphertext);
    free(decrypted);
}

int main(void) {
    void *tcs = baresgx_load_elf_enclave(ENCLAVE_PATH, ENCLAVE_DEBUG);
    baresgx_info("Loaded enclave at %p", tcs);

    baresgx_info("Reading enclave memory..");
    printf("\tL mem at %p is %lx\n", tcs, *((uint64_t*)tcs));

    baresgx_info("Calling enclave TCS..");

    run_hmac((sgx_enclave_id_t)tcs);
    run_aead((sgx_enclave_id_t)tcs);

    return 0;
}

