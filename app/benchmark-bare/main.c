#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include "../../external/sgx-step/libsgxstep/cpu.h"
#include "../../external/sgx-step/libsgxstep/sched.h"
//#include "baresgx/urts.h"
//#include "enclave/test_encl.h"
#include "../../trts/bare-trts/sgx_edger8r.h"
#include "../bare-crypto-app/enclave/test_encl_u.h"

#define NONCE_LEN       12
#define MAC_LEN         16
#define DIGEST_LEN      32
#define KEY_LEN_AEAD    32
#define BYTES_PER_LINE  30


#define ENCLAVE_PATH "enclave_crypto/encl.elf"
#define ENCLAVE_DEBUG 0
#define ITERATIONS 100000

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

int main(void) {
    void *tcs = baresgx_load_elf_enclave(ENCLAVE_PATH, ENCLAVE_DEBUG);
    struct tm *timeinfo;
    char filename[100];
    time_t rawtime;

    if (!tcs) {
        printf("Failed to load enclave\n");
        return 1;
    }
    baresgx_info("loaded enclave at %p", tcs);

    // Get current time for filename
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(filename, sizeof(filename), "../../data/benchmark-bare/enclave_timing_return_%Y-%m-%d_%H-%M-%S.csv", timeinfo);

    // Open file with timestamped name
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        printf("Error opening file %s!\n", filename);
        return 1;
    }
    fprintf(fp, "Iteration,ElapsedCycles\n");

    // Buffer results to reduce I/O overhead
    uint64_t *cycles = malloc(ITERATIONS * sizeof(uint64_t));
    if (!cycles) {
        printf("Memory allocation failed\n");
        fclose(fp);
        return 1;
    }


    uint8_t nonce[NONCE_LEN] = {0};
    const char *aad = "TCB should be minimized!";
    uint32_t aadlen = strlen(aad);

    const char *message = "Bare-SGX rocks!";
    uint32_t mlen = strlen(message);
    uint8_t digest[DIGEST_LEN] = {0};

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



    if (prepare_system_for_benchmark(100) != 0) {
        printf("Failed to prepare system\n");
        return 1;
    }
    printf("System prepared successfully\n");



    for (uint32_t i = 0; i < ITERATIONS; ++i) {
        //BARESGX_ASSERT(baresgx_enter_enclave(tcs, (uint64_t)&arg_ret));
        
        //encl_AEAD_enc(tcs, ciphertext, mac, (const uint8_t*)message, mlen, (const uint8_t*)aad, aadlen, nonce);
        //encl_AEAD_dec(tcs, decrypted, ciphertext, mlen, (const uint8_t*)aad, aadlen, nonce, mac);


        encl_HMAC(tcs, digest, (const uint8_t*)message, mlen);

        uint64_t start = rdtsc_begin();
        
        //encl_AEAD_enc(tcs, ciphertext, mac, (const uint8_t*)message, mlen, (const uint8_t*)aad, aadlen, nonce);
        //encl_AEAD_dec(tcs, decrypted, ciphertext, mlen, (const uint8_t*)aad, aadlen, nonce, mac);
        //BARESGX_ASSERT(baresgx_enter_enclave(tcs, (uint64_t)&arg_ret));

        encl_HMAC(tcs, digest, (const uint8_t*)message, mlen);

        uint64_t end = rdtsc_end();
       
        cycles[i] = end - start;
    }

    print_hmac_args((const uint8_t*)message, mlen, digest, DIGEST_LEN);
    //print_aead_args(nonce, aad, aadlen, decrypted, ciphertext, mac, mlen);
    //printf("\nDecrypted text: %s\n", decrypted);

    free(ciphertext);
    free(decrypted);

    // Write results to file
    for (uint32_t i = 0; i < ITERATIONS; ++i) {
        fprintf(fp, "%u,%lu\n", i, cycles[i]);
    }

    free(cycles);
    fclose(fp);
    printf("Results written to %s\n", filename);
    return 0;
}