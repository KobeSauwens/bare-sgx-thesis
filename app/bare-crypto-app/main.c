#include <stdio.h>
#include <string.h>
#include "../../urts/include/baresgx/urts.h"
#include <openssl/rand.h>
//#include "../../external/hacl-star/dist/portable-gcc-compatible/Lib_RandomBuffer_System.h"
#include "../../trts/FreeRTOS/FreeRTOSConfig.h"

#include "enclave/test_encl.h"
//#include "enclave/test_encl_u.h"
//#include "enclave/test_encl.h"

#define ENCLAVE_PATH    "enclave/encl.elf"
#define ENCLAVE_DEBUG   0
#define configAPPLICATION_ALLOCATED_HEAP 1

uint8_t ucHeap[configTOTAL_HEAP_SIZE];

#define BYTES_PER_LINE 30

// Helper function to print byte array in aligned hex
void print_hex_aligned(const char *label, uint8_t *data, uint32_t len) {
    printf("%s [len=%u]:\n", label, len);
    for (uint32_t i = 0; i < len; i++) {
        // New line every BYTES_PER_LINE bytes
        if (i % BYTES_PER_LINE == 0)
            printf("  %04x: ", i); // Offset label

        printf("%02x ", data[i]);

        // Add spacing at end of line
        if ((i + 1) % BYTES_PER_LINE == 0 || i + 1 == len)
            printf("\n");
    }
}// Helper function to print byte array in hex
void print_hex(const char *label, uint8_t *data, uint32_t len) {
    printf("%s [len=%u]: ", label, len);
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if (i < len - 1) printf(":");
    }
    printf("\n");
}


// Helper: Print a byte array on one line with label
void print_hex_one_line(const char *label, uint8_t *data, uint32_t len) {
    printf("%-12s [len=%3u]: ", label, len);  // Left-align label, show length
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if (i < len - 1) printf(" ");
    }
    printf("\n");
}

void print_encl_op_hmac(struct encl_op_hmac *op, uint32_t digest_len) {
    printf("=== encl_op_HMAC ===\n");
    print_hex_one_line("Message", op->message, op->message_len);
    print_hex_one_line("Digest",  op->digest, digest_len);
}

// Main pretty printer
void print_encl_op_AEAD(struct encl_op_AEAD *op) {
    printf("=== encl_op_AEAD ===\n");

    // Optional: print header_AEAD if needed

    print_hex_one_line("Nonce",     op->n,      12);
    print_hex_one_line("AAD",       op->aad,    op->aadlen);
    print_hex_one_line("Message",   op->m,      op->mlen);
    print_hex_one_line("Ciphertext",op->cipher, op->mlen);
    print_hex_one_line("MAC",       op->mac,    16);
}

void dump_hex(char *str, uint8_t *buf, int len)
{
    printf("%s = ", str);
    for (int i=0; i < len; i++)
        printf("%02x ", *(buf + i));
    printf("\n");
}

int main(void)
{
    struct encl_op_hmac arg_hmac;
    //struct encl_op_AEAD arg_AEAD_ENC;
    //struct encl_op_AEAD arg_AEAD_DEC;


    uint8_t key_for_dump[KEY_LEN_AEAD] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};
    
    void *tcs;

    tcs = baresgx_load_elf_enclave(ENCLAVE_PATH, ENCLAVE_DEBUG);
    baresgx_info("loaded enclave at %p", tcs);

    baresgx_info("reading enclave memory..");
    printf("\tL mem at %p is %lx\n", (void*) tcs, *((uint64_t*) tcs));

    baresgx_info("calling enclave TCS..");

    uint8_t digest[DIGEST_LEN] = {0x0};

    char *message = "Bare-SGX rocks!";
    uint32_t message_len = strlen(message);

    arg_hmac.header_hmac.type = ENCL_OP_HMAC;
    arg_hmac.message = (uint8_t*) message;
    arg_hmac.message_len = message_len;
    arg_hmac.digest = digest;

    baresgx_enter_enclave(tcs, (uint64_t) &arg_hmac);
    printf("\nBare SGX currently hashing: \"Bare-SGX rocks!\" \n");
    print_encl_op_hmac(&arg_hmac, DIGEST_LEN);



	// uint8_t nonce[NONCE_LEN] = {0x0};

    // RAND_bytes(nonce,NONCE_LEN);

    // char *aad = "TCB should be minimized!";
    // uint32_t aadlen = strlen(aad);
   

    // char *m = "Bare-SGX rocks!";
    // uint32_t mlen = strlen(message);
	
	// uint8_t mac[MAC_LEN] = {0x0};
    // uint8_t *ciphertext = (uint8_t *)malloc(mlen * sizeof(uint8_t));
    // if (ciphertext == NULL) {
    //     fprintf(stderr, "Failed to allocate memory for ciphertext\n");
    //     return -1;
    // }

    dump_hex("\nKey: ", key_for_dump, KEY_LEN_AEAD);

    // arg_AEAD_ENC.header_AEAD.type = ENCL_OP_AEAD_ENC;
    // arg_AEAD_ENC.n = nonce;
    // arg_AEAD_ENC.aad = (uint8_t*) aad;
    // arg_AEAD_ENC.aadlen = aadlen;
    // arg_AEAD_ENC.m = (uint8_t*) m;
    // arg_AEAD_ENC.mlen = mlen;
    // arg_AEAD_ENC.cipher = (uint8_t*) ciphertext;
    // arg_AEAD_ENC.mac = mac;

    // baresgx_enter_enclave(tcs, (uint64_t) &arg_AEAD_ENC);
    // printf("\nBare SGX currently performing AEAD encryption using ChaCha20 and Poly1305: \"Bare-SGX rocks!\" \n");
    // print_encl_op_AEAD(&arg_AEAD_ENC);
    
    // baresgx_enter_enclave(tcs, (uint64_t) &arg_AEAD_ENC);
    // printf("\nBare SGX currently performing AES encryption: \"Bare-SGX rocks!\" \n");
    // print_encl_op_AEAD(&arg_AEAD_ENC);

    // arg_AEAD_DEC.header_AEAD.type = ENCL_OP_AEAD_DEC;
    // arg_AEAD_DEC.n = nonce;
    // arg_AEAD_DEC.aad = (uint8_t*) aad;
    // arg_AEAD_DEC.aadlen = aadlen;
    // arg_AEAD_DEC.m = (uint8_t*) m;
    // arg_AEAD_DEC.mlen = mlen;
    // arg_AEAD_DEC.cipher = (uint8_t*) arg_AEAD_ENC.cipher;
    // arg_AEAD_DEC.mac = arg_AEAD_ENC.mac;

    // print_encl_op_AEAD(&arg_AEAD_DEC);

    // printf("\nBare SGX currently performing AEAD decryption using ChaCha20 and Poly1305: \"Bare-SGX rocks!\" \n");
    // baresgx_enter_enclave(tcs, (uint64_t) &arg_AEAD_DEC);




    return 0;
}
