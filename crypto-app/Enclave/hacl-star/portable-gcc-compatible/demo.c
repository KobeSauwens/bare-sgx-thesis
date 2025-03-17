#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "Hacl_Hash_SHA2.h"  // Include HACL* SHA2 header

int main() {
    // Example input message
    const char *message = "Bare-SGX rocks!";
    size_t message_len = strlen(message);

    // Output buffer for SHA-256 hash (256 bits = 32 bytes)
    uint8_t hash_output[32];

    printf("Currently hashing: \"%s\"\n", message);

    // Compute SHA-256 hash
    Hacl_Hash_SHA2_hash_256(hash_output, (uint8_t *)message, message_len);

    // Print hash in hexadecimal format
    printf("SHA-256 Hash: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", hash_output[i]);
    }
    printf("\n");

    return 0;
}
