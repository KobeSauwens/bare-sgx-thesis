/* utility headers */
#include "../../common/debug.h"
#include <cacheutils.h>

/* SGX untrusted runtime */
#include <sgx_urts.h>
#include "Enclave/encl_u.h"

#define DIGEST_LEN      32
#define KEY_LEN_AEAD    32
#define KEY_LEN_HMAC    16
#define MAC_LEN         16
#define KEY_LEN_AES     16
#define NONCE_LEN       12

#define NUM_SAMPLES     1000
#define DELAY           1

uint64_t diff[NUM_SAMPLES];

#include <stdio.h>
#include <inttypes.h> // for portable printing of uint8_t

void print_args(
    sgx_enclave_id_t eid,
    int* allowed,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* mac,
    const uint8_t* m, size_t mlen,
    const uint8_t* aad, size_t aadlen,
    const uint8_t* nonce, size_t noncelen
) {
    printf("=== ChaCha20-Poly1305 Enclave Call Arguments ===\n");
    printf("Enclave ID: 0x%lx\n", eid);
    printf("Allowed flag address: %p\n", (void*)allowed);

    printf("Plaintext (m): ");
    for (size_t i = 0; i < mlen; i++) printf("%02x ", m[i]);
    printf("\nLength: %zu bytes\n", mlen);

    printf("AAD: ");
    for (size_t i = 0; i < aadlen; i++) printf("%02x ", aad[i]);
    printf("\nLength: %zu bytes\n", aadlen);

    printf("Nonce: ");
    for (size_t i = 0; i < noncelen; i++) printf("%02x ", nonce[i]);
    printf("\nLength: %zu bytes\n", noncelen);

    // These would only be filled after the ECALL
    printf("Ciphertext (out): ");
    for (size_t i = 0; i < ciphertext_len; i++) printf("%02x ", ciphertext[i]);
    printf("\n");

    printf("MAC (out): ");
    for (size_t i = 0; i < 16; i++) printf("%02x ", mac[i]); // 16 bytes for Poly1305 MAC
    printf("\n");
}


/* define untrusted OCALL functions here */

void ocall_print(const char *str)
{
    info("ocall_print: enclave says: '%s'", str);
}

void ocall_print_uint8_array(uint8_t *arr, size_t len) {
    printf("Print via ocall: \nsha256sum = ");
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", arr[i]);
    }
    printf("\n\n");
}

char *read_from_user(void)
{
    char *buffer = NULL;
    int len; size_t size;

    printf("Enter super secret password ('q' to exit): ");
    if ((len=getline(&buffer, &size, stdin)) != -1)
    {
        /* get rid of the terminating newline character */
        buffer[len-1]='\0';
        printf("--> You entered: '%s'\n", buffer);
        return buffer;
    }
    else
    {
        printf("--> failure to read line\n");
        return NULL;
    }
}

sgx_enclave_id_t create_enclave(void)
{
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_enclave_id_t eid = -1;

    info_event("Creating enclave...");
    SGX_ASSERT( sgx_create_enclave( "./Enclave/encl.so", /*debug=*/1,
                                    &token, &updated, &eid, NULL ) );

    return eid;
}

int compare(const void * a, const void * b) {
   return ( *(uint64_t*)a - *(uint64_t*)b );
}

#define TAG_LEN 32  // 256 bits

int main( int argc, char **argv )
{
    sgx_enclave_id_t eid = create_enclave();
    int rv = 1, secret = 0;
    int j, tsc1, tsc2, med, allowed = 0;

    uint8_t digest[TAG_LEN] = {0x0};

    char *message = "Bare-SGX rocks!";
    uint32_t message_len = strlen(message);
    
    /* =========================== START SOLUTION =========================== */
    SGX_ASSERT(encl_op_hmac(eid, &allowed, digest, (uint8_t*) message, message_len));
    //printf("The return value was: %i \n",allowed);
    //#printf("The secret was 0x%08x \n",secret);
    /* ============================ END SOLUTION ============================ */
    printf("Print via main: \n");
    dump_hex("sha256sum", digest, TAG_LEN);
    
    uint8_t nonce[NONCE_LEN] = {0x0};

    //RAND_bytes(nonce,NONCE_LEN);

    char *aad = "TCB should be minimized!";
    uint32_t aadlen = strlen(aad);
   

    char *m = "Bare-SGX rocks!";
    uint32_t mlen = strlen(message);
	
	uint8_t mac[MAC_LEN] = {0x0};
    
    uint8_t *ciphertext = malloc(mlen);
    uint8_t *decrypted = malloc(mlen);

    if (ciphertext == NULL || decrypted == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    SGX_ASSERT( encl_op_chacha20poly1305_enc(eid, &allowed, ciphertext, mac, m, mlen, aad, aadlen, nonce) );
    print_args(eid, &allowed, ciphertext, mlen, mac, m, mlen, aad, aadlen, nonce, NONCE_LEN);

    SGX_ASSERT( encl_op_chacha20poly1305_dec(eid, &allowed, ciphertext, mac, decrypted, mlen, aad, aadlen, nonce) );
    print_args(eid, &allowed, ciphertext, mlen, mac, decrypted, mlen, aad, aadlen, nonce, NONCE_LEN);

    info_event("destroying SGX enclave");
    SGX_ASSERT( sgx_destroy_enclave( eid ) );

    info("all is well; exiting..");
	return 0;
}
