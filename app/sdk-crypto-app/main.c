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
    printf("Enclave ID:\t\t0x%lx\n", eid);
    printf("Allowed flag addr:\t%p\n\n", (void*)allowed);

    printf("Plaintext [len: %zu]:\t", mlen);
    for (size_t i = 0; i < mlen; i++) printf("%02x ", m[i]);
    printf("\n");

    printf("AAD [len: %zu]:\t\t", aadlen);
    for (size_t i = 0; i < aadlen; i++) printf("%02x ", aad[i]);
    printf("\n");

    printf("Nonce [len: %zu]:\t", noncelen);
    for (size_t i = 0; i < noncelen; i++) printf("%02x ", nonce[i]);
    printf("\n");

    printf("Ciphertext [len: %zu]:\t", ciphertext_len);
    for (size_t i = 0; i < ciphertext_len; i++) printf("%02x ", ciphertext[i]);
    printf("\n");

    printf("MAC [len: 16]:\t\t");
    for (size_t i = 0; i < 16; i++) printf("%02x ", mac[i]);
    printf("\n");
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
    
    SGX_ASSERT(encl_op_hmac(eid, &allowed, digest, (uint8_t*) message, message_len));
    printf("Print via main: \n");
    dump_hex("sha256sum", digest, TAG_LEN);
    
    uint8_t nonce[NONCE_LEN] = {0x0};


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
