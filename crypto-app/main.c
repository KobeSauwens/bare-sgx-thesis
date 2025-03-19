/* utility headers */
#include "../common/debug.h"
#include <cacheutils.h>

/* SGX untrusted runtime */
#include <sgx_urts.h>
#include "Enclave/encl_u.h"

#define NUM_SAMPLES     1000
#define DELAY           1

uint64_t diff[NUM_SAMPLES];

/* define untrusted OCALL functions here */

void ocall_print(const char *str)
{
    info("ocall_print: enclave says: '%s'", str);
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

int main( int argc, char **argv )
{
    sgx_enclave_id_t eid = create_enclave();
    int rv = 1, secret = 0;
    int j, tsc1, tsc2, med, allowed = 0;

    uint8_t digest[32];


    const char *message = "Bare-SGX rocks!";
    uint32_t message_len = strlen(message);
    uint8_t *message_int = (uint8_t*) message;

    //SGX_ASSERT(ecall_dummy(eid, &allowed, rv) )
    /* =========================== START SOLUTION =========================== */
    SGX_ASSERT(ecall_get_secret(eid, &allowed, digest, message_int, message_len) );
    //printf("The return value was: %i \n",digest);
    //#printf("The secret was 0x%08x \n",secret);
    /* ============================ END SOLUTION ============================ */


    info_event("destroying SGX enclave");
    SGX_ASSERT( sgx_destroy_enclave( eid ) );

    info("all is well; exiting..");
	return 0;
}
