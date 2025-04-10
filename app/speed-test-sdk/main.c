/* utility headers */
#include "../../common/debug.h"
#include <cacheutils.h>
#include <time.h> // For timing
#include "../../sgx-step/libsgxstep/cpu.h"
#include "../../sgx-step/libsgxstep/sched.h"
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

    int result = prepare_system_for_benchmark(100);
    if (result == 0) {
        printf("System prepared successfully\n");
    } else {
        printf("Failed to prepare system\n");
    }
    FILE *fp = fopen("../../enclave_timing_return.csv", "w");  // Open file in write mode
    
    if (fp == NULL) {
        printf("Error opening file!\n");
        return 1;
    }

    // Write CSV header
    fprintf(fp, "Iteration,ElapsedCycles\n");

    for(uint32_t i = 0; i < 100000; ++i)
    {
        SGX_ASSERT( ecall_get_secret(eid) );

        uint64_t start = rdtsc_begin();

        SGX_ASSERT( ecall_get_secret(eid) );

        uint64_t end = rdtsc_end();
        
        uint64_t elapsed_clocks = end - start;

        fprintf(fp, "%u,%lu\n", i, elapsed_clocks);
    }

    fclose(fp);



    info_event("destroying SGX enclave");
    
    SGX_ASSERT( sgx_destroy_enclave( eid ) );

    info("all is well; exiting..");
	return 0;
}
