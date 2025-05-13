#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include "../../external/sgx-step/libsgxstep/cpu.h"
#include "../../external/sgx-step/libsgxstep/sched.h"
#include "baresgx/urts.h"
#include "enclave/test_encl.h"

#define ENCLAVE_PATH "enclave/encl.elf"
#define ENCLAVE_DEBUG 0
#define ITERATIONS 100000

int main(void) {
    void *tcs = baresgx_load_elf_enclave(ENCLAVE_PATH, ENCLAVE_DEBUG);
    struct encl_op_ret arg_ret;
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

    arg_ret.header.type = ENCL_OP_RET;

    if (prepare_system_for_benchmark(100) != 0) {
        printf("Failed to prepare system\n");
        return 1;
    }
    printf("System prepared successfully\n");

    for (uint32_t i = 0; i < ITERATIONS; ++i) {
        BARESGX_ASSERT(baresgx_enter_enclave(tcs, (uint64_t)&arg_ret));

        uint64_t start = rdtsc_begin();
        
        BARESGX_ASSERT(baresgx_enter_enclave(tcs, (uint64_t)&arg_ret));

        uint64_t end = rdtsc_end();
       
        cycles[i] = end - start;
    }

    // Write results to file
    for (uint32_t i = 0; i < ITERATIONS; ++i) {
        fprintf(fp, "%u,%lu\n", i, cycles[i]);
    }

    free(cycles);
    fclose(fp);
    printf("Results written to %s\n", filename);
    return 0;
}