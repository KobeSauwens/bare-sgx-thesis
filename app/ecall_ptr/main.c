#include <stdio.h>
#include "baresgx/urts.h"
#include "enclave/test_encl.h"

#define ENCLAVE_PATH    "enclave/encl.elf"
#define ENCLAVE_DEBUG   0

int main(void)
{
    struct encl_op_math arg;
    uint64_t rv = -1;
    void *tcs;

    tcs = baresgx_load_elf_enclave(ENCLAVE_PATH, ENCLAVE_DEBUG);
    baresgx_info("loaded enclave at %p", tcs);

    baresgx_info("reading enclave memory..");
    printf("\tL mem at %p is %lx\n", (void*) tcs, *((uint64_t*) tcs));

    baresgx_info("calling enclave TCS..");

    arg.header.type = ENCL_OP_ADD;
    arg.val1 = 1300;
    arg.val2 = 37;
    arg.rv_pt = &rv;
    baresgx_enter_enclave(tcs, (uint64_t) &arg);
    printf("\tL enclave returned %ld + %ld = %ld\n", arg.val1, arg.val2, rv);

    arg.header.type = ENCL_OP_SUB;
    arg.val1 = 1300;
    arg.val2 = 37;
    arg.rv_pt = &rv;
    baresgx_enter_enclave(tcs, (uint64_t) &arg);
    printf("\tL enclave returned %ld - %ld = %ld\n", arg.val1, arg.val2, rv);

    //Confused deputy attack trying to dereference memory inside enclave
    arg.header.type = (uint64_t) tcs;
    arg.val1 = 1300;
    arg.val2 = 37;
    arg.rv_pt = &rv;
    baresgx_enter_enclave(tcs, (uint64_t) &arg);
    printf("\tL enclave returned %ld - %ld = %ld\n", arg.val1, arg.val2, rv);


    return 0;
}
