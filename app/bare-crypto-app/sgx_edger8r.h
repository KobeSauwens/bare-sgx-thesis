#ifndef SGX_EDGER8R_H
#define SGX_EDGER8R_H

#include "../../urts/include/baresgx/urts.h"


typedef enum {
    SGX_SUCCESS = 0x00000000,
    SGX_ERROR_UNEXPECTED = 0x00010001,
    SGX_ERROR_INVALID_PARAMETER = 0x00010003,
    SGX_ERROR_OUT_OF_MEMORY = 0x00010004,
} sgx_status_t;

#define SGX_CDECL
#define SGX_EXTERNC //sextern // C++ is not suppported in Bare SGX

static inline sgx_status_t sgx_ecall_redirect(void* eid, uint64_t ecall_id, void* ms)
{
    return baresgx_enter_enclave(eid, ms, ecall_id);
}

#define sgx_ecall(eid, ecall_id, ocall_table, ms) sgx_ecall_redirect(eid, ecall_id, ms)


typedef uint64_t sgx_enclave_id_t;

#endif