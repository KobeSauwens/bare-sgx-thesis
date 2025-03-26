#ifndef TEST_ENCL_U_H__
#define TEST_ENCL_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t encl_body(sgx_enclave_id_t eid, size_t rdi, size_t rsi);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
