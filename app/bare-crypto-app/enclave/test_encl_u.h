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


sgx_status_t do_encl_op_hmac(sgx_enclave_id_t eid, struct encl_op_hmac* op);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
