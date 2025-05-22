#ifndef TEST_ENCL_T_H__
#define TEST_ENCL_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "test_encl.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void do_encl_op_hmac(uint8_t* digest, uint8_t* message, uint32_t message_len);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
