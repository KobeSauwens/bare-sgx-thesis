#include "test_encl_u.h"
#include <errno.h>

typedef struct ms_do_encl_op_hmac_t {
	uint8_t* ms_digest;
	uint8_t* ms_message;
	uint32_t ms_message_len;
} ms_do_encl_op_hmac_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_test_encl = {
	0,
	{ NULL },
};
sgx_status_t do_encl_op_hmac(sgx_enclave_id_t eid, uint8_t* digest, uint8_t* message, uint32_t message_len)
{
	sgx_status_t status;
	ms_do_encl_op_hmac_t ms;
	ms.ms_digest = digest;
	ms.ms_message = message;
	ms.ms_message_len = message_len;
	status = sgx_ecall(eid, 0, &ocall_table_test_encl, &ms);
	return status;
}

