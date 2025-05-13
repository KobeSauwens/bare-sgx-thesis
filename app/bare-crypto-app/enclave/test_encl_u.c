#include "test_encl_u.h"
#include <errno.h>

typedef struct ms_do_encl_op_hmac_t {
	struct encl_op_hmac* ms_op;
} ms_do_encl_op_hmac_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_test_encl = {
	0,
	{ NULL },
};
sgx_status_t do_encl_op_hmac(sgx_enclave_id_t eid, struct encl_op_hmac* op)
{
	sgx_status_t status;
	ms_do_encl_op_hmac_t ms;
	ms.ms_op = op;
	status = sgx_ecall(eid, 0, &ocall_table_test_encl, &ms);
	return status;
}

