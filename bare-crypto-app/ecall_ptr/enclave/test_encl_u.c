#include "test_encl_u.h"
#include <errno.h>

typedef struct ms_encl_body_t {
	size_t ms_rdi;
	size_t ms_rsi;
} ms_encl_body_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_test_encl = {
	0,
	{ NULL },
};
sgx_status_t encl_body(sgx_enclave_id_t eid, size_t rdi, size_t rsi)
{
	sgx_status_t status;
	ms_encl_body_t ms;
	ms.ms_rdi = rdi;
	ms.ms_rsi = rsi;
	status = sgx_ecall(eid, 0, &ocall_table_test_encl, &ms);
	return status;
}

