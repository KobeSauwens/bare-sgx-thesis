#include "test_encl_t.h"
//#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
//#include "sgx_lfence.h" /* for sgx_lfence */

//#include <errno.h>
//#include <mbusafecrt.h> /* for memcpy_s etc */
//#include <stdlib.h> /* for malloc/free etc */

#define SGX_CDECL
#define SGX_EXTERNC //sextern // C++ is not suppported in Bare SGX

typedef enum {
    SGX_SUCCESS = 0x00000000,
    SGX_ERROR_UNEXPECTED = 0x00010001,
    SGX_ERROR_INVALID_PARAMETER = 0x00010003,
    SGX_ERROR_OUT_OF_MEMORY = 0x00010005,
} sgx_status_t;

// used to be sgx_is_outside_enclave
#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

// used to be sgx_is_outside_enclave
#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

// used to be sgx_is_within_enclave
#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! is_inside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)



typedef struct ms_do_encl_op_hmac_t {
	struct encl_op_hmac* ms_op;
} ms_do_encl_op_hmac_t;

static sgx_status_t SGX_CDECL sgx_do_encl_op_hmac(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_do_encl_op_hmac_t));
	//
	// fence after pointer checks
	//
	//sgx_lfence();
	ms_do_encl_op_hmac_t* ms = SGX_CAST(ms_do_encl_op_hmac_t*, pms);
	ms_do_encl_op_hmac_t __in_ms;
	//if (memcpy_s(&__in_ms, sizeof(ms_do_encl_op_hmac_t), ms, sizeof(ms_do_encl_op_hmac_t))) {
	memcpy(&__in_ms, ms, sizeof(ms_do_encl_op_hmac_t));
	//	return SGX_ERROR_UNEXPECTED;
	//}
	sgx_status_t status = SGX_SUCCESS;
	struct encl_op_hmac* _tmp_op = __in_ms.ms_op;
	size_t _len_op = sizeof(struct encl_op_hmac);
	struct encl_op_hmac* _in_op = NULL;

	CHECK_UNIQUE_POINTER(_tmp_op, _len_op);

	//
	// fence after pointer checks
	//
	//sgx_lfence();

	if (_tmp_op != NULL && _len_op != 0) {
		_in_op = (struct encl_op_hmac*)malloc(_len_op);
		if (_in_op == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		//if (memcpy_s(_in_op, _len_op, _tmp_op, _len_op)) { 
		memcpy(_in_op, _tmp_op, _len_op); // used to be memcpy_s

	}
	do_encl_op_hmac(_in_op);
	if (_in_op) {
		//if (memcpy_verw_s(_tmp_op, _len_op, _in_op, _len_op)) { // used to be memcpy_verw_s
		memcpy(_tmp_op, _in_op, _len_op); // used to be memcpy_verw_s
	}

err:
	if (_in_op) free(_in_op);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_do_encl_op_hmac, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


