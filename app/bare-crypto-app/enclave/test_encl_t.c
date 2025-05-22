#include "test_encl_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_do_encl_op_hmac_t {
	uint8_t* ms_digest;
	uint8_t* ms_message;
	uint32_t ms_message_len;
} ms_do_encl_op_hmac_t;

static sgx_status_t SGX_CDECL sgx_do_encl_op_hmac(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_do_encl_op_hmac_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_do_encl_op_hmac_t* ms = SGX_CAST(ms_do_encl_op_hmac_t*, pms);
	ms_do_encl_op_hmac_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_do_encl_op_hmac_t), ms, sizeof(ms_do_encl_op_hmac_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_digest = __in_ms.ms_digest;
	size_t _len_digest = 32;
	uint8_t* _in_digest = NULL;
	uint8_t* _tmp_message = __in_ms.ms_message;
	uint32_t _tmp_message_len = __in_ms.ms_message_len;
	size_t _len_message = _tmp_message_len;
	uint8_t* _in_message = NULL;

	CHECK_UNIQUE_POINTER(_tmp_digest, _len_digest);
	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_digest != NULL && _len_digest != 0) {
		if ( _len_digest % sizeof(*_tmp_digest) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_digest = (uint8_t*)malloc(_len_digest)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_digest, 0, _len_digest);
	}
	if (_tmp_message != NULL && _len_message != 0) {
		if ( _len_message % sizeof(*_tmp_message) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_message = (uint8_t*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_message, _len_message, _tmp_message, _len_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	do_encl_op_hmac(_in_digest, _in_message, _tmp_message_len);
	if (_in_digest) {
		if (memcpy_verw_s(_tmp_digest, _len_digest, _in_digest, _len_digest)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_digest) free(_in_digest);
	if (_in_message) free(_in_message);
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


