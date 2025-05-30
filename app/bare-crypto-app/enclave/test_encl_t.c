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


typedef struct ms_encl_HMAC_t {
	uint8_t* ms_digest;
	uint8_t* ms_message;
	uint32_t ms_message_len;
} ms_encl_HMAC_t;

typedef struct ms_encl_AEAD_enc_t {
	uint8_t* ms_ciphertext;
	uint8_t* ms_tag;
	uint8_t* ms_plaintext;
	uint32_t ms_plaintext_len;
	uint8_t* ms_data;
	uint32_t ms_data_len;
	uint8_t* ms_nonce;
} ms_encl_AEAD_enc_t;

typedef struct ms_encl_AEAD_dec_t {
	uint8_t* ms_plaintext;
	uint8_t* ms_ciphertext;
	uint32_t ms_ciphertext_len;
	uint8_t* ms_data;
	uint32_t ms_data_len;
	uint8_t* ms_nonce;
	uint8_t* ms_tag;
} ms_encl_AEAD_dec_t;

static sgx_status_t SGX_CDECL sgx_encl_HMAC(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_HMAC_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_HMAC_t* ms = SGX_CAST(ms_encl_HMAC_t*, pms);
	ms_encl_HMAC_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_HMAC_t), ms, sizeof(ms_encl_HMAC_t))) {
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
	encl_HMAC(_in_digest, _in_message, _tmp_message_len);
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

static sgx_status_t SGX_CDECL sgx_encl_AEAD_enc(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_AEAD_enc_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_AEAD_enc_t* ms = SGX_CAST(ms_encl_AEAD_enc_t*, pms);
	ms_encl_AEAD_enc_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_AEAD_enc_t), ms, sizeof(ms_encl_AEAD_enc_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_ciphertext = __in_ms.ms_ciphertext;
	uint32_t _tmp_plaintext_len = __in_ms.ms_plaintext_len;
	size_t _len_ciphertext = _tmp_plaintext_len;
	uint8_t* _in_ciphertext = NULL;
	uint8_t* _tmp_tag = __in_ms.ms_tag;
	size_t _len_tag = 32;
	uint8_t* _in_tag = NULL;
	uint8_t* _tmp_plaintext = __in_ms.ms_plaintext;
	size_t _len_plaintext = _tmp_plaintext_len;
	uint8_t* _in_plaintext = NULL;
	uint8_t* _tmp_data = __in_ms.ms_data;
	uint32_t _tmp_data_len = __in_ms.ms_data_len;
	size_t _len_data = _tmp_data_len;
	uint8_t* _in_data = NULL;
	uint8_t* _tmp_nonce = __in_ms.ms_nonce;
	size_t _len_nonce = 12;
	uint8_t* _in_nonce = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ciphertext, _len_ciphertext);
	CHECK_UNIQUE_POINTER(_tmp_tag, _len_tag);
	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);
	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_nonce, _len_nonce);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ciphertext != NULL && _len_ciphertext != 0) {
		if ( _len_ciphertext % sizeof(*_tmp_ciphertext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ciphertext = (uint8_t*)malloc(_len_ciphertext)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ciphertext, 0, _len_ciphertext);
	}
	if (_tmp_tag != NULL && _len_tag != 0) {
		if ( _len_tag % sizeof(*_tmp_tag) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_tag = (uint8_t*)malloc(_len_tag)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_tag, 0, _len_tag);
	}
	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		if ( _len_plaintext % sizeof(*_tmp_plaintext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_plaintext = (uint8_t*)malloc(_len_plaintext);
		if (_in_plaintext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_plaintext, _len_plaintext, _tmp_plaintext, _len_plaintext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_data != NULL && _len_data != 0) {
		if ( _len_data % sizeof(*_tmp_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data = (uint8_t*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_nonce != NULL && _len_nonce != 0) {
		if ( _len_nonce % sizeof(*_tmp_nonce) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_nonce = (uint8_t*)malloc(_len_nonce);
		if (_in_nonce == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_nonce, _len_nonce, _tmp_nonce, _len_nonce)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	encl_AEAD_enc(_in_ciphertext, _in_tag, _in_plaintext, _tmp_plaintext_len, _in_data, _tmp_data_len, _in_nonce);
	if (_in_ciphertext) {
		if (memcpy_verw_s(_tmp_ciphertext, _len_ciphertext, _in_ciphertext, _len_ciphertext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_tag) {
		if (memcpy_verw_s(_tmp_tag, _len_tag, _in_tag, _len_tag)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ciphertext) free(_in_ciphertext);
	if (_in_tag) free(_in_tag);
	if (_in_plaintext) free(_in_plaintext);
	if (_in_data) free(_in_data);
	if (_in_nonce) free(_in_nonce);
	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_AEAD_dec(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_AEAD_dec_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_AEAD_dec_t* ms = SGX_CAST(ms_encl_AEAD_dec_t*, pms);
	ms_encl_AEAD_dec_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_AEAD_dec_t), ms, sizeof(ms_encl_AEAD_dec_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_plaintext = __in_ms.ms_plaintext;
	uint32_t _tmp_ciphertext_len = __in_ms.ms_ciphertext_len;
	size_t _len_plaintext = _tmp_ciphertext_len;
	uint8_t* _in_plaintext = NULL;
	uint8_t* _tmp_ciphertext = __in_ms.ms_ciphertext;
	size_t _len_ciphertext = _tmp_ciphertext_len;
	uint8_t* _in_ciphertext = NULL;
	uint8_t* _tmp_data = __in_ms.ms_data;
	uint32_t _tmp_data_len = __in_ms.ms_data_len;
	size_t _len_data = _tmp_data_len;
	uint8_t* _in_data = NULL;
	uint8_t* _tmp_nonce = __in_ms.ms_nonce;
	size_t _len_nonce = 12;
	uint8_t* _in_nonce = NULL;
	uint8_t* _tmp_tag = __in_ms.ms_tag;
	size_t _len_tag = 32;
	uint8_t* _in_tag = NULL;

	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);
	CHECK_UNIQUE_POINTER(_tmp_ciphertext, _len_ciphertext);
	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_nonce, _len_nonce);
	CHECK_UNIQUE_POINTER(_tmp_tag, _len_tag);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		if ( _len_plaintext % sizeof(*_tmp_plaintext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_plaintext = (uint8_t*)malloc(_len_plaintext)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_plaintext, 0, _len_plaintext);
	}
	if (_tmp_ciphertext != NULL && _len_ciphertext != 0) {
		if ( _len_ciphertext % sizeof(*_tmp_ciphertext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ciphertext = (uint8_t*)malloc(_len_ciphertext);
		if (_in_ciphertext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ciphertext, _len_ciphertext, _tmp_ciphertext, _len_ciphertext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_data != NULL && _len_data != 0) {
		if ( _len_data % sizeof(*_tmp_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data = (uint8_t*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_nonce != NULL && _len_nonce != 0) {
		if ( _len_nonce % sizeof(*_tmp_nonce) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_nonce = (uint8_t*)malloc(_len_nonce);
		if (_in_nonce == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_nonce, _len_nonce, _tmp_nonce, _len_nonce)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_tag != NULL && _len_tag != 0) {
		if ( _len_tag % sizeof(*_tmp_tag) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tag = (uint8_t*)malloc(_len_tag);
		if (_in_tag == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tag, _len_tag, _tmp_tag, _len_tag)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	encl_AEAD_dec(_in_plaintext, _in_ciphertext, _tmp_ciphertext_len, _in_data, _tmp_data_len, _in_nonce, _in_tag);
	if (_in_plaintext) {
		if (memcpy_verw_s(_tmp_plaintext, _len_plaintext, _in_plaintext, _len_plaintext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_plaintext) free(_in_plaintext);
	if (_in_ciphertext) free(_in_ciphertext);
	if (_in_data) free(_in_data);
	if (_in_nonce) free(_in_nonce);
	if (_in_tag) free(_in_tag);
	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_return(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	encl_return();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_encl_HMAC, 0, 0},
		{(void*)(uintptr_t)sgx_encl_AEAD_enc, 0, 0},
		{(void*)(uintptr_t)sgx_encl_AEAD_dec, 0, 0},
		{(void*)(uintptr_t)sgx_encl_return, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


