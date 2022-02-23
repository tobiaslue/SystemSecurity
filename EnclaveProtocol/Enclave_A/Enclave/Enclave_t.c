#include "Enclave_t.h"

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


typedef struct ms_printSecret_t {
	sgx_status_t ms_retval;
} ms_printSecret_t;

typedef struct ms_createKeyPair_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t* ms_p_public;
} ms_createKeyPair_t;

typedef struct ms_computeSharedKey_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t* ms_p_public_B;
} ms_computeSharedKey_t;

typedef struct ms_readPSK_t {
	sgx_status_t ms_retval;
	unsigned char* ms_message;
	int* ms_correct_psk;
} ms_readPSK_t;

typedef struct ms_getPSK_t {
	sgx_status_t ms_retval;
	unsigned char* ms_message;
} ms_getPSK_t;

typedef struct ms_getChallenge_t {
	sgx_status_t ms_retval;
	unsigned char* ms_message;
} ms_getChallenge_t;

typedef struct ms_checkChallenge_t {
	sgx_status_t ms_retval;
	unsigned char* ms_result;
	int* ms_correct_challenge;
} ms_checkChallenge_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL sgx_printSecret(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_printSecret_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_printSecret_t* ms = SGX_CAST(ms_printSecret_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = printSecret();


	return status;
}

static sgx_status_t SGX_CDECL sgx_createKeyPair(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_createKeyPair_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_createKeyPair_t* ms = SGX_CAST(ms_createKeyPair_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_p_public = ms->ms_p_public;
	size_t _len_p_public = 64;
	sgx_ec256_public_t* _in_p_public = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_public, _len_p_public);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_public != NULL && _len_p_public != 0) {
		if ((_in_p_public = (sgx_ec256_public_t*)malloc(_len_p_public)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_public, 0, _len_p_public);
	}

	ms->ms_retval = createKeyPair(_in_p_public);
	if (_in_p_public) {
		if (memcpy_s(_tmp_p_public, _len_p_public, _in_p_public, _len_p_public)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_public) free(_in_p_public);
	return status;
}

static sgx_status_t SGX_CDECL sgx_computeSharedKey(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_computeSharedKey_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_computeSharedKey_t* ms = SGX_CAST(ms_computeSharedKey_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_p_public_B = ms->ms_p_public_B;
	size_t _len_p_public_B = 64;
	sgx_ec256_public_t* _in_p_public_B = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_public_B, _len_p_public_B);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_public_B != NULL && _len_p_public_B != 0) {
		_in_p_public_B = (sgx_ec256_public_t*)malloc(_len_p_public_B);
		if (_in_p_public_B == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_public_B, _len_p_public_B, _tmp_p_public_B, _len_p_public_B)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = computeSharedKey(_in_p_public_B);

err:
	if (_in_p_public_B) free(_in_p_public_B);
	return status;
}

static sgx_status_t SGX_CDECL sgx_readPSK(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_readPSK_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_readPSK_t* ms = SGX_CAST(ms_readPSK_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_message = ms->ms_message;
	size_t _len_message = 16;
	unsigned char* _in_message = NULL;
	int* _tmp_correct_psk = ms->ms_correct_psk;
	size_t _len_correct_psk = sizeof(int);
	int* _in_correct_psk = NULL;

	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);
	CHECK_UNIQUE_POINTER(_tmp_correct_psk, _len_correct_psk);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_message != NULL && _len_message != 0) {
		if ( _len_message % sizeof(*_tmp_message) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_message = (unsigned char*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_message, _len_message, _tmp_message, _len_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_correct_psk != NULL && _len_correct_psk != 0) {
		if ( _len_correct_psk % sizeof(*_tmp_correct_psk) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_correct_psk = (int*)malloc(_len_correct_psk)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_correct_psk, 0, _len_correct_psk);
	}

	ms->ms_retval = readPSK(_in_message, _in_correct_psk);
	if (_in_correct_psk) {
		if (memcpy_s(_tmp_correct_psk, _len_correct_psk, _in_correct_psk, _len_correct_psk)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_message) free(_in_message);
	if (_in_correct_psk) free(_in_correct_psk);
	return status;
}

static sgx_status_t SGX_CDECL sgx_getPSK(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_getPSK_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_getPSK_t* ms = SGX_CAST(ms_getPSK_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_message = ms->ms_message;
	size_t _len_message = 16;
	unsigned char* _in_message = NULL;

	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_message != NULL && _len_message != 0) {
		if ( _len_message % sizeof(*_tmp_message) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_message = (unsigned char*)malloc(_len_message)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_message, 0, _len_message);
	}

	ms->ms_retval = getPSK(_in_message);
	if (_in_message) {
		if (memcpy_s(_tmp_message, _len_message, _in_message, _len_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_message) free(_in_message);
	return status;
}

static sgx_status_t SGX_CDECL sgx_getChallenge(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_getChallenge_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_getChallenge_t* ms = SGX_CAST(ms_getChallenge_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_message = ms->ms_message;
	size_t _len_message = 8;
	unsigned char* _in_message = NULL;

	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_message != NULL && _len_message != 0) {
		if ( _len_message % sizeof(*_tmp_message) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_message = (unsigned char*)malloc(_len_message)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_message, 0, _len_message);
	}

	ms->ms_retval = getChallenge(_in_message);
	if (_in_message) {
		if (memcpy_s(_tmp_message, _len_message, _in_message, _len_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_message) free(_in_message);
	return status;
}

static sgx_status_t SGX_CDECL sgx_checkChallenge(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_checkChallenge_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_checkChallenge_t* ms = SGX_CAST(ms_checkChallenge_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_result = ms->ms_result;
	size_t _len_result = 4;
	unsigned char* _in_result = NULL;
	int* _tmp_correct_challenge = ms->ms_correct_challenge;
	size_t _len_correct_challenge = sizeof(int);
	int* _in_correct_challenge = NULL;

	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);
	CHECK_UNIQUE_POINTER(_tmp_correct_challenge, _len_correct_challenge);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_result = (unsigned char*)malloc(_len_result);
		if (_in_result == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_result, _len_result, _tmp_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_correct_challenge != NULL && _len_correct_challenge != 0) {
		if ( _len_correct_challenge % sizeof(*_tmp_correct_challenge) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_correct_challenge = (int*)malloc(_len_correct_challenge)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_correct_challenge, 0, _len_correct_challenge);
	}

	ms->ms_retval = checkChallenge(_in_result, _in_correct_challenge);
	if (_in_correct_challenge) {
		if (memcpy_s(_tmp_correct_challenge, _len_correct_challenge, _in_correct_challenge, _len_correct_challenge)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_result) free(_in_result);
	if (_in_correct_challenge) free(_in_correct_challenge);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[7];
} g_ecall_table = {
	7,
	{
		{(void*)(uintptr_t)sgx_printSecret, 0, 0},
		{(void*)(uintptr_t)sgx_createKeyPair, 0, 0},
		{(void*)(uintptr_t)sgx_computeSharedKey, 0, 0},
		{(void*)(uintptr_t)sgx_readPSK, 0, 0},
		{(void*)(uintptr_t)sgx_getPSK, 0, 0},
		{(void*)(uintptr_t)sgx_getChallenge, 0, 0},
		{(void*)(uintptr_t)sgx_checkChallenge, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][7];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

