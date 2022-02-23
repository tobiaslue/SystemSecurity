#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_printSecret_t {
	sgx_status_t ms_retval;
} ms_printSecret_t;

typedef struct ms_createKeyPair_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t* ms_p_public;
} ms_createKeyPair_t;

typedef struct ms_computeSharedKey_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t* ms_p_public_A;
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

typedef struct ms_completeChallenge_t {
	sgx_status_t ms_retval;
	unsigned char* ms_message;
	unsigned char* ms_result;
} ms_completeChallenge_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_print_string,
	}
};
sgx_status_t printSecret(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_printSecret_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t createKeyPair(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* p_public)
{
	sgx_status_t status;
	ms_createKeyPair_t ms;
	ms.ms_p_public = p_public;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t computeSharedKey(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* p_public_A)
{
	sgx_status_t status;
	ms_computeSharedKey_t ms;
	ms.ms_p_public_A = p_public_A;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t readPSK(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* message, int* correct_psk)
{
	sgx_status_t status;
	ms_readPSK_t ms;
	ms.ms_message = message;
	ms.ms_correct_psk = correct_psk;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t getPSK(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* message)
{
	sgx_status_t status;
	ms_getPSK_t ms;
	ms.ms_message = message;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t completeChallenge(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* message, unsigned char* result)
{
	sgx_status_t status;
	ms_completeChallenge_t ms;
	ms.ms_message = message;
	ms.ms_result = result;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

