#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_tcrypto.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif

sgx_status_t printSecret(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t createKeyPair(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* p_public);
sgx_status_t computeSharedKey(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* p_public_B);
sgx_status_t readPSK(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* message, int* correct_psk);
sgx_status_t getPSK(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* message);
sgx_status_t getChallenge(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* message);
sgx_status_t checkChallenge(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* result, int* correct_challenge);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
