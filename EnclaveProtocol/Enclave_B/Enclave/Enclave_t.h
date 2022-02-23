#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tcrypto.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t printSecret(void);
sgx_status_t createKeyPair(sgx_ec256_public_t* p_public);
sgx_status_t computeSharedKey(sgx_ec256_public_t* p_public_A);
sgx_status_t readPSK(unsigned char* message, int* correct_psk);
sgx_status_t getPSK(unsigned char* message);
sgx_status_t completeChallenge(unsigned char* message, unsigned char* result);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
