#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>


int enclave_secret = 42;
sgx_ec256_private_t p_private;
sgx_ec256_dh_shared_t shared_key;
sgx_ecc_state_handle_t p_ecc_handle;
sgx_aes_ctr_128bit_key_t *enc_key = (sgx_aes_ctr_128bit_key_t *)malloc(sizeof(uint8_t)*16);


int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

sgx_status_t printSecret()
{
  char buf[BUFSIZ] = {"From Enclave: Hello from the enclave.\n"};
  ocall_print_string(buf);
  printf("From Enclave: Another way to print from the Enclave. My secret is %u.\n", enclave_secret);
  return SGX_SUCCESS;
}

/*************************
 * BEGIN 2. Key Pair Generation
 *************************/
sgx_status_t createKeyPair(sgx_ec256_public_t *p_public){
  sgx_status_t sgx_status;

  sgx_status = sgx_ecc256_open_context(&p_ecc_handle);
  if (sgx_status != SGX_SUCCESS) {
      return sgx_status;
  }
  
  sgx_status = sgx_ecc256_create_key_pair(&p_private, p_public, p_ecc_handle);
  if (sgx_status != SGX_SUCCESS) {
      return sgx_status;
  }

  return sgx_status;
}
/*************************
 * END 2. Key Pair Generation
 *************************/

/*************************
 * BEGIN 3. Calculate Shared Secret
 *************************/
sgx_status_t computeSharedKey(sgx_ec256_public_t *p_public_A){
  sgx_status_t sgx_status;
  sgx_status = sgx_ecc256_compute_shared_dhkey(&p_private, p_public_A, &shared_key, p_ecc_handle);
  if (sgx_status != SGX_SUCCESS) {
      return sgx_status;
  }
  sgx_status = sgx_ecc256_close_context(p_ecc_handle);
  if (sgx_status != SGX_SUCCESS) {
      return sgx_status;
  }
  enc_key = (sgx_aes_ctr_128bit_key_t *)&shared_key.s;
  return sgx_status;
}
/*************************
 * END 3. Calculate Shared Secret
 *************************/

sgx_status_t getPSK(unsigned char* message){
  sgx_status_t sgx_status;

  unsigned char bob[16] = "I AM BOBOB";
  uint8_t iv[16];
  memset(iv, 0, 16);

  sgx_status = sgx_aes_ctr_encrypt(enc_key, bob, 11, iv, 1, message);
  
  return sgx_status;
}

sgx_status_t readPSK(unsigned char* message, int *correct_psk){
  sgx_status_t sgx_status;
  *correct_psk = 0;

  unsigned char alice[11] = "I AM ALICE";
  uint8_t iv[16];
  memset(iv, 0, 16);

  unsigned char psk_A[16] = {0x0};

  sgx_status = sgx_aes_ctr_decrypt(enc_key, message, 16, iv, 1, psk_A);
  if (sgx_status != SGX_SUCCESS) {
      return sgx_status;
  }
  int x = strcmp((const char *)alice, (const char *)psk_A);
  if (x == 0){
    *correct_psk = 1;
  }
  return sgx_status;
}

sgx_status_t completeChallenge(unsigned char* message, unsigned char* result){
  sgx_status_t sgx_status;

  /*************************
   * BEGIN 6. Decrypt Challenge
   *************************/
  uint8_t iv[16];
  memset(iv, 0, 16);

  unsigned char plaintext[8] = {0x0};
  sgx_status = sgx_aes_ctr_decrypt(enc_key, message, 8, iv, 1, plaintext);
  if (sgx_status != SGX_SUCCESS) {
      return sgx_status;
  }

  unsigned char x1[4];
  unsigned char x2[4];
  memcpy(x1, plaintext, 4);
  memcpy(x2, plaintext + 4, 4);
    /*************************
   * END 6. Decrypt Challenge
   *************************/


  /*************************
 * BEGIN 7. Compute and Encrypt Response
 *************************/
  uint32_t *a = (uint32_t *)x1;
  uint32_t *b = (uint32_t *)x2;

  uint32_t result_int = *a + *b;
  unsigned char result_char[4] = {0};
  memcpy(result_char, &result_int, 4);
  memset(iv, 0, 16);

  sgx_status = sgx_aes_ctr_encrypt(enc_key, result_char, 4, iv, 1, result);

  /*************************
 * END 7. Compute and Encrypt Response
 *************************/
  return sgx_status;
}


