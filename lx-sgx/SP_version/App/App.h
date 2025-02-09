#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <stdarg.h>
#include <semaphore.h>
#include "pbc/pbc.h"

#include "sgx_error.h"	/* sgx_status_t */
#include "sgx_eid.h"	/* sgx_enclave_id_t */
using namespace std;

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"

extern sgx_enclave_id_t global_eid;	/* global enclave id */


#if defined(__cplusplus)
extern "C" {
#endif
//放函数声明
extern size_t ZR_SIZE;
extern size_t G1_SIZE;
extern size_t G2_SIZE;
extern size_t GT_SIZE;
extern size_t cipher_C1_size;
extern size_t ptc_C1_size;
extern size_t tc_T1_size;
extern pthread_mutex_t mutex;//互斥锁
extern sem_t semaphore;//信号量
extern double abe_time_setup;
extern double abe_time_keygen;
extern double abe_time_enc;
extern double abe_time_t1;
extern double abe_time_t2;
extern double abe_time_dec;
extern double transform1_start_time, transform1_end_time;
extern double transform2_start_time, transform2_end_time;

// Cipher
extern string M;
extern unsigned char* cipher_str;
extern size_t cipher_str_count;
extern size_t policy_len;


// tk_1
extern unsigned char* tk_1_str;
extern size_t tk_1_str_count;
extern size_t key_len_tk_1, value_len_tk_1;
extern unsigned char* umap_key_str_tk_1;
extern unsigned char* umap_value_str_tk_1;
extern size_t each_str_counts_size_tk_1;
extern size_t* each_str_counts_tk_1;
// tk_2
extern unsigned char* tk_2_str;
extern size_t tk_2_str_count;
extern size_t key_len_tk_2, value_len_tk_2;
extern unsigned char* umap_key_str_tk_2;
extern unsigned char* umap_value_str_tk_2;
extern size_t each_str_counts_size_tk_2;
extern size_t* each_str_counts_tk_2;

// hk
extern unsigned char* hk_str;
extern size_t hk_str_count;
// dk
extern unsigned char* dk_str;
extern size_t dk_str_count;
// ptc
extern unsigned char* ptc_str;
extern size_t ptc_str_count;
// tc
extern unsigned char* tc_str;
extern size_t tc_str_count;

void step_1_enc();
void step_2_transform1(int i);
void step_2_transform2(int i);
void step_3_dec(int i);
#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
