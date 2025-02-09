#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_PRE(void);

sgx_status_t SGX_CDECL ocall_PRE(void);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_element_printf(uint8_t* buffer_g, size_t len_g, int additional_value);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
