#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRE_DEFINED__
#define OCALL_PRE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_PRE, (void));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_ELEMENT_PRINTF_DEFINED__
#define OCALL_ELEMENT_PRINTF_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_element_printf, (uint8_t* buffer_g, size_t len_g, int additional_value));
#endif

sgx_status_t ecall_PRE(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
