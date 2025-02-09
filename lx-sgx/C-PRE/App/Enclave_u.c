#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_element_printf_t {
	uint8_t* ms_buffer_g;
	size_t ms_len_g;
	int ms_additional_value;
} ms_ocall_element_printf_t;

static sgx_status_t SGX_CDECL Enclave_ocall_PRE(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_PRE();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_element_printf(void* pms)
{
	ms_ocall_element_printf_t* ms = SGX_CAST(ms_ocall_element_printf_t*, pms);
	ocall_element_printf(ms->ms_buffer_g, ms->ms_len_g, ms->ms_additional_value);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[3];
} ocall_table_Enclave = {
	3,
	{
		(void*)Enclave_ocall_PRE,
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_element_printf,
	}
};
sgx_status_t ecall_PRE(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

