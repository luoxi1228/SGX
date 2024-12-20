#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <assert.h>
#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

int printf(const char* fmt, ...);
void ecall_Add(int *res,int a,int b);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */