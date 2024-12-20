#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <assert.h>
#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

//void ecall();
int printf(const char* fmt, ...);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
