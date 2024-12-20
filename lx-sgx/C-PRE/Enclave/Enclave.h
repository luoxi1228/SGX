#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <assert.h>
#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

//void ecall();
int printf(const char* fmt, ...);
//extern element_t g;  // 声明全局变量 g


#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
