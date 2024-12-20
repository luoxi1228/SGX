#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <string.h>

void ecall_hello_from_enclave(char *buf, size_t len)
{
    const char *hello = "Hello Enclave-lx";

    size_t size = len;
    if(strlen(hello) < len)
    {
        size = strlen(hello) + 1;
    }

    memcpy(buf, hello, size - 1); //将字符串 hello 复制到 buf 缓冲区中
    buf[size-1] = '\0'; //手动将字符串的结尾字符 \0 放入缓冲区
}

