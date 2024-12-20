#include <stdio.h> /* vsnprintf */
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <vector>
#include <cstdio>
#include "pbc-sgx/pbc.h"
#include <string.h>

int printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void ecall_serialized(uint8_t *buffer_g1, size_t len_g1,
           uint8_t *buffer_g2, size_t len_g2,
           uint8_t *buffer_gt, size_t len_gt)
{
    (void)len_g1; //未使用，防止警告
    (void)len_g2;
    (void)len_gt;
    int len1,len2,len3;
     printf("Enclave反序列化后: \n");

    // 初始化 PBC pairing 结构
    pairing_t pairing;
    char param_str[] =  "type a\n" \
                        "q 87807107996633125224377819847540498158068831994142082" \
                        "1102865339926647563088022295707862517942266222142315585" \
                        "8769582317459277713367317481324925129998224791\n" \
                        "h 12016012264891146079388821366740534204802954401251311" \
                        "822919615131047207289359704531102844802183906537786776\n" \
                        "r 730750818665451621361119245571504901405976559617\n" \
                        "exp2 159\n" \
                        "exp1 107\n" \
                        "sign1 1\n" \
                        "sign0 1\n";

    pbc_param_t par;
    pbc_param_init_set_str(par, param_str);
    pairing_init_pbc_param(pairing, par);

    // 用于存储反序列化后的元素
    element_t g1, g2, gt;

    // 初始化元素类型
    element_init_G1(g1, pairing);
    element_init_G2(g2, pairing);
    element_init_GT(gt, pairing);

    //反序列化
    len1=element_from_bytes(g1, buffer_g1);
    len2=element_from_bytes(g2, buffer_g2);
    len3=element_from_bytes(gt, buffer_gt);

    // 反序列化 G1
    if (len1 > 0) {
        printf("G1: ");
        ocall_element_printf(buffer_g1,len_g1,1);
    } else {
        printf("反序列化 G1 失败\n");
    }

    // 反序列化 G2
    if (len2 > 0) {
        printf("G2: ");
        ocall_element_printf(buffer_g2,len_g2,2);
    } else {
        printf("反序列化 G2 失败\n");
    }

    // 反序列化 GT
    if (len3 > 0) {
        printf("GT: ");
        ocall_element_printf(buffer_gt,len_gt,0);
    } else {
        printf("反序列化 GT 失败\n");
    }

    // 清理元素
    element_clear(g1);
    element_clear(g2);
    element_clear(gt);

    // 清理 pairing
    pairing_clear(pairing);
}