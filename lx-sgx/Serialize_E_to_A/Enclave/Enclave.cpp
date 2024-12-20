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

int printf(const char *fmt, ...){
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void printf_serialized(uint8_t *buffer_g1, size_t len_g1,
           uint8_t *buffer_g2, size_t len_g2,
           uint8_t *buffer_gt, size_t len_gt){

    printf("\n");
    printf("Enclave序列化后：\n");
    printf("G1: ");
    for (size_t i = 0; i < len_g1; ++i) {
        printf("%02x", buffer_g1[i]);
    }
    printf("\n");

    printf("G2: ");
    for (size_t i = 0; i < len_g2; ++i) {
        printf("%02x", buffer_g2[i]);
    }
    printf("\n");

    printf("GT: ");
    for (size_t i = 0; i < len_gt; ++i) {
        printf("%02x", buffer_gt[i]);
    }
    printf("\n");
    printf("\n");
}

void ecall_serialized()
{
    pairing_t pairing;
    element_t g1,g2,gt;
    unsigned char buffer_g1[512], buffer_g2[512], buffer_gt[512];
    int len_g1, len_g2, len_gt;
    // Initialize pairing
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
    // 初始化群元素
    element_init_G1(g1, pairing);
    element_init_G2(g2, pairing);
    element_init_GT(gt, pairing);

    // 生成随机元素
    element_random(g1);
    element_random(g2);
    element_pairing(gt, g1, g2);

    // 序列化元素
    len_g1 = element_to_bytes(buffer_g1, g1);
    len_g2 = element_to_bytes(buffer_g2, g2);
    len_gt = element_to_bytes(buffer_gt, gt);

    //原始元素
    printf("原始数据:\n");
    printf("G1: ");
    ocall_element_printf(buffer_g1,len_g1,1);
    printf("G2: ");
    ocall_element_printf(buffer_g2,len_g2,2);
    printf("GT: ");
    ocall_element_printf(buffer_gt,len_gt,0);


    //打印序列化后的数据
    printf_serialized(buffer_g1,len_g1,buffer_g2,len_g2,buffer_gt,len_gt);

    //调用Ocall传递序列化的数据到APP
    ocall_serialized(buffer_g1, len_g1, buffer_g2, len_g2, buffer_gt, len_gt);
    // Clear elements
    element_clear(g1);
    element_clear(g2);
    element_clear(gt);
    pairing_clear(pairing);
}