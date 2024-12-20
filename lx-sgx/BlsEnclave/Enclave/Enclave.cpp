#include <stdio.h> /* vsnprintf */
#include <stdarg.h>
#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <vector>
#include <cstdio>
#include "pbc/pbc.h"
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
void step_1()
{
    pairing_t pairing;
    element_t sk, pk, signature, h, g;
    char message[] = "Hello, world!";
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
    // Initialize elements
    element_init_Zr(sk, pairing);
    element_init_G1(signature, pairing);
    element_init_G1(h, pairing);
    element_init_G1(g, pairing);
    element_init_G1(pk, pairing);
    // Generate data
    element_random(sk); // x
    element_random(g);
    // Generate signature
    element_from_hash(h, message, strlen(message));
    element_pow_zn(signature, h, sk); // h^x
    element_pow_zn(pk, g, sk);        // g^x
    // Verify signature
    element_t e1, e2;
    element_init_GT(e1, pairing);
    element_init_GT(e2, pairing);
    pairing_apply(e1, signature, g, pairing); //e(signature, g)
    pairing_apply(e2, h, pk, pairing); // e(h,g^x)
    if (element_cmp(e1, e2) == 0)
    {
        printf("Signature verified successfully.\n");
    }
    else
    {
        printf("Failed to verify signature.\n");
    }
    // Clear elements
    element_clear(e1);
    element_clear(e2);
    element_clear(sk);
    element_clear(pk);
    element_clear(signature);
    element_clear(h);
    element_clear(g);
    pairing_clear(pairing);
}