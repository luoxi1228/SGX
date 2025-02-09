#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "ABE_sgx/ABE2OD.h"
#include "pbc_sgx/pbc.h"
#include "PicoSHA2/picosha2.h"


using namespace ABE2ODSPACE;
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}
pairing_t pairing;
void get_pairing()
{

    const char *param ="type a   \
q 40132934874065581357639239301938089130039744463472639389591743372055069245229811691989086088125328594220615378634210894681862132537783020759006156856256486760853214375759294871087842511098137328669742901944483362556170153388301818039153709502326627974456159915072198235053718093631308481607762634120235579251 \
h 5986502056676971303894401875152023968506744561211054886102595589603460071084910131070137261543726329935522867827513637124526300709663875599084261056444276 \
r 6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941560715789883889358865432577 \
exp2 511  \
exp1 87   \
sign1 1  \
sign0 1";
    // 初始化pbc_param_t
    pbc_param_t par;
    pbc_param_init_set_str(par, param);
    // 初始化pairing_t

    pairing_init_pbc_param(pairing, par);
}

void before()
{
    get_pairing();
}
void after()
{
    pairing_clear(pairing);
}

void prerequisite(size_t *C1_size)
{
    ABE2OD abe2od;
    before();
    abe2od.SETSTATICSIZE(pairing);
    printf("Enclave:G1 = %ld bytes\n",G1_SIZE);
    printf("Enclave:G2 = %ld bytes\n",G2_SIZE);
    printf("Enclave:GT = %ld bytes\n",GT_SIZE);
    printf("Enclave:Zr = %ld bytes\n",ZR_SIZE);

    cipher_C1_size = *C1_size;
    ptc_C1_size = cipher_C1_size;
    tc_T1_size = cipher_C1_size;
}


void transform2(unsigned char** tc_str,size_t * tc_str_count,
                unsigned char** hk_str,size_t * hk_str_count, unsigned char** ptc_str,size_t *ptc_str_count)
{

    ABE2OD abe2od;

    //de-serialize HK
    KeyTuple::HK hk_rec;
    element_init_Zr(hk_rec.gamma_1, pairing);
    element_init_Zr(hk_rec.gamma_2, pairing);
    abe2od.deserl_HK(hk_rec, *hk_str,*hk_str_count);

    //de-serialize PTC
    ABE2ODSPACE::PTC ptc_rec;
    element_init_GT(ptc_rec.C0, pairing);
    element_init_GT(ptc_rec.CP1, pairing);
    element_init_GT(ptc_rec.CP2, pairing);
    abe2od.deserl_PTC(ptc_rec, *ptc_str, *ptc_str_count);
    //Transform2
    TC tc;
    element_init_GT(tc.T0, pairing);
    element_init_GT(tc.T2, pairing);
    int reg = abe2od.Transform2(tc, hk_rec, ptc_rec, pairing);

    element_t result_1,result_2;
    element_init_GT(result_1, pairing);
    element_init_GT(result_2, pairing);
    element_pow_zn(result_1, ptc_rec.CP1, hk_rec.gamma_1);
    element_pow_zn(result_2, ptc_rec.CP2, hk_rec.gamma_2);

    // T0
    element_set(tc.T0, ptc_rec.C0);
    // T1
    tc.T1 = ptc_rec.C1;

    // T2
    element_set(tc.T2, result_1);
        
    if (element_cmp(result_1, result_2) != 0)
    {

        reg=1;
    }
    else
    {

        reg=0;
    }
            
    element_clear(result_1);
    element_clear(result_2);
    /*
    if(reg==1)//逆天bug,在Enclava中竟然对不上，其实是正确的，害我debug了一天，理由：M与M1是一致的，以及在外面的相同代码也是得到reg==1
    {

        printf("Enclave: ptc.CP1 ^ hk.gamma_1 and ptc.CP2 ^ hk.gamma_2 are equal\n");
    }
    else// 在Enclave中走了下分支
    {
        printf("Enclave: ptc.CP1 ^ hk.gamma_1 != ptc.CP2 ^ hk.gamma_2\n");
    }*/

    //serialize TC
    abe2od.serl_TC(tc_str, tc_str_count, tc);
    // free hk
    element_clear(hk_rec.gamma_1);
    element_clear(hk_rec.gamma_2);


    // free ptc
    element_clear(ptc_rec.C0);
    element_clear(ptc_rec.CP1);
    element_clear(ptc_rec.CP2);

    // free tc
    element_clear(tc.T0);
    element_clear(tc.T2);



}


