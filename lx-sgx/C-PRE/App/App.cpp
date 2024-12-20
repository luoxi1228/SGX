#include <stdio.h>
#include <cstdio>
#include <string.h>
#include <assert.h>
#include <iostream>
#include <iomanip>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include <pbc/pbc.h>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_MEMORY_MAP_FAILURE,
        "Failed to reserve memory for the enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret){
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

//初始化Enclave
int initialize_enclave(void){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}


/* OCall functions */
//打印函数
void ocall_print_string(const char *str){
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}
void ocall_element_printf(uint8_t *buffer_g,size_t len_g,int addition){
    // 初始化 PBC pairing 结构
    (void) len_g;
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
    // 初始化元素类型
    element_t g;
    if(addition==0){
        element_init_Zr(g,pairing);
    }else if(addition==1){
        element_init_G1(g, pairing);
    }else if(addition==2){
        element_init_G2(g, pairing);
    }else if(addition==3){
        element_init_GT(g,pairing);
    }else{
        printf("Addition Error!");
        return;
    }
    //打印
    if(element_from_bytes(g, buffer_g)>0){
       element_printf("%B\n", g);
    }else{
        printf("Error!");
    }
}
void printf_serialized(uint8_t *buffer_g1, size_t len_g1,
           uint8_t *buffer_g2, size_t len_g2,
           uint8_t *buffer_gt, size_t len_gt){
    printf("\n");
    printf("APP序列化后: \n");
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

//序列化
void ocall_PRE()
{
}



/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);


    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    /* Utilize the Ocall */
    ecall_PRE(global_eid);
    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    printf("\n");
    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}

