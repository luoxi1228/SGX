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
#include <sgx_tcrypto.h>  // 包含 SGX SHA-256 哈希函数所需的头文件

element_t g;  // 声明全局变量 g

void initialize(pairing_t pairing) {
    element_init_G1(g, pairing);  // 初始化 g
    element_random(g);            // 随机化 g
}
void cleanup() {
    element_clear(g);
}

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

void printf_element(element_t G ,int addition){
    unsigned char buffer[512];
    int len=element_to_bytes(buffer,G);
    ocall_element_printf(buffer, len, addition);

}
// 打印字节数组（用于调试）
void print_byte_array(unsigned char* array, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x ", array[i]);
    }
    printf("\n");
}

//字符串转字节
void string_to_bytes(const char* str, unsigned char* buffer, int& len) {
    len = strlen(str);  // 获取字符串长度，不包括末尾的'\0'
    for (int i = 0; i < len; i++) {
        buffer[i] = (unsigned char) str[i];  // 将字符逐个转换为字节
    }
}

//字节级异或
void xor_byte(unsigned char* buffer1, int len1, unsigned char* buffer2, int len2, unsigned char* result, int& len_result) {

    // 确保两个输入长度相同
    if(len1 != len2) {
        printf("Warning: Input lengths differ: %d != %d\n", len1, len2);
    }
    
    int max_len = (len1 > len2) ? len1 : len2;
     // 分配内存空间给异或结果
    result = (unsigned char*) malloc(max_len * sizeof(unsigned char));
    
    // 直接进行异或操作
    for (int i = 0; i < max_len; i++) {
        unsigned char byte1 = (i < len1) ? buffer1[i] : 0;
        unsigned char byte2 = (i < len2) ? buffer2[i] : 0;
        result[i] = byte1 ^ byte2;
    }
    len_result=max_len;
    
}


void string_to_element(const char *str, element_t& e, pairing_t pairing) {
    // 获取字符串的长度
    size_t len = strlen(str);
    
    // 创建一个足够容纳字符串的字节数组
    unsigned char *byte_array = (unsigned char *)malloc(len);
    
    // 将字符串每个字符的 ASCII 值复制到字节数组中
    for (size_t i = 0; i < len; i++) {
        byte_array[i] = (unsigned char)str[i];
    }

    // 使用字节数组填充 element_t 元素
    int len2 = element_from_bytes(e, byte_array);
    
    // 检查转换是否成功
    if(len2 >0) {
        printf("成功将字符串转换为element_t \n");
    } else {
        printf("转换失败！返回的字节数: %d\n", len2);
    }

    // 释放临时字节数组
    free(byte_array);
}

void H1(unsigned char* m, int len,element_t R, element_t& output, pairing_t pairing) {
    uint8_t hash[32];  // 使用固定大小的数组来存储哈希值

    int len_R,total_len;
    unsigned char buffer_R[512];
    len_R=element_to_bytes(buffer_R,R);
    total_len=len_R+len;
    unsigned char* combined_input = new unsigned char[total_len];
    // 将2个输入字节流拼接到一起
    memcpy(combined_input, m, len);
    memcpy(combined_input + len, buffer_R, len_R);

    // 使用 SGX 提供的 SHA-256 哈希函数
    sgx_status_t status = sgx_sha256_msg(combined_input, total_len, &hash);  // 传递指向 hash 数组的指针
    if (status != SGX_SUCCESS) {
        printf("SGX SHA-256 hashing failed: %d\n", status);
        return;
    }

    // 将哈希值映射到群 Zr 中的元素
    element_t temp;
    element_init_Zr(temp, pairing);
    element_from_hash(temp, hash, 32);  // 使用 32 字节的哈希结果

    // 设置输出为群 Zr 中的元素
    element_set(output, temp);

    element_clear(temp);
    delete[] combined_input;

}

void H2(element_t pk, element_t w, element_t& output, pairing_t pairing) {
    uint8_t hash[32];  // 使用固定大小的数组来存储哈希值

    int len_pk,len_w,total_len;
    unsigned char buffer_pk[512],buffer_w[512];
    len_pk=element_to_bytes(buffer_pk,pk);
    len_w=element_to_bytes(buffer_w,w);
    total_len=len_pk+len_w;

    unsigned char buffer_combined[total_len];
    memcpy(buffer_combined, buffer_pk, len_pk);   // 拷贝第一个字节数组
    memcpy(buffer_combined + len_pk, buffer_w, len_w); // 拷贝第二个字节数组 

    // 使用 SGX 提供的 SHA-256 哈希函数
    sgx_status_t status = sgx_sha256_msg(buffer_combined, total_len, &hash);  // 传递指向 hash 数组的指针
    if (status != SGX_SUCCESS) {
        printf("SGX SHA-256 hashing failed: %d\n", status);
        return;
    }

    // 将哈希值映射到群 G 中的元素
    element_t temp;
    element_init_G1(temp, pairing);
    element_from_hash(temp, hash, 32);  // 使用 32 字节的哈希结果

    // 设置输出为群 G 中的元素
    element_set(output, temp);

    element_clear(temp);
}

void H3(element_t R, unsigned char* output, int& output_len, pairing_t pairing) {
    uint8_t hash[32];  // 使用 SHA-256 输出固定大小（32字节）

    int len_R;
    // 使用 PBC 库中的 element_to_bytes 函数将群元素转化为字节流
    unsigned char buffer_R[512];  // 假设 buffer 足够大以存放群元素字节表示
    len_R = element_to_bytes(buffer_R, R);

    // 使用 SGX 提供的 SHA-256 哈希函数
    sgx_status_t status = sgx_sha256_msg(buffer_R, len_R, &hash);  // 传递指向 hash 数组的指针
    if (status != SGX_SUCCESS) {
        printf("SGX SHA-256 hashing failed: %d\n", status);
        return;
    }

    // 将哈希值映射到群 G1 中的元素
    element_t temp;
    element_init_G1(temp, pairing);
    element_from_hash(temp, hash, 32);  // 使用 32 字节的哈希结果

    // 将群元素 temp 转化为字节流输出
    output_len = element_to_bytes(output, temp);

    // 释放临时变量
    element_clear(temp);
}


void H4(element_t C1,element_t C2,unsigned char* buffer_c3,int len_c3, element_t& output, pairing_t pairing) {

    uint8_t hash[32];  // SHA-256 输出为 32 字节

    unsigned char buffer_c1[512],buffer_c2[512];
    int len_c1,len_c2;
    len_c1= element_to_bytes(buffer_c1, C1);
    len_c2= element_to_bytes(buffer_c2, C2);

    // 计算总的输入字节流长度
    int total_len = len_c1 + len_c2 + len_c3;

    // 创建一个足够大的缓冲区来存储拼接后的字节流
    unsigned char* combined_input = new unsigned char[total_len];

    // 将三个输入字节流拼接到一起
    memcpy(combined_input, buffer_c1, len_c1);
    memcpy(combined_input + len_c1, buffer_c2, len_c2);
    memcpy(combined_input + len_c1 + len_c2, buffer_c3, len_c3);

    // 使用 SGX 提供的 SHA-256 哈希函数
    sgx_status_t status = sgx_sha256_msg(combined_input, total_len, &hash);  // 传递指向 hash 数组的指针
    if (status != SGX_SUCCESS) {
        printf("SGX SHA-256 hashing failed: %d\n", status);
        return;
    }

    // 将哈希值映射到群 G 中的元素
    element_t temp;
    element_init_G1(temp, pairing);
    element_from_hash(temp, hash, 32);  // 使用 32 字节的哈希结果
    // 设置输出为群 G 中的元素
    element_set(output, temp);

    element_clear(temp);
    // 释放临时分配的内存
    delete[] combined_input;
    
}

void H5(element_t g, element_t& output, pairing_t pairing) {
    unsigned char buffer[512];
    int len = element_to_bytes(buffer, g);

    uint8_t hash[32];
    sgx_sha256_msg(buffer, len, &hash);

    element_t temp;
    element_init_Zr(temp, pairing);
    element_from_hash(temp, hash, 32);
    element_set(output, temp);

    element_clear(temp);
}

void KeyGen(pairing_t pairing, element_t& pk, element_t& sk,element_t g) {
    element_t x;

    element_init_Zr(x, pairing);  // 初始化标量 x
    element_random(x);            // 生成随机标量 x

    element_pow_zn(pk, g, x);     // pk = g^x
    element_set(sk, x);           // sk = x

    element_clear(x);
}

void ReKeyGen(element_t& rk1, element_t& rk2, element_t ski, element_t pki, element_t pkj,  element_t w, pairing_t pairing) {
    element_t s, tmp1, tmp2, tmp3;

    // 选择随机数 s ∈ Zq
    element_init_Zr(s, pairing);
    element_random(s);

    // 计算 H2(pki, w)
    element_t h2;
    element_init_G1(h2, pairing);

    H2(pki,w,h2,pairing);

    // 计算 rk1 = (H2(pki, w) * pkj^s)^(-ski)
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);
    element_init_Zr(tmp3, pairing);

    // 计算 pkj^s
    element_pow_zn(tmp1, pkj, s);

    // 计算 H2(pki, w) * pkj^s
    element_mul(tmp2, h2, tmp1);

    // 计算 (H2(pki, w) * pkj^s)^(−ski)
    element_neg(tmp3, ski);  // 取 -ski
    element_pow_zn(rk1, tmp2, tmp3);

    // 计算 rk2 = pki^s
    element_pow_zn(rk2, pki, s);

    // 清理临时元素
    element_clear(s);
    element_clear(h2);
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(tmp3);
}

void Enc2(element_t pk, unsigned char* m,int len_m, element_t w, element_t& C1,element_t& C2,unsigned char* C3,int& len_c3,element_t& C4, pairing_t pairing,element_t g){
    element_t R,r,e;
    element_init_GT(R,pairing);
    element_init_Zr(r,pairing);
    element_init_GT(e, pairing);
    element_random(R);

    //计算r
    H1(m,len_m,R,r,pairing);
    //printf("r\n");
    
    //C1 is G1
    element_pow_zn(C1,g,r); //C1=g^r
    //printf("c1\n");

    //C2 is GT
    element_t h2;
    element_init_G1(h2,pairing);
   
    H2(pk,w,h2,pairing); // H2(pk,w)
    pairing_apply(e, pk, h2, pairing); //e(pk,H2(pk,w))

    element_t temp2;
    element_init_GT(temp2, pairing);
    element_pow_zn(temp2,e,r);//e(pk,H2(pk,w))^r
    element_mul(C2, R, temp2);// R * e(pk,H2(pk,w))^r
    //printf("c2 \n");

    //C3 is G1
    unsigned char buffer_h3[512]; 
    int len_h3;               // 预留足够的空间
    H3(R,buffer_h3,len_h3,pairing);       

    xor_element(m,len_m, buffer_h3,len_h3, C3, len_c3);  //m xor H3(R)
    printf("m\n");
    print_byte_array(m,len_m);
    printf("h3\n");
    print_byte_array(buffer_h3,len_h3);
    printf("C3\n");
    print_byte_array(C3,len_c3);

    //C4 is G1
    element_t temp4;
    element_init_G1(temp4,pairing);
    H4(C1,C2,C3,len_c3,temp4,pairing);
    element_pow_zn(C4,temp4,r); //H4(C1, C2, C3)^r
    //printf("c4\n");


    element_clear(R);
    element_clear(r);
    element_clear(e);
    element_clear(h2);
    element_clear(temp2);
    element_clear(temp4);

}

// void Dec2(element_t pk, element_t sk, element_t w, element_t C1, element_t C2, element_t C3, element_t C4, pairing_t pairing, element_t g, element_t& output){
//     element_t e1, e2,e3, h4, h2, temp_e, R , r, temp_g;
//     element_init_GT(e1,pairing);
//     element_init_GT(e2,pairing);
//     element_init_GT(e3,pairing);
//     element_init_G1(h4,pairing);
//     element_init_G1(h2,pairing);
//     element_init_GT(temp_e,pairing);
//     element_init_GT(R,pairing);
//     element_init_Zr(r,pairing);
//     element_init_G1(temp_g,pairing);

//     pairing_apply(e2,g,C4,pairing); //e(g,C4)
//     H4(C1,C2,C3,h4,pairing); //H4(C1,C2,C3)
//     pairing_apply(e1,C1,h4,pairing); //e(C1,H4(C1,C2,C3))

//     if (element_cmp(e1,e2)!=0){
//         printf("解密失败1！");
//     }else{
//         H2(pk,w,h2,pairing);//H2(pk,w)
//         pairing_apply(e3,C1,h2,pairing); 
//         element_pow_zn(temp_e,e3,sk);  // temp2 = e(C1,H2(pk,w))^sk

//         element_div(R,C2,temp_e);    //  R= C2 / e(C1,H2(pk,w))^sk
//         unsigned char buffer_h3[512];
//         H3(R,buffer_h3,pairing);  //H3(R)

//         unsigned char buffer_m[512];

//         xor_element(C3,buffer_h3,buffer_m,len_m);  // buffer_m= C3 xor H3(R)
//         printf("m\n");
//         int len = sizeof(buffer_m);
//         print_byte_array(buffer_m,len)
//         printf("h3\n");
//         printf_element(h3,1);
//         printf("C3\n");
//         printf_element(C3,1);

//         H1(buffer_m,len_m,R,r,pairing);  //r=H1(m,R)
         
//         element_pow_zn(temp_g,g,r); // g^(H1(m,R))


//         if(element_cmp(temp_g,C1)==0){
//             element_set(output,temp_m);
//         }else{
//             printf("解密失败2！");
//         }
//     }

//     element_clear(e1);
//     element_clear(e2);
//     element_clear(e3);
//     element_clear(h4);
//     element_clear(h2);
//     element_clear(temp_e);
//     element_clear(R);
//     element_clear(h3);
//     element_clear(r);
//     element_clear(temp_g);
//     element_clear(temp_m);


// }

void ecall_PRE()
{
    pairing_t pairing;
    element_t pk_i, sk_i;
    element_t pk_j, sk_j;
    element_t rk1,rk2,w;
    element_t C1,C2,C4;

     
    
    // 初始化配对参数
    char param_str[] = "type a\n"
                       "q 87807107996633125224377819847540498158068831994142082"
                       "1102865339926647563088022295707862517942266222142315585"
                       "8769582317459277713367317481324925129998224791\n"
                       "h 12016012264891146079388821366740534204802954401251311"
                       "822919615131047207289359704531102844802183906537786776\n"
                       "r 730750818665451621361119245571504901405976559617\n"
                       "exp2 159\n"
                       "exp1 107\n"
                       "sign1 1\n"
                       "sign0 1\n";

    pbc_param_t par;
    pbc_param_init_set_str(par, param_str);
    pairing_init_pbc_param(pairing, par);

    initialize(pairing);  
    element_init_G1(pk_i,pairing);
    element_init_Zr(sk_i,pairing);
    element_init_G1(pk_j,pairing);
    element_init_Zr(sk_j,pairing);

    element_init_G1(rk1,pairing);
    element_init_G1(rk2,pairing);
    element_init_G1(w,pairing);
    element_random(w);

    element_init_G1(C1,pairing);
    element_init_GT(C2,pairing);
    element_init_G1(C4,pairing);
    unsigned char C3[512];
    int len_c3;


    KeyGen(pairing, pk_i, sk_i,g);
    //KeyGen(pairing, pk_j, sk_j,g);
    //ReKeyGen(rk1,rk2,sk_i,pk_i,pk_j,w,pairing);
  
    // 打印公钥和私钥
    printf("\n公钥pki:  ");
    printf_element(pk_i,1);
    printf("私钥ski:  ");
    printf_element(sk_i,0);

    // int len3,len4;
    // unsigned char buffer_rk1[512], buffer_rk2[512];
    // len3=element_to_bytes(buffer_rk1, rk1);
    // len4=element_to_bytes(buffer_rk2, rk2);
    // ocall_element_printf(buffer_rk1, len3, 1);
    // ocall_element_printf(buffer_rk2, len4, 1);

    unsigned char buffer_m[512];
    char m[]="0123456789";
    int len_m;
    string_to_bytes(m,buffer_m,len_m);

    printf("明文M: ");
    print_byte_array(buffer_m,len_m);
   
    Enc2(pk_i,buffer_m ,len_m, w, C1,C2,C3,len_c3,C4, pairing,g);
    printf("\n二级密文CT:  ");
    printf("\nC1:  ");
    printf_element(C1,1);
    printf("\nC2:  ");
    printf_element(C2,3);
    printf("\nC3:  ");
    print_byte_array(C3,len_c3);
    printf("\nC4:  ");
    printf_element(C4,1);

    // printf("\n解密: \n");
    // element_t dec_m;
    // element_init_G1(dec_m,pairing);
    // Dec2(pk_i,sk_i,w,C1,C2,C3,C4,pairing,g,dec_m);
    // printf("\nm:  ");
    // printf_element(dec_m,1);


    // 清理元素
    cleanup();
    element_clear(pk_i);
    element_clear(sk_i);
    element_clear(pk_j);
    element_clear(sk_j);
    element_clear(rk1);
    element_clear(rk2);
    element_clear(w);
    element_clear(C1);
    element_clear(C2);
    element_clear(C4);
    //element_clear(dec_m);
    pairing_clear(pairing);

}