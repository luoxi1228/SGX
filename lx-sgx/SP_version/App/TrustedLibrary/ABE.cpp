#include "ABE/ABE2OD.h"
#include "App.h"
#include "Enclave_u.h"
#include <sys/resource.h>
#include <iostream>
#include <omp.h>
#include <random>

using namespace ABE2ODSPACE;
using namespace std;
ABE2OD abe2od;
pairing_t pairing;


// cipher
string M;
unsigned char *cipher_str;
size_t cipher_str_count;
size_t policy_len;
size_t cipher_C1_size = 0;
size_t ptc_C1_size = 0;
size_t tc_T1_size = 0;

// tk_1
unsigned char *tk_1_str;
size_t tk_1_str_count;
size_t key_len_tk_1, value_len_tk_1;
unsigned char *umap_key_str_tk_1;
unsigned char *umap_value_str_tk_1;
size_t each_str_counts_size_tk_1;
size_t *each_str_counts_tk_1;
// tk_2
unsigned char *tk_2_str;
size_t tk_2_str_count;
size_t key_len_tk_2, value_len_tk_2;
unsigned char *umap_key_str_tk_2;
unsigned char *umap_value_str_tk_2;
size_t each_str_counts_size_tk_2;
size_t *each_str_counts_tk_2;

// hk
unsigned char *hk_str;
size_t hk_str_count;
// dk
unsigned char *dk_str;
size_t dk_str_count;
// ptc
unsigned char *ptc_str;
size_t ptc_str_count;
// tc
unsigned char *tc_str;
size_t tc_str_count;

string generateBinaryHash(size_t bitLength) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<int> dist(0, 1);

    std::string hash;
    for (size_t i = 0; i < bitLength; i++) {
        int bit = dist(gen);
        hash += std::to_string(bit);
    }

    return hash;
}


void step_1_enc() {
    const char *param = "type a   \
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

    abe2od.SETSTATICSIZE(pairing);
    printf("APP:G1 = %ld bytes\n", G1_SIZE);
    printf("APP:G2 = %ld bytes\n", G2_SIZE);
    printf("APP:GT = %ld bytes\n", GT_SIZE);
    printf("APP:Zr = %ld bytes\n", ZR_SIZE);

    abe2od.Setup(pairing);// 初始化得到(PK,MSK)

    // encryption
    string access_policy = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,10)";//测试的访问策略为10个属性必须全部满足
    LSSS lsss(access_policy);
    const size_t desiredBitLength = 256; // 所需的位数
    M = generateBinaryHash(desiredBitLength);//随机设置明文M的hash值
    Ciphertext cipher;
    abe2od.Enc(cipher, M, lsss, pairing);
    cipher_C1_size = cipher.C1.size();
    ptc_C1_size = cipher_C1_size;
    tc_T1_size = cipher_C1_size;

    //KeyGen
    string attribute_str = "(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10)";
    KeyTuple keytuple;
    abe2od.KeyGen(keytuple, attribute_str, pairing);
    //abe2od.showkeytuple(keytuple);


    // ecall get pairing and size
    double prerequisite_start_time, prerequisite_end_time;
    prerequisite_start_time = omp_get_wtime();
    prerequisite(global_eid, &cipher_C1_size);
    prerequisite_end_time = omp_get_wtime();
    printf("Enclave init 耗时:%.10f ms\n", (prerequisite_end_time - prerequisite_start_time) * 1000);

    // serialize cipher
    abe2od.serl_Ciphertext(&cipher_str, &cipher_str_count, cipher, &policy_len);

    // serialize keytuple.tk_1
    vector<size_t> umap_each_str_counts_tk_1;
    abe2od.serl_TK(&tk_1_str, &tk_1_str_count, keytuple.tk_1, &umap_key_str_tk_1, &key_len_tk_1, &umap_value_str_tk_1,
                   &value_len_tk_1, umap_each_str_counts_tk_1);
    each_str_counts_size_tk_1 = umap_each_str_counts_tk_1.size();
    each_str_counts_tk_1 = (size_t *) malloc(each_str_counts_size_tk_1 * sizeof(size_t));
    for (size_t i = 0; i < each_str_counts_size_tk_1; i++) {
        each_str_counts_tk_1[i] = umap_each_str_counts_tk_1[i];
    }

    // serialize keytuple.tk_2
    vector<size_t> umap_each_str_counts_tk_2;
    abe2od.serl_TK(&tk_2_str, &tk_2_str_count, keytuple.tk_2, &umap_key_str_tk_2, &key_len_tk_2, &umap_value_str_tk_2,
                   &value_len_tk_2, umap_each_str_counts_tk_2);
    each_str_counts_size_tk_2 = umap_each_str_counts_tk_2.size();
    each_str_counts_tk_2 = (size_t *) malloc(each_str_counts_size_tk_2 * sizeof(size_t));
    for (size_t i = 0; i < each_str_counts_size_tk_2; i++) {
        each_str_counts_tk_2[i] = umap_each_str_counts_tk_2[i];
    }

    // serialize DK
    abe2od.serl_DK(&dk_str, &dk_str_count, keytuple.dk);

    // serialize HK
    abe2od.serl_HK(&hk_str, &hk_str_count, keytuple.hk);

}

void step_2_transform1(int i) {

    Ciphertext cipher_rec;
    element_init_GT(cipher_rec.C0, pairing);
    element_init_G1(cipher_rec.C2, pairing);
    size_t cipher_rec_vec_length =
            (cipher_str_count - policy_len - G1_SIZE - GT_SIZE - cipher_C1_size) / (G1_SIZE * 2 + ZR_SIZE);
    for (size_t i = 0; i < cipher_rec_vec_length; i++) {
        struct element_s tmp;
        element_init_G1(&tmp, pairing);
        cipher_rec.Ei.push_back(tmp);
    }
    for (size_t i = 0; i < cipher_rec_vec_length; i++) {
        struct element_s tmp;
        element_init_G1(&tmp, pairing);
        cipher_rec.Di.push_back(tmp);
    }
    for (size_t i = 0; i < cipher_rec_vec_length; i++) {
        struct element_s tmp;
        element_init_Zr(&tmp, pairing);
        cipher_rec.lambda.push_back(tmp);
    }
    unsigned char *pointer = cipher_str;
    LSSS lsss_rec;
    char *policy = reinterpret_cast<char *>(pointer);
    std::string access_policy(policy, policy_len);
    lsss_rec.initialize(access_policy);
    cipher_rec.policy = &lsss_rec;
    pointer = pointer + policy_len;
    abe2od.deserl_Ciphertext(cipher_rec, pointer, cipher_str_count, policy_len);

    //de-serialize tk_1
    KeyTuple::TK tk_1_rec;
    element_init_G1(tk_1_rec.K, pairing);
    element_init_G1(tk_1_rec.L, pairing);
    char *tk_key_pointer = (char *) (umap_key_str_tk_1);
    for (size_t i = 0; i < each_str_counts_size_tk_1; i++) {
        std::string key_tmp(tk_key_pointer, (each_str_counts_tk_1)[i]);
        tk_key_pointer = tk_key_pointer + (each_str_counts_tk_1)[i];
        struct element_s value_tmp;
        element_init_G1(&value_tmp, pairing);
        tk_1_rec.Ky.emplace(key_tmp, value_tmp);
    }
    abe2od.deserl_TK(tk_1_rec, tk_1_str, tk_1_str_count, umap_value_str_tk_1, value_len_tk_1);

    //de-serialize tk_2
    KeyTuple::TK tk_2_rec;
    element_init_G1(tk_2_rec.K, pairing);
    element_init_G1(tk_2_rec.L, pairing);
    char *tk_key_pointer_2 = (char *) (umap_key_str_tk_2);
    for (size_t i = 0; i < each_str_counts_size_tk_2; i++) {
        std::string key_tmp(tk_key_pointer_2, (each_str_counts_tk_2)[i]);
        tk_key_pointer_2 = tk_key_pointer_2 + (each_str_counts_tk_2)[i];
        struct element_s value_tmp;
        element_init_G1(&value_tmp, pairing);
        tk_2_rec.Ky.emplace(key_tmp, value_tmp);
    }
    abe2od.deserl_TK(tk_2_rec, tk_2_str, tk_2_str_count, umap_value_str_tk_2, value_len_tk_2);


    // transformation 1
    PTC ptc;


    //#pragma omp critical
    transform1_start_time = omp_get_wtime();
    abe2od.Transform1(ptc, tk_1_rec, tk_2_rec, cipher_rec, pairing);

    //#pragma omp critical
    transform1_end_time = omp_get_wtime();
    abe_time_t1 += (transform1_end_time - transform1_start_time);
    //printf("[ task %d ] transform1（App）耗时:%.4f ms\n", i,(transform1_end_time - transform1_start_time)*1000);
    //abe2od.showPTC(ptc);

    // serialize PTC
    abe2od.serl_PTC(&ptc_str, &ptc_str_count, ptc);
    element_clear(ptc.C0);
    element_clear(ptc.CP1);
    element_clear(ptc.CP2);



    /*
    cout<<"测试开始！-------------------------------------------------------------------------\n";

    KeyTuple::HK hk;
    element_init_Zr(hk.gamma_1, pairing);
    element_init_Zr(hk.gamma_2, pairing);
    abe2od.deserl_HK(hk, hk_str,hk_str_count);
    abe2od.showHK(hk);

    element_t result_1,result_2;
    element_init_GT(result_1, pairing);
    element_init_GT(result_2, pairing);
    element_pow_zn(result_1, ptc.CP1, hk.gamma_1);
    element_pow_zn(result_2, ptc.CP2, hk.gamma_2);

    if (element_cmp(result_1, result_2) == 0) {
        printf("ptc.CP1 ^ hk.gamma_1 and ptc.CP2 ^ hk.gamma_2 are equal\n");
    } else {
        printf("ptc.CP1 ^ hk.gamma_1 and ptc.CP2 ^ hk.gamma_2 are not equal\n");
        return;
    }

    cout<<"测试结束！-------------------------------------------------------------------------\n";*/

}

void step_2_transform2(int i) {

    // transformation 2
    TC tc;
    element_init_GT(tc.T0, pairing);
    element_init_GT(tc.T2, pairing);
    tc_str_count = cipher_C1_size + (size_t) element_length_in_bytes(tc.T0) + (size_t) element_length_in_bytes(tc.T2);
    tc_str = (unsigned char *) malloc(tc_str_count);


    transform2_start_time = omp_get_wtime();
    // ecall
    transform2(global_eid, &tc_str, &tc_str_count, &hk_str, &hk_str_count, &ptc_str, &ptc_str_count);

    transform2_end_time = omp_get_wtime();
    abe_time_t2 += (transform2_end_time - transform2_start_time);
    //printf("[ task %d ] transform2（Enclave）耗时:%.4f ms\n", i,(transform2_end_time - transform2_start_time)*1000);


}

void step_3_dec(int i) {

    // deserialize tc
    TC tc;
    element_init_GT(tc.T0, pairing);
    element_init_GT(tc.T2, pairing);

    // deserialize tc
    unsigned char *pointer = tc_str;
    string T1(reinterpret_cast<char *>(pointer), tc_T1_size);
    tc.T1 = T1;
    pointer = pointer + tc_T1_size;
    element_from_bytes(tc.T0, pointer);
    pointer = pointer + GT_SIZE;
    element_from_bytes(tc.T2, pointer);

    // deserialize dk
    KeyTuple::DK dk;
    element_init_Zr(dk.beta, pairing);
    element_from_bytes(dk.beta, dk_str);


    // decryption
    double dec_start_time, dec_end_time;
    dec_start_time = omp_get_wtime();
    string M1 = abe2od.Dec(dk, tc, pairing);
    dec_end_time = omp_get_wtime();
    abe_time_dec += (dec_end_time - dec_start_time);
    //printf("[ task %d ] Dec (App) 耗时:%.4f ms\n", i, (dec_end_time  - dec_start_time)*1000);
    //cout<<"-------------------------------------------------------------------------\n";

    if (M1 != M) {
        // cout<<"Before encryption: M = "<<M<<'\n';
        // cout<<"After encryption: M1 = "<<M1<<'\n';
        cout << "错误：M与M1不一致\n";
        exit(-1);
    }

    //free(tc_str);
    element_clear(tc.T0);
    element_clear(tc.T2);
    element_clear(dk.beta);
}


