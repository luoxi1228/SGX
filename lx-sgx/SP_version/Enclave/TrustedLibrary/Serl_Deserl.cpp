

#include "ABE_sgx/ABE2OD.h"

#include "../Enclave.h"
#include "../Enclave_t.h"

#include <vector>
#include <map>
#include <string.h>
#include <stdio.h>
#include <assert.h>
using namespace ABE2ODSPACE;

size_t ZR_SIZE = 0;
size_t G1_SIZE = 0;
size_t G2_SIZE = 0;
size_t GT_SIZE = 0;
size_t cipher_C1_size = 0;
size_t ptc_C1_size = 0;
size_t tc_T1_size = 0;

// compute
void ABE2ODSPACE::ABE2OD::SETSTATICSIZE(pairing_t pairing)
{
    element_t zr, g1, g2, gt;
    element_init_Zr(zr, pairing);
    element_init_G1(g1, pairing);
    element_init_G2(g2, pairing);
    element_init_GT(gt, pairing);
    element_random(zr);
    element_random(g1);
    element_random(g2);
    element_random(gt);
    ZR_SIZE = element_length_in_bytes(zr);
    G1_SIZE = element_length_in_bytes(g1);
    G2_SIZE = element_length_in_bytes(g2);
    GT_SIZE = element_length_in_bytes(gt);
}

// element_t -> string
void ABE2ODSPACE::ABE2OD::serl(unsigned char** str, size_t* count, element_t e)
{
    //printf("element_t serialization --- \n");
    *count = (size_t) element_length_in_bytes(e);
    *str = (unsigned char*) malloc(*count);
    element_to_bytes(*str, e);
}

// string -> element_t
void ABE2ODSPACE::ABE2OD::deserl(element_t e, unsigned char* str, size_t count)
{
    printf("element_t de-serialization --- \n");
    element_from_bytes(e, str);
   
}

// element_t[array_length] -> string
void ABE2ODSPACE::ABE2OD::serl_array(unsigned char** arr_str, size_t* str_count, element_t *array, size_t array_length)
{
    //printf("array serialization --- \n");
    *str_count = (size_t) element_length_in_bytes(array[0])*array_length;
    *arr_str = (unsigned char*) malloc(*str_count);
    unsigned char *pointer = *arr_str;
    for (size_t i = 0; i < array_length; i++)
    {
        // printf("length = %d,\t%d\n",  element_length_in_bytes(array[i]), *str_count);
        element_to_bytes(pointer, array[i]);
        pointer = pointer + element_length_in_bytes(array[i]);
    }

}

// string -> element_t[array_length]
void ABE2ODSPACE::ABE2OD::deserl_array(element_t* array_rec, size_t array_length, unsigned char* arr_str, size_t str_count)
{
    //printf("array de-serialization --- \n");
    size_t each_length = (int) str_count / array_length;
    unsigned char *pointer = arr_str;
    for (size_t i = 0; i < array_length; i++)
    {
        // printf("length = %d,\t%d\n",  element_length_in_bytes(array[i]), *str_count);
        element_from_bytes(array_rec[i], pointer);
        pointer = pointer + each_length;
    }
    
}

// struct PK -> string
void ABE2ODSPACE::ABE2OD::serl_PK(unsigned char** str, size_t* str_count, struct ABE2ODSPACE::PK pk)
{
    //printf("PK serialization --- \n");
    *str_count = (size_t) element_length_in_bytes(pk.g) + element_length_in_bytes(pk.ga) +element_length_in_bytes(pk.eggalpha);
    *str = (unsigned char*) malloc(*str_count);
    unsigned char *pointer = *str;
    element_to_bytes(pointer, pk.g);
    pointer = pointer + element_length_in_bytes(pk.g);
    element_to_bytes(pointer, pk.ga);
    pointer = pointer + element_length_in_bytes(pk.ga);
    element_to_bytes(pointer, pk.eggalpha);
}

// string -> struct PK
void ABE2ODSPACE::ABE2OD::deserl_PK(struct ABE2ODSPACE::PK pk, unsigned char* str, size_t str_count)
{
    //printf("PK de-serialization --- \n");
    unsigned char *pointer = str;
    element_from_bytes(pk.g, pointer);
    pointer = pointer + G1_SIZE;
    element_from_bytes(pk.ga, pointer);
    pointer = pointer + G1_SIZE;
    element_from_bytes(pk.eggalpha, pointer);
   
}

// vector<element_s> -> string
void ABE2ODSPACE::ABE2OD::serl_vec(unsigned char** str, size_t* str_count, std::vector<struct element_s>& vec)
{
    //printf("vec serialization --- \n");
    *str_count = (size_t) element_length_in_bytes(&vec[0]) * vec.size();
    *str = (unsigned char*) malloc(*str_count);
    unsigned char *pointer = *str;
    for (size_t i = 0; i < vec.size(); i++)
    {
        // printf("length = %d,\t%d\n",  element_length_in_bytes(array[i]), *str_count);
        element_to_bytes(pointer, &vec[i]);
        pointer = pointer + element_length_in_bytes(&vec[i]);
    }
}

// string -> vector<element_s>
void ABE2ODSPACE::ABE2OD::deserl_vec(std::vector<struct element_s>& vec, unsigned char* str, size_t str_count)
{
    //printf("vec de-serialization --- \n");
    if(!vec.size())
    {
        //printf("***** REMEMBER ALLOCATE MEMORY FOR vec BEFORE USING THIS FUNCTION ******");
    }
    size_t each_length = (int) str_count / vec.size();  // ***** REMEMBER ALLOCATE MEMORY FOR vec BEFORE USING THIS FUNCTION ******
    unsigned char *pointer = str;
    for (size_t i = 0; i < vec.size(); i++)
    {
        // printf("length = %d,\t%d\n",  element_length_in_bytes(array[i]), *str_count);
        element_from_bytes(&vec[i], pointer);
        pointer = pointer + each_length;
    }
   
}

// map<string, element_s> -> string
void ABE2ODSPACE::ABE2OD::serl_umap(unsigned char** key_str, size_t* key_str_count,
               unsigned char** value_str, size_t* value_str_count,
               std::vector<size_t>& each_str_counts,
               std::map<std::string, struct element_s>& umap)
{
    //printf("umap serialization --- \n");
    *key_str_count = 0;
    *value_str_count = 0;
    for (std::pair<std::string, struct element_s> e : umap)
    {
        *key_str_count = *key_str_count + e.first.size();
        each_str_counts.push_back(e.first.size());
        *value_str_count = *value_str_count + (size_t) element_length_in_bytes(&e.second);
    }
    assert(each_str_counts.size() == umap.size());

    *key_str = (unsigned char*) malloc(*key_str_count);
    *value_str = (unsigned char*) malloc(*value_str_count);
    printf("%ld, %ld\n", *key_str_count, *value_str_count);
    char* key_pointer = (char *) *key_str;
    unsigned char* value_pointer = (unsigned char*) *value_str;
    for (std::pair<std::string, struct element_s> e : umap)
    {
        strncpy(key_pointer, e.first.c_str(), e.first.size());
        key_pointer = key_pointer + e.first.size();
        element_to_bytes(value_pointer, &e.second);
        value_pointer = value_pointer + element_length_in_bytes(&e.second);
    }
}

// string -> map<string, element_s>
void ABE2ODSPACE::ABE2OD::deserl_umap(std::map<std::string, struct element_s>& umap, unsigned char* str, size_t str_count)
{
    //printf("umap de-serialization --- \n");

    if(!umap.size())
    {
        printf("***** REMEMBER ALLOCATE MEMORY FOR vec BEFORE USING THIS FUNCTION ******");
    }
    size_t each_length = (int) str_count / umap.size();  // ***** REMEMBER ALLOCATE MEMORY FOR vec BEFORE USING THIS FUNCTION ******
    unsigned char *pointer = str;
    for (std::pair<std::string, struct element_s> e : umap)
    {
        element_from_bytes(&e.second, pointer);
        pointer = pointer + each_length;
    }
}


// LSSS -> string
void ABE2ODSPACE::ABE2OD::serl_lsss(char** policy_str, size_t* policy_str_count, LSSS *policy)
{
    //printf("LSSS serialization --- \n");
    *policy_str_count = policy->access_policy.size();
    *policy_str = (char*) malloc(*policy_str_count);
    strncpy(*policy_str, policy->access_policy.c_str(), *policy_str_count);
}

// string -> LSSS
void ABE2ODSPACE::ABE2OD::deserl_lsss(LSSS *policy, char* policy_str, size_t policy_str_count)
{
    //printf("LSSS de-serialization --- \n");
    std::string access_policy(policy_str, policy_str_count);
    policy->initialize(access_policy);
  
}


// struct MSK -> string
void ABE2ODSPACE::ABE2OD::serl_MSK(unsigned char** str, size_t* str_count, struct ABE2ODSPACE::MSK msk)
{
    //printf("MSK serialization --- \n");
    *str_count = (size_t) element_length_in_bytes(msk.galpha);
    *str = (unsigned char*) malloc(*str_count);
    unsigned char *pointer = *str;
    element_to_bytes(pointer, msk.galpha);
}

// string -> struct MSK
void ABE2ODSPACE::ABE2OD::deserl_MSK(struct ABE2ODSPACE::MSK msk, unsigned char* str, size_t str_count)
{
    //printf("MSK de-serialization --- \n");
    unsigned char *pointer = str;
    element_from_bytes(msk.galpha, pointer);
    
}


// struct Ciphertext -> string
void ABE2ODSPACE::ABE2OD::serl_Ciphertext(unsigned char** str, size_t* str_count, struct ABE2ODSPACE::Ciphertext cipher, size_t* policy_str_count)
{

    //printf("Ciphertext serialization --- \n");
    //LSSS
    char* policy_str;
    serl_lsss(&policy_str, policy_str_count, cipher.policy);
    
    //vec
    unsigned char* vec_str1;
    size_t str1_count;
    serl_vec(&vec_str1,&str1_count,cipher.Ei);
    unsigned char* vec_str2;
    size_t str2_count;
    serl_vec(&vec_str2,&str2_count,cipher.Di);
    unsigned char* vec_str3;
    size_t str3_count;
    serl_vec(&vec_str3,&str3_count,cipher.lambda);

    *str_count = (size_t) *policy_str_count + cipher_C1_size + element_length_in_bytes(cipher.C0) + element_length_in_bytes(cipher.C2)+str1_count+str2_count+str3_count;
    *str = (unsigned char*) malloc(*str_count);
    unsigned char *pointer = *str;
    memcpy(pointer, policy_str,*policy_str_count);//LSSS
    pointer=pointer+*policy_str_count;
    memcpy(pointer,cipher.C1.c_str(), cipher.C1.size());
    pointer=pointer+cipher.C1.size();
    element_to_bytes(pointer, cipher.C0);
    pointer = pointer + element_length_in_bytes(cipher.C0);
    element_to_bytes(pointer, cipher.C2);
    pointer = pointer + element_length_in_bytes(cipher.C2);
    memcpy(pointer, vec_str1,str1_count);//Ei
    pointer=pointer+str1_count;
    memcpy(pointer, vec_str2,str2_count);//Di
    pointer=pointer+str2_count;
    memcpy(pointer, vec_str3,str3_count);//lambda
}

// string -> struct Ciphertext
void ABE2ODSPACE::ABE2OD::deserl_Ciphertext(struct Ciphertext &cipher, unsigned char* str, size_t str_count, size_t policy_str_count)
{
    //printf("Ciphertext de-serialization --- \n");
    unsigned char *pointer = str;
    /*
    LSSS lsss_rec;
    char *policy = reinterpret_cast<char*>(pointer);
    std::string access_policy(policy, policy_str_count);
    lsss_rec.initialize(access_policy);
    cipher.policy=&lsss_rec;  得要在同一个文件里，不然赋值不成功，哪怕传了引用*/
    pointer= pointer+policy_str_count;
    
    string temp_C1(reinterpret_cast<char*>(pointer), cipher_C1_size);
    cipher.C1 = temp_C1;
    pointer=pointer + cipher.C1.size();
    
    element_from_bytes(cipher.C0, pointer);
    pointer = pointer + GT_SIZE;
    element_from_bytes(cipher.C2, pointer);
    pointer = pointer + G1_SIZE;
    size_t n= (str_count - policy_str_count - G1_SIZE - GT_SIZE-cipher_C1_size) / (G1_SIZE+ G1_SIZE+ ZR_SIZE);
    //Ci
    for (size_t i = 0; i < n; i++)
    {
        element_from_bytes(&cipher.Ei[i], pointer);
        pointer = pointer + G1_SIZE;
    }
    //Di
    for (size_t i = 0; i < n; i++)
    {
        element_from_bytes(&cipher.Di[i], pointer);
        pointer = pointer + G1_SIZE;
    }
    
    //lambda
    for (size_t i = 0; i < n; i++)
    {
        element_from_bytes(&cipher.lambda[i], pointer);
        pointer = pointer + ZR_SIZE;
    }    
    

}

// struct PTC -> string
void ABE2OD::serl_PTC(unsigned char** str, size_t* str_count, struct PTC ptc)
{
    //printf("PTC serialization --- \n");
    *str_count = ptc_C1_size + (size_t) element_length_in_bytes(ptc.C0) + (size_t) element_length_in_bytes(ptc.CP1) + (size_t) element_length_in_bytes(ptc.CP2);
    *str = (unsigned char*) malloc(*str_count);
    unsigned char *pointer = *str;
    memcpy(pointer,ptc.C1.c_str(), ptc.C1.size());
    pointer=pointer+ptc.C1.size();
 
    element_to_bytes(pointer, ptc.C0);
    pointer = pointer + element_length_in_bytes(ptc.C0);
    element_to_bytes(pointer, ptc.CP1);
    pointer = pointer + element_length_in_bytes(ptc.CP1);
    element_to_bytes(pointer, ptc.CP2);

}

// string -> struct PTC
void ABE2OD::deserl_PTC(struct PTC &ptc, unsigned char* str, size_t str_count)
{
    //printf("PTC de-serialization --- \n");
    unsigned char *pointer = str;
    string C1(reinterpret_cast<char*>(pointer), ptc_C1_size);
    ptc.C1=C1;
    pointer=pointer + ptc_C1_size;
    element_from_bytes(ptc.C0, pointer);
    pointer = pointer + GT_SIZE;
    element_from_bytes(ptc.CP1, pointer);
    pointer = pointer + GT_SIZE;
    element_from_bytes(ptc.CP2, pointer);

}

// struct TC -> string
void ABE2OD::serl_TC(unsigned char** str, size_t* str_count, struct TC tc)
{
    unsigned char *pointer = *str;
    memcpy(pointer, tc.T1.c_str(), tc_T1_size);
    pointer=pointer+tc.T1.size();
    element_to_bytes(pointer, tc.T0);
    pointer = pointer + element_length_in_bytes(tc.T0);
    element_to_bytes(pointer, tc.T2);

}

// string -> struct TC
void ABE2OD::deserl_TC(struct TC &tc, unsigned char* str, size_t str_count)
{
    //printf("TC de-serialization --- \n");
    unsigned char *pointer = str;
    string T1(reinterpret_cast<char*>(pointer), tc_T1_size);
    tc.T1=T1;
    pointer=pointer + tc_T1_size;
    element_from_bytes(tc.T0, pointer);
    pointer = pointer + GT_SIZE;
    element_from_bytes(tc.T2, pointer);
    //free(str);

}

// struct TK -> string
void ABE2ODSPACE::ABE2OD::serl_TK(unsigned char** str, size_t* str_count, struct ABE2ODSPACE::KeyTuple::TK tk,
		unsigned char** umap_key_str,size_t* umap_key_len, unsigned char** umap_value_str,size_t* umap_value_len,std::vector<size_t>& each_str_counts)
{

    //printf("TK serialization --- \n");
    //umap
    serl_umap(umap_key_str,umap_key_len, umap_value_str, umap_value_len, each_str_counts,tk.Ky);

    *str_count = (size_t) tk.attributes.size()+element_length_in_bytes(tk.K)+element_length_in_bytes(tk.L);//attributes+K+L
    *str = (unsigned char*) malloc(*str_count);
    unsigned char *pointer = *str;
    memcpy(pointer,tk.attributes.c_str(), tk.attributes.size());
    pointer=pointer+tk.attributes.size();
    element_to_bytes(pointer,tk.K);
    pointer = pointer + element_length_in_bytes(tk.K);
    element_to_bytes(pointer,tk.L);
    pointer = pointer + element_length_in_bytes(tk.L);
    // attributes+K+L -> pointer
}

// string -> struct TK
void ABE2ODSPACE::ABE2OD::deserl_TK(struct ABE2ODSPACE::KeyTuple::TK &tk, unsigned char* str, size_t str_count, unsigned char* umap_value_str, size_t umap_value_len)//加引用才能让string attributes成功赋值
{

    //printf("TK de-serialization --- \n");
    unsigned char *pointer = str;
    string attributes(reinterpret_cast<char*>(pointer), str_count-G1_SIZE-G1_SIZE);
    tk.attributes=attributes;
    pointer=pointer+tk.attributes.size();
    element_from_bytes(tk.K, pointer);
    pointer = pointer + G1_SIZE;
    element_from_bytes(tk.L, pointer);
    pointer = pointer + G1_SIZE;
    deserl_umap(tk.Ky, umap_value_str, umap_value_len);

}


// struct HK -> string
void ABE2OD::serl_HK(unsigned char** str, size_t* str_count, struct KeyTuple::HK hk)
{
    //printf("RK serialization --- \n");
    *str_count = (size_t) element_length_in_bytes(hk.gamma_1) + (size_t) element_length_in_bytes(hk.gamma_2);
    *str = (unsigned char*) malloc(*str_count);
    unsigned char *pointer = *str;
    element_to_bytes(pointer,hk.gamma_1);
    pointer = pointer + element_length_in_bytes(hk.gamma_2);
    element_to_bytes(pointer, hk.gamma_2);

}

// string -> struct HK
void ABE2OD::deserl_HK(struct KeyTuple::HK &hk, unsigned char* str, size_t str_count)
{

    //printf("HK de-serialization --- \n");
    unsigned char *pointer = str;
    element_from_bytes(hk.gamma_1, pointer);
    pointer = pointer + ZR_SIZE;
    element_from_bytes(hk.gamma_2, pointer);
    
    
}

// struct DK -> string
void ABE2OD::serl_DK(unsigned char** str, size_t* str_count, struct ABE2ODSPACE::KeyTuple::DK dk)
{
    //printf("DK serialization --- \n");
    *str_count = (size_t) element_length_in_bytes(dk.beta);
    *str = (unsigned char*) malloc(*str_count);
    unsigned char *pointer = *str;
    element_to_bytes(pointer, dk.beta);
}

// string -> struct DK
void ABE2OD::deserl_DK(struct ABE2ODSPACE::KeyTuple::DK &dk, unsigned char* str, size_t str_count)
{

    //printf("DK de-serialization --- \n");
    unsigned char *pointer = str;
    element_from_bytes(dk.beta, pointer);
}
