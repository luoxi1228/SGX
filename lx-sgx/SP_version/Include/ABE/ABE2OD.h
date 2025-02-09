

#ifndef SECRETSHARING_ABE2OD_H
#define SECRETSHARING_ABE2OD_H

#include <vector>
#include <map>
#include <bitset>
#include <openssl/sha.h>
#include <string>

#include "../pbc/pbc.h"
#include "../PicoSHA2/picosha2.h"

#include "utilities.h"
#include "LSSS.h"

using namespace std;
namespace ABE2ODSPACE
{
    struct PK {
        element_t g;
        element_t eggalpha;
        element_t ga;
    };

    struct MSK {
        element_t galpha;
    };

    struct KeyTuple {
        struct TK {
            string attributes;
            element_t K;
            element_t L;
            map<string, element_s> Ky; 
        };
        struct HK {
            element_t gamma_1;//Zr
            element_t gamma_2;//Zr
        };
        struct DK {
            element_t beta; //Zr
        };

        TK tk_1;
        TK tk_2;
        HK hk;
        DK dk;
    };

    struct Ciphertext {
        LSSS *policy;
        element_t C0;
        string C1;//hash
        element_t C2;
        vector<element_s> Di;
        vector<element_s> Ei;
        vector<element_s> lambda;
    };

    struct PTC {
        element_t C0;
        string C1;
        element_t CP1;
        element_t CP2;
    };
    
    struct TC {
        element_t T0;
        string T1;
        element_t T2;
    };

    class ABE2OD {
    public:
        PK pk;
        MSK msk;
        
        /*
         * constructor and destructor
         */
        ABE2OD();
        ~ABE2OD();

        /*
         * initialize the parameters
         * _pairing : initialize the pairing
         */
        void Setup(pairing_t _pairing);
        void Enc(Ciphertext &cipher, string M, LSSS &lsss, pairing_t _pairing);
        void KeyGen(KeyTuple &keytuple, const string _attributes, pairing_t _pairing);
        void Transform1(PTC &ptc, KeyTuple::TK &tk_1, KeyTuple::TK &tk_2, Ciphertext &cipher, pairing_t _pairing);
        void Transform2(TC &tc, KeyTuple::HK &hk, PTC &ptc, pairing_t _pairing);
        string Dec(KeyTuple::DK &dk, TC &tc, pairing_t _pairing);
        /*
         * Serl functions
         */
        void SETSTATICSIZE(pairing_t pairing);
        void serl(unsigned char** str, size_t* count, element_t e);
        void serl_array(unsigned char** arr_str, size_t* str_count, element_t *array, size_t array_length);
        void serl_PK(unsigned char** str, size_t* str_count, struct PK pk);
        void serl_vec(unsigned char** str, size_t* str_count, std::vector<struct element_s>& vec);
        void serl_umap(unsigned char** key_str, size_t* key_str_count,
               unsigned char** value_str, size_t* value_str_count,
               std::vector<size_t>& each_str_counts,
               std::map<std::string, struct element_s>& umap);
        void serl_lsss(char** policy_str, size_t* policy_str_count, LSSS *policy); 
        void serl_MSK(unsigned char** str, size_t* str_count, struct MSK msk);
        void serl_Ciphertext(unsigned char** str, size_t* str_count, struct Ciphertext cipher, size_t* policy_str_count);
        void serl_PTC(unsigned char** str, size_t* str_count, struct PTC ptc);
        void serl_TC(unsigned char** str, size_t* str_count, struct TC tc); 
        void serl_TK(unsigned char** str, size_t* str_count, struct KeyTuple::TK tk,unsigned char** umap_key_str,size_t* umap_key_len, 
        		unsigned char** umap_value_str,size_t* umap_value_len,std::vector<size_t>& each_str_counts);
	void serl_HK(unsigned char** str, size_t* str_count, struct KeyTuple::HK hk);
	void serl_DK(unsigned char** str, size_t* str_count, struct KeyTuple::DK dk);
        /*
         * deSerl functions
         */
        void deserl(element_t e, unsigned char* str, size_t count);
        void deserl_array(element_t* array_rec, size_t array_length, unsigned char* arr_str, size_t str_count);
        void deserl_PK(struct PK pk, unsigned char* str, size_t str_count);
        void deserl_vec(std::vector<struct element_s>& vec, unsigned char* str, size_t str_count);
        void deserl_umap(std::map<std::string, struct element_s>& umap, unsigned char* str, size_t str_count);
        void deserl_lsss(LSSS *policy, char* policy_str, size_t policy_str_count);
        void deserl_MSK(struct MSK msk, unsigned char* str, size_t str_count);
        void deserl_Ciphertext(struct Ciphertext &cipher, unsigned char* str, size_t str_count, size_t policy_str_count);
        void deserl_PTC(struct PTC &ptc, unsigned char* str, size_t str_count);
        void deserl_TC(struct TC &tc, unsigned char* str, size_t str_count);
        void deserl_TK(struct KeyTuple::TK &tk, unsigned char* str, size_t str_count, unsigned char* umap_value_str, size_t umap_value_len);
        void deserl_HK(struct KeyTuple::HK &hk, unsigned char* str, size_t str_count);
        void deserl_DK(struct KeyTuple::DK &dk, unsigned char* str, size_t str_count);
        /*
         * DEBUG functions
         */
        void showkeys();
        void showkeytuple(KeyTuple &ktuple);
        void showcipher(Ciphertext &cipher);
        void showPTC(PTC &ptc);
        void showTC(TC &tc);
        void showTK(KeyTuple::TK &tk);
        void showHK(KeyTuple::HK &hk);
    };

}


#endif //SECRETSHARING_ABE2OD_H
