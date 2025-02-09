
#include "../Enclave.h"
#include "../Enclave_t.h"

#include <vector>
#include "ABE_sgx/LSSS.h"
#include "ABE_sgx/utilities.h"
#include <cassert>
LSSS::LSSS() {}

LSSS::LSSS(string access_control) {
    initialize(access_control);
}

void showstack(stack<pair<vector<int>, string>> stk)
{
    while(!stk.empty())
    {
        pair<vector<int>, string> top;
        top = stk.top();
        stk.pop();
    }
}

void LSSS::parseString(stack<pair<vector<int>, string>> &stk, pair<vector<int>, string> &pair, int& counter) {
    if(pair.second.at(0) != '(')
    {
        M.push_back(pair.first);
        rho.push_back(pair.second);
        return;
    }

    pair.second.erase(0,1);
    pair.second.pop_back();

    // get the threshold
    int d = pair.second.at(pair.second.size()-1)-'0';
    pair.second.erase(pair.second.size()-2, 2);

    // get the number and string
    vector<string> substrvec;
    string substr;
    int ct = 0;
    for(int i = 0; i<pair.second.size(); i++)
    {
        substr += pair.second.at(i);
        if(pair.second.at(i) == '(')
        {
            ++ct;
        }
        if(pair.second.at(i) == ')')
        {
            --ct;
        }
        if(0 == ct && pair.second.at(i) == ')')
        {
            substrvec.push_back(substr);
            ++i;
            substr.clear();
        }
        if(0 == ct && i<pair.second.size() && pair.second.at(i) == ')')
        {
            substrvec.push_back(substr);
            ++i;
            substr.clear();
        }
        if(0==ct && substr.size()!=0 &&
           i<pair.second.size()-1 && pair.second.at(i+1) == ',')
        {
            substrvec.push_back(substr);
            ++i;
            substr.clear();
        }
    }
    if(substr.size() !=0)    substrvec.push_back(substr);
    size_t n = substrvec.size();
    // cout << "d = " << d << "\tn = " << n << endl;
    assert(d <= n);

    // add zeros
    while(pair.first.size() < counter)  pair.first.push_back(0);

    for(int i = substrvec.size()-1; i>=0; --i)
    {
        // add vector
        vector<int> vec(pair.first);
        int x = i+1;
        int prod = 1;
        for(int t = 0; t<d-1; ++t)
        {
            prod *= x;
            vec.push_back(prod);
        }

        // output
        stk.push(make_pair(vec, substrvec.at(i)));
    }
    counter += (d-1);
}

void LSSS::initialize(string &access_control) {
    access_policy = access_control;
    trim(access_control);

    stack<pair<vector<int>, string>> stk;

    vector<int> init_vec;
    init_vec.push_back(1);
    int counter = 1;

    stk.push(make_pair(init_vec, access_control));


    while(!stk.empty())
    {
        //showstack(stk);
        pair<vector<int>, string> top;
        top = stk.top();
        stk.pop();
        parseString(stk, top, counter);
    }

    // reshape
    for(int i=0; i<M.size();i++)
    {
        while(M[i].size()<counter) M[i].push_back(0);
    }

    //show();
}

void LSSS::show() {
    if(M.size() != rho.size())
    {
        // cout << "size unmathced!" <<endl;
        throw;
    }

    for(int i=0; i<M.size(); i++)
    {
        // cout << "[ ";
        for(int j = 0; j<M[i].size();++j)
        {
            // cout << M[i].at(j) << " ";
        }
        // cout << "], \t" << rho[i] << endl;
    }

}

bool LSSS::satisfy(string &attributes) {
    // parse the string
    vector<string> attributes_set;
    string2attribute_Set(attributes_set, attributes);

    // for (int i=0; i < attributes_set.size(); ++i)   cout <<attributes_set.at(i) << ' ';
    // cout << endl;

    // fetch the rows
    vector<int> Itemp;
    Fetchrows(Itemp, attributes_set, rho);

    vector<vector<double>> matrix;
    for(int i=0; i<M[0].size(); ++i)
    {
        vector<double> vec;
        for (int j = 0; j < Itemp.size(); ++j) {
            vec.push_back(M.at(Itemp[j]).at(i));
        }

        if(i == 0) {
            vec.push_back(1);
        } else {
            vec.push_back(0);
        }

        for (int k=0; k < vec.size(); ++k)   // cout <<vec.at(k) << ' ';
        // cout << endl;
        matrix.push_back(vec);
    }
    vector<vector<double>> matrixT;
    for(int i=0; i<Itemp.size(); ++i)
    {
        vector<double> vec;
        for (int j = 0; j < M[0].size(); ++j) {
            vec.push_back((double)M[Itemp[i]][j]);
        }

        for (int k=0; k < vec.size(); ++k)   // cout <<vec.at(k) << ' ';
        // cout << endl;
        matrixT.push_back(vec);
    }
    //showmatrix(matrixT);

    vector<vector<double>> prod;

    for (int i = 0; i < matrixT.size(); ++i) {
        vector<double> vec;
        for(int j = 0; j<matrix[0].size(); ++j)
        {
            double sum = 0.0;
            for (int k = 0; k < matrixT[0].size(); ++k)
                sum += matrixT[i][k] * matrix[k][j];
            vec.push_back(sum);
        }
        prod.push_back(vec);
    }

    // solve
    vector<double> res;
    bool ret;
    solve(res, prod);
    for (int i=0; i<matrix.size(); ++i)
    {
        double sum = 0.0;
        for(int j = 0; j < matrix[i].size()-1; ++j)
        {
            sum += matrix[i][j] * res[j];
        }
        // cout << sum << '\t';
    } // cout << endl;

    return false;

}

bool LSSS::isSatisfy(string attributes, pairing_t pairing) {

    // parse the string
    vector<string> attributes_set;
    string2attribute_Set(attributes_set, attributes);


    vector<int> Itemp;
    Fetchrows(Itemp, attributes_set, rho);
    if(Itemp.size() == 0) return false;


    // transform to the linear equations
    vector<vector<double>> matrix;
    for(int i=0; i<M[0].size(); ++i)
    {
        vector<double> vec;
        for (int j = 0; j < Itemp.size(); ++j) {
            vec.push_back(M.at(Itemp[j]).at(i));
        }

        if(i == 0) {
            vec.push_back(1);
        } else {
            vec.push_back(0);
        }

        //for (int k=0; k < vec.size(); ++k)   cout <<vec.at(k) << ' ';
        //cout << endl;
        matrix.push_back(vec);
    }
    //showmatrix(matrix);

    // matrix
    vector<vector<double>> matrixT;
    for(int i=0; i<Itemp.size(); ++i)
    {
        vector<double> vec;
        for (int j = 0; j < M[0].size(); ++j) {
            vec.push_back((double)M[Itemp[i]][j]);
        }
        matrixT.push_back(vec);
    }
    //showmatrix(matrixT);

    vector<vector<double>> prod;

    for (int i = 0; i < matrixT.size(); ++i) {
        vector<double> vec;
        for(int j = 0; j<matrix[0].size(); ++j)
        {
            double sum = 0.0;
            for (int k = 0; k < matrixT[0].size(); ++k)
                sum += matrixT[i][k] * matrix[k][j];
            vec.push_back(sum);
        }
        prod.push_back(vec);
    }

    vector<vector<element_s>> prod_G;
    for (int i = 0; i < prod.size(); ++i)
    {
        vector<element_s> vec;
        for (int j = 0; j < prod[0].size(); ++j)
        {
            element_s a;
            element_init_Zr(&a, pairing);
            element_set_si(&a, (long)prod[i][j]);
            vec.push_back(a);
            //cout << prod[i][j] << '\t';
        }
        //cout << endl;

        prod_G.push_back(vec);
    }

    /*
    for (int i = 0; i < prod_G.size(); ++i)
    {
        for (int j = 0; j < prod_G[0].size(); ++j)
        {
            element_printf("(%d,%d)\t%B\n", i, j, &prod_G[i][j]);
        }
    }*/

    // solve
    vector<element_s> res;
    solve(res, prod_G, pairing);

    bool ret = true;
    for (int i=0; i<matrix.size(); ++i)
    {
        element_t sum;
        element_init_Zr(sum, pairing);
        element_set0(sum);
        for(int j = 0; j < matrix[i].size()-1; ++j)
        {
            element_t tmp;
            element_init_Zr(tmp, pairing);
            element_mul_si(tmp, &res[j], (unsigned int)matrix[i][j]);
            element_add(sum, sum, tmp);
            //sum += matrix[i][j] * res[j];
        }
        if(i == 0) {
            ret = ret && element_is1(sum);
        } else{
            ret = ret && element_is0(sum);
        }
    } 

    return ret;
}

LSSS::~LSSS() {
    rho.clear();
    for (int i = 0; i < M.size(); ++i) {
        M[i].clear();
    } M.clear();
}

void LSSS::generateShares(vector<element_s> &shares, vector<element_s> &secret, pairing_t pairing) {
    // debug the input secrets
    /*
    for(int i=0; i<secret.size(); i++)
    {
        element_printf("%d : %B \n", i, &secret[i]);
    }*/

    // generate the shares one by one
    for(int i=0; i< M.size(); i++)
    {
        element_s tmp;
        element_init_Zr(&tmp, pairing);
        element_set0(&tmp);

        for (int j = 0; j < secret.size(); ++j)
        {
            element_s tmp1;
            element_init_Zr(&tmp1, pairing);
            element_mul_si(&tmp1, &secret[j], M[i][j]);
            element_add(&tmp, &tmp, &tmp1);
        }
        shares.push_back(tmp);
    }

}

void LSSS::findVector(vector<element_s> &vec, const string attributes, pairing_t pairing) {


    // parse the string
    vector<string> attributes_set;
    string2attribute_Set(attributes_set, attributes);


    // fetch the rows
    vector<int> Itemp;
    Fetchrows(Itemp, attributes_set, rho);
    if(Itemp.size() == 0) return;


    // transform to the linear equations
    vector<vector<double>> matrix;
    for(int i=0; i<M[0].size(); ++i)
    {
        vector<double> vec;
        for (int j = 0; j < Itemp.size(); ++j) {
            vec.push_back(M.at(Itemp[j]).at(i));
        }

        if(i == 0) {
            vec.push_back(1);
        } else {
            vec.push_back(0);
        }
        matrix.push_back(vec);
    }
 

    // matrix
    vector<vector<double>> matrixT;
    for(int i=0; i<Itemp.size(); ++i)
    {
        vector<double> vec;
        for (int j = 0; j < M[0].size(); ++j) {
            vec.push_back((double)M[Itemp[i]][j]);
        }

        matrixT.push_back(vec);
    }

    vector<vector<double>> prod;

    for (int i = 0; i < matrixT.size(); ++i) {
        vector<double> vec;
        for(int j = 0; j<matrix[0].size(); ++j)
        {
            double sum = 0.0;
            for (int k = 0; k < matrixT[0].size(); ++k)
                sum += matrixT[i][k] * matrix[k][j];
            vec.push_back(sum);
        }
        prod.push_back(vec);
    }
    
    
    vector<vector<element_s>> prod_G;
    for (int i = 0; i < prod.size(); ++i)
    {
        vector<element_s> vec;
        for (int j = 0; j < prod[0].size(); ++j)
        {
            element_s a;
            element_init_Zr(&a, pairing);
            element_set_si(&a, (long)prod[i][j]);
            vec.push_back(a);
        }

        prod_G.push_back(vec);
    }

    // solve
    solve(vec, prod_G, pairing);

}

void LSSS::getValidShares(vector<element_s> &valid_Shares, vector<element_s> &shares, string attributes, pairing_t pairing) {

    // parse the string
    vector<string> attributes_set;
    string2attribute_Set(attributes_set, attributes);
    vector<int> Itemp;
    Fetchrows(Itemp, attributes_set, rho);
    // cout << "I size:" << I.size() << endl;
    if(Itemp.size() == 0) return;

    for (int i=0; i <Itemp.size(); ++i) {
        element_s tmp;
        element_init_Zr(&tmp, pairing);
        element_set(&tmp, &shares[Itemp[i]]);
        valid_Shares.push_back(tmp);
    }
}

void LSSS::getValidSharesExt(vector<element_s> &valid_Shares, vector<element_s> &valid_Ci, vector<element_s> &valid_Di, vector<element_s> &valid_kx,
                       vector<element_s> &shares, vector<element_s> &Ci, vector<element_s> &Di,map<string, element_s> &kx,
                       string attributes, pairing_t pairing)
{
    // parse the string
    vector<string> attributes_set;
    string2attribute_Set(attributes_set, attributes);

    // fetch the rows
    vector<int> Itemp;
    Fetchrows(Itemp, attributes_set, rho);
    //cout << "I size:" << I.size() << endl;
    if(Itemp.size() == 0) return;

    for (int i=0; i < Itemp.size(); ++i) {
        element_s tmp,c,d, k;
        element_init_Zr(&tmp, pairing);
        element_init_G1(&c, pairing);
        element_init_G1(&d, pairing);
        element_init_G1(&k, pairing);

        element_set(&tmp, &shares[Itemp[i]]);
        element_set(&c, &Ci[Itemp[i]]);
        element_set(&d, &Di[Itemp[i]]);
        element_set(&k, &kx.at(rho.at(Itemp[i])));

        valid_Shares.push_back(tmp);
        valid_Ci.push_back(c);
        valid_Di.push_back(d);
        valid_kx.push_back(k);
    }
}


