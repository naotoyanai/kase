/**
	@file
	@brief a sample of BLS signature
	see https://github.com/herumi/bls
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause

*/
#include <mcl/bn256.hpp>
#include <mcl/bn.hpp>
#include <iostream>
#include <mcl/aggregate_sig.hpp>
#include <cybozu/benchmark.hpp>
#include <cybozu/xorshift.hpp>
#include <mcl/bls12_381.hpp>


#define n 100
#define msgn 10

using namespace mcl::bn256;
using namespace mcl::aggs;



typedef struct {
    G1 gen1;
    G2 gen2;
    G1 gi1[2*n];
    G2 gi2[2*n];
} param;

typedef struct {
    G2 C1;
    G1 C2;
    Fp12 C3;
} cipher;

/*
void Hash(G1& P, const std::string& m)
{
	Fp t;
	t.setHashOf(m);
	mapToG1(P, t);
}
 */

void Hash(G1& P, const std::string& m)
{
    Fp t;
    t.setHashOf(m);
    mapToG1(P, t);
}


void Setup (param par)
{
    Fr a;
    a.setRand();
    int i;

    G1::mul(par.gi1[0], par.gen1, a);
    G2::mul(par.gi2[0], par.gen2, a);
    
    for (i=1; i <n; i++){
        a= a*a;
        G1::mul(par.gi1[i], par.gen1, a);
        G2::mul(par.gi2[i], par.gen2, a);
    }
    
}

void KeyGen(Fr& s)
{
    s.setRand();
}

void Extract(param par, const Fr& s, int S[n], G1& kagg)
{
    int i=0, k=0;
    for (i=0; i < n; i++){
        if (S[i]== 1) {
            k = n-i;
            G1::add(kagg, kagg, par.gi1[k]);
        }
    }
	G1::mul(kagg, kagg, s); // kagg = s _sum g[i]
}

void Encrypt(param par, Fr& s, int i, std::string& m, cipher Ci)
{
    Fr t;
    G1 Hm;
    G1 tv;
    G1 v;
    Fp12 e1, e2;
    int j = n;
    
    t.setRand();
    G2::mul (Ci.C1, par.gen2, s);
    G1::mul (v, par.gen1, s);
    G1::add (tv, v, par.gi1[i]);
    G1::mul(Ci.C2, tv, t);
    
    Hash(Hm, m);
    pairing(e1, Hm, par.gen2);
    Fp12::pow(e1, e1, t);

    pairing(e2, par.gen1, par.gi2[j]);
    Fp12::pow(e2, e2, t);
    
    Fp12::div(Ci.C3, e1, e2); // z = x / y
    
}

void Trapdoor(G1& Tr, param par, G1& kagg, const std::string& m)
{
    G1 Hm;
    Hash(Hm, m);
    G1::add(Tr, kagg, Hm); // sign = s H(m)
}

void Adjust (G1& Tri, param par, G1& Tr, int i, int S[n])
{
    int j=0, k=0;
    Tri = Tr;
    for (j=0; j< n; j++){
        if ( (S[j] == 1) && (j != i)) {
            k = n - j + i;
            G1::add (Tri, Tri, par.gi1[k]);
        }
    }
}

bool Test (param par, cipher Ci, G1 Tri, int S[n])
{
    Fp12 e1, e2, e3;
    G2 pub;
    int j;
    
    for (j=0; j<n; j++){
        if (S[j] == 1) pub += par.gi2[j];
    }
    pairing (e1, Tri, Ci.C1);
    pairing (e2, Ci.C2, pub);
    Fp12::div(e3, e1, e2);
    return e3 == Ci.C3;
}



//int main(int argc, char *argv[])
int main()
{
    const std::string msgArray[] = { "abc", "12345", "xyz", "pqr", "aggregate signature" };
    const size_t len = sizeof(msgArray) / sizeof(msgArray[0]);
    std::vector<std::string> msgVec(n);
    
    // for indexes
    int i =0, j=0, numofm = msgn;
    int S[n];
    for (i=0; i<n; i++){
        S[i]=0;
    }
    
    for (i = 0; i < n; i += msgn) {
        for (j=0; j < msgn; j++){
            msgVec[i] = msgArray[j];
            i++;
        }
    }
    
	// setup parameter
	initPairing();
    param pubk;
    Setup(pubk);

	// generate secret key and public key
	Fr s;
	KeyGen(s);
    
    // Encryption for n documents
    cipher cil[n];
    for (i = 0; i < n ; i++){
        Encrypt(pubk, s, i, msgVec[i], cil[i]);
    }
    
    // Extract
    G1 kagg;
    Extract(pubk, s, S, kagg);
    
    // Trapdoor generation
    G1 trap;
    i= 1;
    Trapdoor(trap, pubk, kagg, msgVec[i]);
    
    //Adujstment of trapdoor for n documents
    G1 trapi[n];
    for (i = 0; i< n; i++){
        Adjust (trapi[i], pubk, trap, i, S);
    }
    
    //Test
    i = 1;
    bool hit = Test (pubk, cil[i], trapi[i], S);
    std::cout << "test " << (hit ? "ok" : "ng") << std::endl;

/*
	// sign
	G1 sign;
	Sign(sign, s, m);
	std::cout << "msg " << m << std::endl;
	std::cout << "sign " << sign << std::endl;

	// verify
	bool ok = Verify(sign, Q, pub, m);
	std::cout << "verify " << (ok ? "ok" : "ng") << std::endl;
 */
}
