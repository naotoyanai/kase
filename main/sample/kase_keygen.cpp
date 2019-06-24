/**
	@file
	@brief a sample of BLS signature
	see https://github.com/herumi/bls
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause

*/
#include <mcl/bn256.hpp>
#include <iostream>

Define int n =10

struct param {
    G1 gen1;
    G2 gen2;
    G1 g[n];
}

using namespace mcl::bn256;

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

void KeyGen(Fr& s)
{
	s.setRand();
}

void Extract(struct param, const Fr& s, int S[n], G1 kagg)
{
    for (i=0; i < n; i++){
        if (S[i]== 1) kagg += param.g[i];
    }
	G1::mul(kagg, kagg, s); // kagg = s _sum g[i]
}


void Trapdoor(G1& Tr, struct param, G1& kagg, const std::string& m)
{
    G1 Hm;
    Hash(Hm, m);
    Tr = kagg + Hm; // sign = s H(m)
}


/*
bool Verify(const G1& sign, const G2& Q, const G2& pub, const std::string& m)
{
	Fp12 e1, e2;
	G1 Hm;
	Hash(Hm, m);
	pairing(e1, sign, Q); // e1 = e(sign, Q)
	pairing(e2, Hm, pub); // e2 = e(Hm, sQ)
	return e1 == e2;
}
 */

int main(int argc, char *argv[])
{
	std::string m = argc == 1 ? "hello mcl" : argv[1];

	// setup parameter
	initPairing();
	G2 Q;
	mapToG2(Q, 1);

	// generate secret key and public key
	Fr s;
	G2 pub;
	KeyGen(s);
	std::cout << "secret key " << s << std::endl;
	std::cout << "public key " << pub << std::endl;
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
