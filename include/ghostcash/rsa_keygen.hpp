#pragma once

#include "ghostcash/bigint.hpp"
#include <gmp.h>

struct RSAKeyPair {
    BigInt n;
    BigInt e;
    BigInt d;
    int modulus_bits;
};

class RSAKeyGen {
public:
    static RSAKeyPair generate(int n_bits, Rng& rng) {
        RSAKeyPair kp;
        kp.modulus_bits = n_bits;
        kp.e = BigInt(65537);

        int prime_bits = n_bits / 2;

        BigInt p = random_prime(prime_bits, rng, kp.e);
        BigInt q;
        do {
            q = random_prime(prime_bits, rng, kp.e);
        } while (q == p);

        mpz_t n, phi, p1, q1, d;
        mpz_inits(n, phi, p1, q1, d, nullptr);

        mpz_mul(n, p.v, q.v);

        mpz_sub_ui(p1, p.v, 1);
        mpz_sub_ui(q1, q.v, 1);
        mpz_mul(phi, p1, q1);

        if (mpz_invert(d, kp.e.v, phi) == 0) {
            mpz_clears(n, phi, p1, q1, d, nullptr);
            throw std::runtime_error("RSAKeyGen: e not invertible mod phi(n); retry key generation");
        }

        mpz_set(kp.n.v, n);
        mpz_set(kp.d.v, d);

        mpz_clears(n, phi, p1, q1, d, nullptr);
        return kp;
    }

private:
    static BigInt random_prime(int bits, Rng& rng, const BigInt& e) {
        mpz_t candidate, p_minus_1, g;
        mpz_inits(candidate, p_minus_1, g, nullptr);

        for (;;) {
            rng.bits(candidate, bits);
            mpz_setbit(candidate, bits - 1);
            mpz_setbit(candidate, bits - 2);
            mpz_setbit(candidate, 0);

            if (mpz_probab_prime_p(candidate, 40) > 0) {
                mpz_sub_ui(p_minus_1, candidate, 1);
                mpz_gcd(g, p_minus_1, e.v);
                if (mpz_cmp_ui(g, 1) == 0) {
                    break;
                }
            }
        }

        BigInt result;
        mpz_set(result.v, candidate);
        mpz_clears(candidate, p_minus_1, g, nullptr);
        return result;
    }
};
