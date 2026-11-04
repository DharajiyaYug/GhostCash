#pragma once

#include "ghostcash/bigint.hpp"
#include <gmp.h>
#include <stdexcept>

struct GroupParams {
    BigInt p;
    BigInt q;
    BigInt g;
};

class GroupSetup {
public:
    static GroupParams generate(int q_bits, int p_bits, gmp_randstate_t& rng) {
        if (p_bits <= q_bits) {
            throw std::invalid_argument("GroupSetup: p_bits must exceed q_bits");
        }

        BigInt q = random_prime(q_bits, rng);

        int k_bits = p_bits - q_bits;
        BigInt p;
        mpz_t k, candidate;
        mpz_inits(k, candidate, nullptr);
        for (;;) {
            mpz_urandomb(k, rng, k_bits);
            mpz_setbit(k, k_bits - 1);
            if (mpz_odd_p(k)) mpz_add_ui(k, k, 1);

            mpz_mul(candidate, k, q.v);
            mpz_add_ui(candidate, candidate, 1);

            if ((int)mpz_sizeinbase(candidate, 2) != p_bits) continue;
            if (mpz_probab_prime_p(candidate, 40) > 0) {
                mpz_set(p.v, candidate);
                break;
            }
        }
        mpz_clears(k, candidate, nullptr);

        BigInt g;
        mpz_t exponent, p_minus_1;
        mpz_inits(exponent, p_minus_1, nullptr);
        mpz_sub_ui(p_minus_1, p.v, 1);
        mpz_divexact(exponent, p_minus_1, q.v);

        for (;;) {
            BigInt h = BigInt::random_below(p, rng);
            mpz_powm(g.v, h.v, exponent, p.v);
            if (mpz_cmp_ui(g.v, 1) != 0) break;
        }
        mpz_clears(exponent, p_minus_1, nullptr);

        return GroupParams{p, q, g};
    }

private:
    static BigInt random_prime(int bits, gmp_randstate_t& rng) {
        mpz_t candidate;
        mpz_init(candidate);
        for (;;) {
            mpz_urandomb(candidate, rng, bits);
            mpz_setbit(candidate, bits - 1);
            mpz_setbit(candidate, 0);
            if (mpz_probab_prime_p(candidate, 40) > 0) break;
        }
        BigInt result;
        mpz_set(result.v, candidate);
        mpz_clear(candidate);
        return result;
    }
};
