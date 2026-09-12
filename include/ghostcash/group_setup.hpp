// group_setup.hpp
//
// One-time system setup: generates a prime-order subgroup of order q
// (256-bit) of Z_p^*, with generator g, following the approach used in DSA
// parameter generation. This is run once and the resulting (p, q, g) are
// fixed thereafter as shared public parameters used by the bank, every
// wallet, and every merchant.
//
// NOTE: this is a simplified, non-seeded construction (adequate for a course
// project); it does not implement the verifiable seeded-search procedure
// FIPS 186 uses to make the parameter choice publicly auditable.

#pragma once

#include "ghostcash/bigint.hpp"
#include <gmp.h>
#include <stdexcept>

struct GroupParams {
    BigInt p; // large prime, |p| >= q_bits + safety margin
    BigInt q; // 256-bit prime order of the subgroup, q | (p - 1)
    BigInt g; // generator of the order-q subgroup
};

class GroupSetup {
public:
    // p_bits should comfortably exceed q_bits for discrete log to be hard in
    // Z_p^* itself (e.g. q_bits = 256, p_bits = 3072).
    static GroupParams generate(int q_bits, int p_bits, gmp_randstate_t& rng) {
        if (p_bits <= q_bits) {
            throw std::invalid_argument("GroupSetup: p_bits must exceed q_bits");
        }

        BigInt q = random_prime(q_bits, rng);

        // Find p = k*q + 1 prime, for random k, with p at the target bit length.
        int k_bits = p_bits - q_bits;
        BigInt p;
        mpz_t k, candidate;
        mpz_inits(k, candidate, nullptr);
        for (;;) {
            mpz_urandomb(k, rng, k_bits);
            mpz_setbit(k, k_bits - 1); // ensure p reaches the target bit length
            // q is odd (it's an odd prime), so p = k*q + 1 is odd iff k is
            // even. Force k even so p has a chance of being prime.
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

        // Find generator g of the order-q subgroup: pick random h in [2, p-2],
        // compute g = h^((p-1)/q) mod p, retry if g == 1.
        BigInt g;
        mpz_t exponent, p_minus_1;
        mpz_inits(exponent, p_minus_1, nullptr);
        mpz_sub_ui(p_minus_1, p.v, 1);
        mpz_divexact(exponent, p_minus_1, q.v);

        for (;;) {
            BigInt h = BigInt::random_below(p, rng); // in [1, p-1]
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
