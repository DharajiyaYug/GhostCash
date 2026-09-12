// rsa_keygen.hpp
//
// Minimal RSA-2048 keypair generation, built specifically to support the
// blind-signature scheme (i.e. plain textbook RSA -- no OAEP/PSS padding,
// since blind signing operates directly on the algebraic homomorphism and
// application-level padding schemes are not compatible with blinding).

#pragma once

#include "ghostcash/bigint.hpp"
#include <gmp.h>

struct RSAKeyPair {
    BigInt n;   // modulus, n = p*q
    BigInt e;   // public exponent
    BigInt d;   // private exponent, d = e^-1 mod phi(n)
    int modulus_bits;
};

class RSAKeyGen {
public:
    // Generates an RSA keypair with an n_bits-bit modulus (spec: 2048).
    // Uses the fixed public exponent e = 65537, standard practice since it's
    // small enough for fast verification and large enough to avoid known
    // small-exponent attacks.
    static RSAKeyPair generate(int n_bits, gmp_randstate_t& rng) {
        RSAKeyPair kp;
        kp.modulus_bits = n_bits;
        kp.e = BigInt(65537);

        int prime_bits = n_bits / 2;

        BigInt p = random_prime(prime_bits, rng, kp.e);
        BigInt q;
        do {
            q = random_prime(prime_bits, rng, kp.e);
        } while (q == p); // vanishingly unlikely, but guard against p == q anyway

        mpz_t n, phi, p1, q1, d;
        mpz_inits(n, phi, p1, q1, d, nullptr);

        mpz_mul(n, p.v, q.v);

        mpz_sub_ui(p1, p.v, 1);
        mpz_sub_ui(q1, q.v, 1);
        mpz_mul(phi, p1, q1); // Using phi(n) = (p-1)(q-1); Carmichael's lambda(n)
                              // would also work and is what real-world RSA
                              // implementations prefer, but phi(n) is simpler
                              // to reason about for a course project and is
                              // still perfectly correct for key generation.

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
    // Generates a random prime of exactly `bits` bits such that gcd(p-1, e) == 1
    // (required so that e is invertible mod phi(n) later).
    static BigInt random_prime(int bits, gmp_randstate_t& rng, const BigInt& e) {
        mpz_t candidate, p_minus_1, g;
        mpz_inits(candidate, p_minus_1, g, nullptr);

        for (;;) {
            mpz_urandomb(candidate, rng, bits);
            // Force the TOP TWO bits (not just the top bit). Forcing only the
            // top bit guarantees each prime is exactly `bits` bits, but two
            // such primes multiplied together can land one bit short of
            // 2*bits (e.g. two primes each just above 2^(bits-1) multiply to
            // just above 2^(2*bits-2)). Forcing the top two bits guarantees
            // each prime exceeds sqrt(2) * 2^(bits-1), which guarantees the
            // product always reaches the full 2*bits bit length.
            mpz_setbit(candidate, bits - 1);
            mpz_setbit(candidate, bits - 2);
            mpz_setbit(candidate, 0);         // force odd

            // 40 rounds of Miller-Rabin: probability of a false positive is
            // astronomically small (< 4^-40), standard choice for crypto-grade
            // primes generated via GMP's probabilistic test.
            if (mpz_probab_prime_p(candidate, 40) > 0) {
                mpz_sub_ui(p_minus_1, candidate, 1);
                mpz_gcd(g, p_minus_1, e.v);
                if (mpz_cmp_ui(g, 1) == 0) {
                    break; // candidate is prime and e is invertible mod (candidate-1)
                }
            }
        }

        BigInt result;
        mpz_set(result.v, candidate);
        mpz_clears(candidate, p_minus_1, g, nullptr);
        return result;
    }
};
