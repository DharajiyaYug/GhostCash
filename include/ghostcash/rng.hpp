// rng.hpp
//
// Single shared source of randomness for the whole project. Every module
// that needs randomness (group setup, RSA keygen, wallet blinding, and
// eventually the ZKP and double-spend modules) pulls its gmp_randstate_t
// from here, instead of each file seeding its own -- one seed point, one
// place to swap the seeding strategy (e.g. for reproducible tests) later.
//
// Seeding: the generator is seeded with 256 bits from the operating system's
// entropy source (OpenSSL RAND_bytes), not from the clock. Limitation: GMP only
// offers non-cryptographic generators (Mersenne Twister here), so the secrets
// drawn from it are only as unpredictable as that 256-bit seed and the
// generator's internal state allow. A production system would draw secrets
// directly from a CSPRNG.
//
// Usage:
//   gmp_randstate_t& rng = Rng::instance();

#pragma once

#include <gmp.h>
#include <openssl/rand.h>
#include <stdexcept>

class Rng {
public:
    static gmp_randstate_t& instance() {
        static Rng holder; // constructed once, lazily, on first use
        return holder.state_;
    }

    // Re-seeds the shared RNG deterministically. Intended for tests that
    // need reproducible output; not used by the demo or normal operation.
    static void reseed(unsigned long seed) {
        gmp_randseed_ui(instance(), seed);
    }

    Rng(const Rng&) = delete;
    Rng& operator=(const Rng&) = delete;

private:
    gmp_randstate_t state_;

    Rng() {
        gmp_randinit_mt(state_);
        unsigned char seed_bytes[32];
        if (RAND_bytes(seed_bytes, sizeof seed_bytes) != 1) {
            throw std::runtime_error("Rng: could not read OS entropy");
        }
        mpz_t seed;
        mpz_init(seed);
        mpz_import(seed, sizeof seed_bytes, 1, 1, 0, 0, seed_bytes);
        gmp_randseed(state_, seed);
        mpz_clear(seed);
    }

    ~Rng() {
        gmp_randclear(state_);
    }
};
