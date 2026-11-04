#pragma once

#include <gmp.h>
#include <openssl/rand.h>
#include <stdexcept>

class Rng {
public:
    static gmp_randstate_t& instance() {
        static Rng holder;
        return holder.state_;
    }

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
