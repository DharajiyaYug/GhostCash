// rng.hpp
//
// Single shared source of randomness for the whole project. Every module
// that needs randomness (group setup, RSA keygen, wallet blinding, and
// eventually the ZKP and double-spend modules) pulls its gmp_randstate_t
// from here, instead of each file seeding its own -- one seed point, one
// place to swap the seeding strategy (e.g. for reproducible tests) later.
//
// Usage:
//   gmp_randstate_t& rng = Rng::instance();

#pragma once

#include <gmp.h>
#include <chrono>

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
        unsigned long seed = static_cast<unsigned long>(
            std::chrono::high_resolution_clock::now().time_since_epoch().count());
        gmp_randseed_ui(state_, seed);
    }

    ~Rng() {
        gmp_randclear(state_);
    }
};
