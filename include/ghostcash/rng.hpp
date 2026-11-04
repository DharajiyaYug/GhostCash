#pragma once

#include <gmp.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <cstddef>
#include <stdexcept>
#include <vector>

class Rng {
public:
    static Rng& instance() {
        static Rng holder;
        return holder;
    }

    void bytes(unsigned char* out, size_t len) {
        if (len == 0) return;
        if (RAND_bytes(out, static_cast<int>(len)) != 1) {
            throw std::runtime_error("Rng: RAND_bytes failed");
        }
    }

    void bits(mpz_t out, size_t nbits) {
        if (nbits == 0) {
            mpz_set_ui(out, 0);
            return;
        }
        std::vector<unsigned char> buf((nbits + 7) / 8);
        bytes(buf.data(), buf.size());
        mpz_import(out, buf.size(), 1, 1, 0, 0, buf.data());
        OPENSSL_cleanse(buf.data(), buf.size());
        mpz_fdiv_r_2exp(out, out, nbits);
    }

    void below(mpz_t out, const mpz_t n) {
        if (mpz_sgn(n) <= 0) throw std::invalid_argument("Rng: bound must be positive");
        size_t nbits = mpz_sizeinbase(n, 2);
        do {
            bits(out, nbits);
        } while (mpz_cmp(out, n) >= 0);
    }

    size_t index_below(size_t n) {
        if (n == 0) throw std::invalid_argument("Rng: bound must be positive");
        mpz_t bound, r;
        mpz_init_set_ui(bound, n);
        mpz_init(r);
        below(r, bound);
        size_t result = mpz_get_ui(r);
        mpz_clears(bound, r, nullptr);
        return result;
    }

    Rng(const Rng&) = delete;
    Rng& operator=(const Rng&) = delete;

private:
    Rng() = default;
};
