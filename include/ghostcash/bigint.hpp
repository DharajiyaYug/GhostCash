// bigint.hpp
//
// Thin RAII / convenience wrapper around GMP's mpz_t so the rest of the
// codebase can write ordinary-looking C++ (BigInt a = b * c % n;) instead of
// raw mpz_* calls everywhere. Only the operations GhostCash actually needs
// are wrapped -- this is not meant to be a general-purpose bignum library.

#pragma once

#include <gmp.h>
#include <string>
#include <stdexcept>
#include <utility>

class BigInt {
public:
    mpz_t v;

    BigInt() { mpz_init(v); }

    BigInt(long x) { mpz_init_set_si(v, x); }

    BigInt(const std::string& s, int base = 10) {
        mpz_init(v);
        if (mpz_set_str(v, s.c_str(), base) != 0) {
            mpz_clear(v);
            throw std::invalid_argument("BigInt: invalid numeral string: " + s);
        }
    }

    BigInt(const BigInt& other) { mpz_init_set(v, other.v); }

    BigInt(BigInt&& other) noexcept {
        mpz_init(v);
        mpz_swap(v, other.v);
    }

    BigInt& operator=(const BigInt& other) {
        if (this != &other) mpz_set(v, other.v);
        return *this;
    }

    BigInt& operator=(BigInt&& other) noexcept {
        if (this != &other) mpz_swap(v, other.v);
        return *this;
    }

    ~BigInt() { mpz_clear(v); }

    // ---- arithmetic (all modular ops reduce into [0, n)) ----

    static BigInt add(const BigInt& a, const BigInt& b) {
        BigInt r; mpz_add(r.v, a.v, b.v); return r;
    }

    static BigInt sub(const BigInt& a, const BigInt& b) {
        BigInt r; mpz_sub(r.v, a.v, b.v); return r;
    }

    static BigInt mulmod(const BigInt& a, const BigInt& b, const BigInt& n) {
        BigInt r, t;
        mpz_mul(t.v, a.v, b.v);
        mpz_mod(r.v, t.v, n.v);
        return r;
    }

    static BigInt powmod(const BigInt& base, const BigInt& exp, const BigInt& n) {
        BigInt r;
        mpz_powm(r.v, base.v, exp.v, n.v);
        return r;
    }

    // Modular inverse of a mod n. Throws if a is not invertible mod n.
    static BigInt invmod(const BigInt& a, const BigInt& n) {
        BigInt r;
        if (mpz_invert(r.v, a.v, n.v) == 0) {
            throw std::runtime_error("BigInt::invmod: value not invertible mod n");
        }
        return r;
    }

    static BigInt mod(const BigInt& a, const BigInt& n) {
        BigInt r; mpz_mod(r.v, a.v, n.v); return r;
    }

    static BigInt gcd(const BigInt& a, const BigInt& b) {
        BigInt r; mpz_gcd(r.v, a.v, b.v); return r;
    }

    // Random integer uniformly in [1, n-1], using a supplied GMP RNG state.
    static BigInt random_below(const BigInt& n, gmp_randstate_t& rng) {
        BigInt r;
        do {
            mpz_urandomm(r.v, rng, n.v);
        } while (mpz_sgn(r.v) == 0); // reject 0
        return r;
    }

    bool operator==(const BigInt& other) const { return mpz_cmp(v, other.v) == 0; }
    bool operator!=(const BigInt& other) const { return !(*this == other); }

    std::string to_string(int base = 10) const {
        char* s = mpz_get_str(nullptr, base, v);
        std::string result(s);
        void (*freefunc)(void*, size_t);
        mp_get_memory_functions(nullptr, nullptr, &freefunc);
        freefunc(s, std::string::traits_type::length(s) + 1);
        return result;
    }

    // Import raw big-endian bytes (e.g. a SHA-256 digest) as a positive integer.
    static BigInt from_bytes(const unsigned char* data, size_t len) {
        BigInt r;
        mpz_import(r.v, len, 1 /*MSB first*/, 1 /*word size*/, 0 /*native endian within word*/, 0, data);
        return r;
    }

    size_t bit_length() const {
        return mpz_sizeinbase(v, 2);
    }
};
