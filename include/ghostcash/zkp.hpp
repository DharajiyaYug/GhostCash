#pragma once

#include "ghostcash/bigint.hpp"
#include "ghostcash/group_setup.hpp"
#include <gmp.h>

class Schnorr {
public:
    static bool is_group_element(const GroupParams& grp, const BigInt& e) {
        if (mpz_cmp_ui(e.v, 1) <= 0) return false;
        if (mpz_cmp(e.v, grp.p.v) >= 0) return false;
        return BigInt::powmod(e, grp.q, grp.p) == BigInt(1);
    }

    static bool is_valid_challenge(const GroupParams& grp, const BigInt& x) {
        return mpz_cmp_ui(x.v, 1) >= 0 && mpz_cmp(x.v, grp.q.v) < 0;
    }

    static BigInt respond(const BigInt& a, const BigInt& s, const BigInt& x, const BigInt& q) {
        return BigInt::mod(BigInt::add(s, BigInt::mulmod(a, x, q)), q);
    }

    static bool verify(const GroupParams& grp, const BigInt& A, const BigInt& S,
                       const BigInt& x, const BigInt& y) {
        if (!is_group_element(grp, A) || !is_group_element(grp, S)) return false;
        if (!is_valid_challenge(grp, x)) return false;
        if (mpz_sgn(y.v) < 0 || mpz_cmp(y.v, grp.q.v) >= 0) return false;

        BigInt lhs = BigInt::powmod(grp.g, y, grp.p);
        BigInt rhs = BigInt::mulmod(S, BigInt::powmod(A, x, grp.p), grp.p);
        return lhs == rhs;
    }

    static bool extract(const GroupParams& grp,
                        const BigInt& x1, const BigInt& y1,
                        const BigInt& x2, const BigInt& y2,
                        BigInt& a_out, BigInt& s_out) {
        BigInt dx = BigInt::mod(BigInt::sub(x1, x2), grp.q);
        if (mpz_sgn(dx.v) == 0) return false;

        BigInt dy = BigInt::sub(y1, y2);
        a_out = BigInt::mulmod(dy, BigInt::invmod(dx, grp.q), grp.q);
        s_out = BigInt::mod(BigInt::sub(y1, BigInt::mulmod(a_out, x1, grp.q)), grp.q);
        return true;
    }
};
