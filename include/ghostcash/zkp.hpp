// zkp.hpp
//
// The Schnorr-style proof from the coin's committed secrets.
//
// A coin carries A = g^a and S = g^s, both signed by the bank. S plays the
// role of Schnorr's commitment (fixed at withdrawal, so no extra commitment
// message is needed at payment time) and A is the public key. Given a
// challenge x from the receiver, the wallet answers
//
//     y = s + a*x   (mod q)
//
// and the receiver accepts iff  g^y == S * A^x  (mod p).
//
// One transcript reveals nothing about a or s: for any (x, y) there is an
// S that makes it verify (see the simulator test), and s masks a*x. Two
// transcripts (x1, y1), (x2, y2) with x1 != x2 on the same coin determine
// both secrets:
//
//     a = (y1 - y2) / (x1 - x2),   s = y1 - a*x1        (mod q)
//
// That extraction is what the bank uses to trace a double spend.

#pragma once

#include "ghostcash/bigint.hpp"
#include "ghostcash/group_setup.hpp"
#include <gmp.h>

class Schnorr {
public:
    // True iff e is a non-trivial element of the order-q subgroup:
    // 1 < e < p and e^q == 1 (mod p). Rejects 0, 1 and anything outside the
    // subgroup (e.g. p-1, which has order 2), so a malformed A or S can't be
    // slipped past the verifier.
    static bool is_group_element(const GroupParams& grp, const BigInt& e) {
        if (mpz_cmp_ui(e.v, 1) <= 0) return false;
        if (mpz_cmp(e.v, grp.p.v) >= 0) return false;
        return BigInt::powmod(e, grp.q, grp.p) == BigInt(1);
    }

    // A challenge must lie in [1, q-1]. x = 0 is rejected: it would make the
    // response equal s.
    static bool is_valid_challenge(const GroupParams& grp, const BigInt& x) {
        return mpz_cmp_ui(x.v, 1) >= 0 && mpz_cmp(x.v, grp.q.v) < 0;
    }

    // Wallet side: y = s + a*x mod q.
    static BigInt respond(const BigInt& a, const BigInt& s, const BigInt& x, const BigInt& q) {
        return BigInt::mod(BigInt::add(s, BigInt::mulmod(a, x, q)), q);
    }

    // Receiver / bank side: g^y == S * A^x (mod p), after validating A, S, x
    // and the range of y.
    static bool verify(const GroupParams& grp, const BigInt& A, const BigInt& S,
                       const BigInt& x, const BigInt& y) {
        if (!is_group_element(grp, A) || !is_group_element(grp, S)) return false;
        if (!is_valid_challenge(grp, x)) return false;
        if (mpz_sgn(y.v) < 0 || mpz_cmp(y.v, grp.q.v) >= 0) return false;

        BigInt lhs = BigInt::powmod(grp.g, y, grp.p);
        BigInt rhs = BigInt::mulmod(S, BigInt::powmod(A, x, grp.p), grp.p);
        return lhs == rhs;
    }

    // Recovers (a, s) from two accepted transcripts of the same coin.
    // Returns false if the challenges coincide mod q (nothing to solve).
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
