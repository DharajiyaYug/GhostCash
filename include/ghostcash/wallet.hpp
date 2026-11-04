#pragma once

#include "ghostcash/bigint.hpp"
#include "ghostcash/coin.hpp"
#include "ghostcash/public_keys.hpp"
#include "ghostcash/hash_utils.hpp"
#include "ghostcash/zkp.hpp"
#include <gmp.h>
#include <sstream>

struct PendingWithdrawal {
    int denomination;
    std::string serial;
    BigInt A, S;
    BigInt m;
    BigInt r;
    BigInt blinded_m;
    BigInt a, s;
    BigInt tag;
};

struct WalletCoin {
    Coin coin;
    BigInt a, s;
    bool spent = false;
};

class Wallet {
public:
    Wallet(BigInt group_p, BigInt group_q, BigInt group_g, gmp_randstate_t& rng)
        : p_(std::move(group_p)), q_(std::move(group_q)), g_(std::move(group_g)), rng_(rng) {}

    BigInt prepare_withdrawal(int denomination, const PublicKeySource& keys, PendingWithdrawal& out_pending) {
        BigInt a = BigInt::random_below(q_, rng_);
        BigInt s = BigInt::random_below(q_, rng_);
        BigInt A = BigInt::powmod(g_, a, p_);
        BigInt S = BigInt::powmod(g_, s, p_);

        std::string serial = random_serial();

        const BigInt& n = keys.public_modulus(denomination);
        const BigInt& e = keys.public_exponent(denomination);

        BigInt m_mod_n = HashUtils::coin_message(serial, A, S, n);

        BigInt r;
        for (;;) {
            r = BigInt::random_below(n, rng_);
            if (BigInt::gcd(r, n) == BigInt(1)) break;
        }

        BigInt r_e = BigInt::powmod(r, e, n);
        BigInt blinded_m = BigInt::mulmod(m_mod_n, r_e, n);

        BigInt tag = HashUtils::hash_tag(a, s);

        out_pending = PendingWithdrawal{denomination, serial, A, S, m_mod_n, r, blinded_m, a, s, tag};
        return blinded_m;
    }

    Coin unblind(const PublicKeySource& keys, const PendingWithdrawal& pending, const BigInt& blind_signature) const {
        const BigInt& n = keys.public_modulus(pending.denomination);
        BigInt r_inv = BigInt::invmod(pending.r, n);
        BigInt signature = BigInt::mulmod(blind_signature, r_inv, n);

        return Coin{pending.serial, pending.A, pending.S, signature, pending.denomination};
    }

    WalletCoin finish_withdrawal(const PublicKeySource& keys, const PendingWithdrawal& pending, const BigInt& blind_signature) const {
        return WalletCoin{unblind(keys, pending, blind_signature), pending.a, pending.s, false};
    }

    bool pay(WalletCoin& wc, const std::string& receiver_id, const std::string& time,
             const std::string& nonce, BigInt& y_out) const {
        if (wc.spent) return false;
        BigInt x = HashUtils::hash_challenge(receiver_id, time, nonce, q_);
        y_out = Schnorr::respond(wc.a, wc.s, x, q_);
        wc.spent = true;
        return true;
    }

private:
    BigInt p_, q_, g_;
    gmp_randstate_t& rng_;

    std::string random_serial() {
        mpz_t tmp;
        mpz_init(tmp);
        mpz_urandomb(tmp, rng_, 128);
        BigInt r; mpz_set(r.v, tmp);
        mpz_clear(tmp);
        return r.to_string(16);
    }
};
