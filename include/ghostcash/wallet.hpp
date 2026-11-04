#pragma once

#include "ghostcash/bigint.hpp"
#include "ghostcash/coin.hpp"
#include "ghostcash/cut_choose.hpp"
#include "ghostcash/public_keys.hpp"
#include "ghostcash/hash_utils.hpp"
#include "ghostcash/rng.hpp"
#include "ghostcash/zkp.hpp"
#include <gmp.h>
#include <stdexcept>
#include <vector>

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

struct WithdrawalBatch {
    int denomination = 0;
    std::vector<PendingWithdrawal> candidates;
};

struct WalletCoin {
    Coin coin;
    BigInt a, s;
    bool spent = false;
};

class Wallet {
public:
    Wallet(BigInt group_p, BigInt group_q, BigInt group_g, Rng& rng)
        : p_(std::move(group_p)), q_(std::move(group_q)), g_(std::move(group_g)), rng_(rng) {}

    BigInt prepare_withdrawal(int denomination, const PublicKeySource& keys, PendingWithdrawal& out_pending) {
        BigInt a = BigInt::random_below(q_, rng_);
        BigInt s = BigInt::random_below(q_, rng_);
        BigInt A = BigInt::powmod(g_, a, p_);
        BigInt S = BigInt::powmod(g_, s, p_);

        std::string serial = BigInt::random_bits(128, rng_).to_string(16);

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

    std::vector<WithdrawCandidate> prepare_batch(int denomination, const PublicKeySource& keys, int k,
                                                 WithdrawalBatch& out_batch) {
        if (k < 1) throw std::invalid_argument("Wallet: need at least one withdrawal candidate");
        out_batch = WithdrawalBatch{denomination, {}};
        std::vector<WithdrawCandidate> sent;
        for (int i = 0; i < k; ++i) {
            PendingWithdrawal p;
            prepare_withdrawal(denomination, keys, p);
            sent.push_back(WithdrawCandidate{p.blinded_m, p.tag});
            out_batch.candidates.push_back(std::move(p));
        }
        return sent;
    }

    static std::vector<CandidateOpening> open_batch(const WithdrawalBatch& batch, size_t keep_index) {
        if (keep_index >= batch.candidates.size()) {
            throw std::invalid_argument("Wallet: the bank chose a candidate index out of range");
        }
        std::vector<CandidateOpening> openings;
        for (size_t i = 0; i < batch.candidates.size(); ++i) {
            if (i == keep_index) continue;
            const PendingWithdrawal& p = batch.candidates[i];
            openings.push_back(CandidateOpening{i, p.serial, p.a, p.s, p.r});
        }
        return openings;
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
    Rng& rng_;
};
