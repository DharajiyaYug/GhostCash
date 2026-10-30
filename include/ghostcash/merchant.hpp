// merchant.hpp
//
// Receiver side of an offline payment. The receiver never contacts the bank
// during a payment; it checks everything it can locally:
//
//   begin_payment:  the coin carries a valid bank signature under the
//                   denomination it claims, and A, S are proper elements of
//                   the order-q subgroup. If so, it issues the challenge
//                   x = H(receiver_id, time, nonce).
//   finish_payment: the wallet's response y satisfies g^y == S * A^x. If so,
//                   it returns the transcript to redeem later.
//
// The signature check uses the bank's public keys (n, e per denomination).
// Here that is done through a const Bank&, but only the public-key accessors
// and verify() are used, which is all a networked receiver would have.

#pragma once

#include "ghostcash/bank.hpp"
#include "ghostcash/bigint.hpp"
#include "ghostcash/coin.hpp"
#include "ghostcash/group_setup.hpp"
#include "ghostcash/hash_utils.hpp"
#include "ghostcash/transcript.hpp"
#include "ghostcash/zkp.hpp"
#include <gmp.h>
#include <string>

// State between issuing a challenge and receiving the response.
struct PaymentSession {
    Coin coin;
    std::string time;
    std::string nonce;
    BigInt x; // the challenge for (receiver_id, time, nonce)
};

class Merchant {
public:
    Merchant(std::string receiver_id, GroupParams group, const Bank& bank, gmp_randstate_t& rng)
        : id_(std::move(receiver_id)), group_(std::move(group)), bank_(bank), rng_(rng) {}

    const std::string& id() const { return id_; }

    // Checks the coin and, if acceptable, opens a payment session with a
    // fresh nonce. `time` is supplied by the caller (wall clock in the real
    // system, a fixed string in tests). Returns false for a coin that should
    // not be accepted.
    bool begin_payment(const Coin& coin, const std::string& time, PaymentSession& out) {
        if (!bank_.has_denomination(coin.denomination)) return false;

        BigInt m = HashUtils::hash_coin_identifier(coin.serial, coin.A, coin.S);
        if (!bank_.verify(coin.denomination, m, coin.signature)) return false;

        if (!Schnorr::is_group_element(group_, coin.A)) return false;
        if (!Schnorr::is_group_element(group_, coin.S)) return false;

        std::string nonce = random_nonce();
        BigInt x = HashUtils::hash_challenge(id_, time, nonce, group_.q);
        out = PaymentSession{coin, time, nonce, x};
        return true;
    }

    // Verifies the wallet's response and, if it is correct, builds the
    // transcript to redeem later.
    bool finish_payment(const PaymentSession& session, const BigInt& y, Transcript& out) const {
        const Coin& c = session.coin;
        if (!Schnorr::verify(group_, c.A, c.S, session.x, y)) return false;
        out = Transcript{c, id_, session.time, session.nonce, y};
        return true;
    }

private:
    std::string id_;
    GroupParams group_;
    const Bank& bank_;
    gmp_randstate_t& rng_;

    // 128-bit random nonce as hex.
    std::string random_nonce() {
        BigInt n;
        mpz_urandomb(n.v, rng_, 128);
        return n.to_string(16);
    }
};
