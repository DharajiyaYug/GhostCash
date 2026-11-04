#pragma once

#include "ghostcash/public_keys.hpp"
#include "ghostcash/bigint.hpp"
#include "ghostcash/coin.hpp"
#include "ghostcash/group_setup.hpp"
#include "ghostcash/hash_utils.hpp"
#include "ghostcash/transcript.hpp"
#include "ghostcash/zkp.hpp"
#include <gmp.h>
#include <string>

struct PaymentSession {
    Coin coin;
    std::string time;
    std::string nonce;
    BigInt x;
};

class Merchant {
public:
    Merchant(std::string receiver_id, GroupParams group, const PublicKeySource& keys, Rng& rng)
        : id_(std::move(receiver_id)), group_(std::move(group)), keys_(keys), rng_(rng) {}

    const std::string& id() const { return id_; }

    bool begin_payment(const Coin& coin, const std::string& time, PaymentSession& out) {
        if (!keys_.has_denomination(coin.denomination)) return false;

        BigInt m = HashUtils::coin_message(coin.serial, coin.A, coin.S, keys_.public_modulus(coin.denomination));
        if (!keys_.verify(coin.denomination, m, coin.signature)) return false;

        if (!Schnorr::is_group_element(group_, coin.A)) return false;
        if (!Schnorr::is_group_element(group_, coin.S)) return false;

        std::string nonce = random_nonce();
        BigInt x = HashUtils::hash_challenge(id_, time, nonce, group_.q);
        out = PaymentSession{coin, time, nonce, x};
        return true;
    }

    bool finish_payment(const PaymentSession& session, const BigInt& y, Transcript& out) const {
        const Coin& c = session.coin;
        if (!Schnorr::verify(group_, c.A, c.S, session.x, y)) return false;
        out = Transcript{c, id_, session.time, session.nonce, y};
        return true;
    }

private:
    std::string id_;
    GroupParams group_;
    const PublicKeySource& keys_;
    Rng& rng_;

    std::string random_nonce() {
        return BigInt::random_bits(128, rng_).to_string(16);
    }
};
