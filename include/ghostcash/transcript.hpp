// transcript.hpp
//
// What a receiver holds after a successful payment, and what it sends to the
// bank to redeem it. The challenge x is not stored: it is recomputed from
// (receiver_id, time, nonce), so the bank checks the proof against the
// challenge for the receiver it is crediting, and a copied transcript can
// only ever credit the receiver it names.

#pragma once

#include "ghostcash/bigint.hpp"
#include "ghostcash/coin.hpp"
#include "ghostcash/hash_utils.hpp"
#include <string>

struct Transcript {
    Coin coin;
    std::string receiver_id; // account the bank will credit
    std::string time;
    std::string nonce;
    BigInt y;                // wallet's response s + a*x mod q

    BigInt challenge(const BigInt& q) const {
        return HashUtils::hash_challenge(receiver_id, time, nonce, q);
    }
};
