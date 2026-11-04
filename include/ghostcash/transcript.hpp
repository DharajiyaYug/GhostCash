#pragma once

#include "ghostcash/bigint.hpp"
#include "ghostcash/coin.hpp"
#include "ghostcash/hash_utils.hpp"
#include <string>

struct Transcript {
    Coin coin;
    std::string receiver_id;
    std::string time;
    std::string nonce;
    BigInt y;

    BigInt challenge(const BigInt& q) const {
        return HashUtils::hash_challenge(receiver_id, time, nonce, q);
    }
};
