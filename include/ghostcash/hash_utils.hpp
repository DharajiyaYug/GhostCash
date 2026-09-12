// hash_utils.hpp
//
// Coin identifier construction: m = H(serial || A || S), via SHA-256,
// mapped into an integer suitable for RSA blind signing. Per project design
// decision, hashing serial and the discrete-log commitments A, S together
// means the bank's signature binds to the coin's commitments, not just an
// arbitrary serial number.

#pragma once

#include "ghostcash/bigint.hpp"
#include <openssl/sha.h>
#include <string>

class HashUtils {
public:
    // Concatenates serial, A, S (as decimal numeral strings, "|"-separated
    // to avoid ambiguous concatenation) and returns SHA-256(...) as a BigInt.
    static BigInt hash_coin_identifier(const std::string& serial,
                                        const BigInt& A,
                                        const BigInt& S) {
        std::string msg = serial + "|" + A.to_string() + "|" + S.to_string();

        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), digest);

        return BigInt::from_bytes(digest, SHA256_DIGEST_LENGTH);
    }
};
