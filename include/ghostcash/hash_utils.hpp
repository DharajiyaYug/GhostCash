// hash_utils.hpp
//
// Coin identifier construction: m = H(serial || A || S), via SHA-256,
// mapped into an integer suitable for RSA blind signing. Per project design
// decision, hashing serial and the discrete-log commitments A, S together
// means the bank's signature binds to the coin's commitments, not just an
// arbitrary serial number.
//
// Also holds the two other hashes the protocol needs:
//   - the withdrawal tag   T = H(a || s), which the bank logs against the
//     withdrawing account so a double spend (which reveals a and s) can be
//     traced back to that account;
//   - the payment challenge x = H(receiver_id, time, nonce) in [1, q-1],
//     which binds a challenge to one receiver.

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
        return sha256_int(msg);
    }

    // Withdrawal tag T = H(a || s). a and s never appear in the coin (only
    // g^a and g^s do), so the tag can't be linked to a coin until a double
    // spend reveals a and s.
    static BigInt hash_tag(const BigInt& a, const BigInt& s) {
        return sha256_int("ghostcash-tag|" + field(a.to_string(16)) + field(s.to_string(16)));
    }

    // Payment challenge x = H(receiver_id, time, nonce), mapped into
    // [1, q-1] (never 0: x = 0 would make the response y equal s and leak it).
    // Fields are length-prefixed so no choice of receiver_id/time/nonce can
    // be re-split into a different triple that hashes the same.
    static BigInt hash_challenge(const std::string& receiver_id,
                                 const std::string& time,
                                 const std::string& nonce,
                                 const BigInt& q) {
        BigInt h = sha256_int("ghostcash-challenge|" + field(receiver_id) + field(time) + field(nonce));
        BigInt q_minus_1 = BigInt::sub(q, BigInt(1));
        return BigInt::add(BigInt::mod(h, q_minus_1), BigInt(1));
    }

private:
    static std::string field(const std::string& s) {
        return std::to_string(s.size()) + ":" + s + "|";
    }

    static BigInt sha256_int(const std::string& msg) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), digest);
        return BigInt::from_bytes(digest, SHA256_DIGEST_LENGTH);
    }
};
