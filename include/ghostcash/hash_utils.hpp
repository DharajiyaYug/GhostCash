// hash_utils.hpp
//
// Coin identifier construction. The bank signs
//
//     m = FDH_n(serial || A || S)
//
// a full-domain hash into Z_n for the denomination's RSA modulus n (SHA-256
// run in counter mode until it covers n plus 128 spare bits, then reduced
// mod n). Signing a hash that fills the whole domain, rather than a 256-bit
// digest of a 2048-bit modulus, is what Chaum-style RSA blind signatures need
// to avoid forgeries built by combining signed values. Hashing serial and the
// discrete-log commitments A, S together binds the signature to the coin's
// commitments, not just an arbitrary serial number.
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
    // This is only the 256-bit digest of the coin fields. The value that is
    // actually signed is coin_message() below.
    static BigInt hash_coin_identifier(const std::string& serial,
                                        const BigInt& A,
                                        const BigInt& S) {
        std::string msg = serial + "|" + A.to_string() + "|" + S.to_string();
        return sha256_int(msg);
    }

    // The message the bank signs: FDH of the coin fields into [0, n).
    static BigInt coin_message(const std::string& serial,
                               const BigInt& A,
                               const BigInt& S,
                               const BigInt& n) {
        std::string base = serial + "|" + A.to_string() + "|" + S.to_string();
        size_t need = (n.bit_length() + 128 + 7) / 8;
        std::string stream;
        for (unsigned i = 0; stream.size() < need; ++i) {
            stream += sha256_bytes("ghostcash-fdh|" + std::to_string(i) + "|" + base);
        }
        stream.resize(need);
        BigInt wide = BigInt::from_bytes(reinterpret_cast<const unsigned char*>(stream.data()), stream.size());
        return BigInt::mod(wide, n);
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

    static std::string sha256_bytes(const std::string& msg) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), digest);
        return std::string(reinterpret_cast<const char*>(digest), SHA256_DIGEST_LENGTH);
    }

    static BigInt sha256_int(const std::string& msg) {
        std::string d = sha256_bytes(msg);
        return BigInt::from_bytes(reinterpret_cast<const unsigned char*>(d.data()), d.size());
    }
};
