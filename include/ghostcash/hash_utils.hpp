#pragma once

#include "ghostcash/bigint.hpp"
#include <openssl/sha.h>
#include <string>

class HashUtils {
public:
    static BigInt hash_coin_identifier(const std::string& serial,
                                        const BigInt& A,
                                        const BigInt& S) {
        std::string msg = serial + "|" + A.to_string() + "|" + S.to_string();
        return sha256_int(msg);
    }

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

    static BigInt hash_tag(const BigInt& a, const BigInt& s) {
        return sha256_int("ghostcash-tag|" + field(a.to_string(16)) + field(s.to_string(16)));
    }

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
