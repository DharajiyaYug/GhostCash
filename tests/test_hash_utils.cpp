#include "third_party/catch.hpp"
#include "ghostcash/hash_utils.hpp"

TEST_CASE("HashUtils: identical inputs produce identical hashes", "[hash_utils]") {
    BigInt A(111), S(222);
    BigInt h1 = HashUtils::hash_coin_identifier("serial1", A, S);
    BigInt h2 = HashUtils::hash_coin_identifier("serial1", A, S);
    REQUIRE(h1 == h2);
}

TEST_CASE("HashUtils: changing the serial changes the hash", "[hash_utils]") {
    BigInt A(111), S(222);
    BigInt h1 = HashUtils::hash_coin_identifier("serial1", A, S);
    BigInt h2 = HashUtils::hash_coin_identifier("serial2", A, S);
    REQUIRE(h1 != h2);
}

TEST_CASE("HashUtils: changing A changes the hash", "[hash_utils]") {
    BigInt S(222);
    BigInt h1 = HashUtils::hash_coin_identifier("serial1", BigInt(111), S);
    BigInt h2 = HashUtils::hash_coin_identifier("serial1", BigInt(999), S);
    REQUIRE(h1 != h2);
}

TEST_CASE("HashUtils: changing S changes the hash", "[hash_utils]") {
    BigInt A(111);
    BigInt h1 = HashUtils::hash_coin_identifier("serial1", A, BigInt(222));
    BigInt h2 = HashUtils::hash_coin_identifier("serial1", A, BigInt(888));
    REQUIRE(h1 != h2);
}

TEST_CASE("HashUtils: output fits in a 256-bit SHA-256 digest", "[hash_utils]") {
    BigInt A(111), S(222);
    BigInt h = HashUtils::hash_coin_identifier("serial1", A, S);
    REQUIRE(h.bit_length() <= 256);
}

TEST_CASE("HashUtils: coin_message is a deterministic full-domain hash into [0, n)", "[hash_utils][fdh]") {
    BigInt n("115792089237316195423570985008687907853269984665640564039457584007913129639747");
    BigInt A(111), S(222);

    BigInt m = HashUtils::coin_message("serial1", A, S, n);
    REQUIRE(m == HashUtils::coin_message("serial1", A, S, n));
    REQUIRE(mpz_sgn(m.v) >= 0);
    REQUIRE(mpz_cmp(m.v, n.v) < 0);
}

TEST_CASE("HashUtils: coin_message fills the whole domain, not just 256 bits", "[hash_utils][fdh]") {
    BigInt n = BigInt::sub(BigInt("1" + std::string(616, '0')), BigInt(1));
    size_t max_bits = 0;
    for (int i = 0; i < 20; ++i) {
        BigInt m = HashUtils::coin_message("serial" + std::to_string(i), BigInt(5), BigInt(6), n);
        max_bits = std::max(max_bits, m.bit_length());
    }
    REQUIRE(max_bits > 2000);
}

TEST_CASE("HashUtils: coin_message depends on every field and on the modulus", "[hash_utils][fdh]") {
    BigInt n("115792089237316195423570985008687907853269984665640564039457584007913129639747");
    BigInt n2("115792089237316195423570985008687907853269984665640564039457584007913129639937");
    BigInt A(111), S(222);
    BigInt base = HashUtils::coin_message("serial1", A, S, n);

    REQUIRE(base != HashUtils::coin_message("serial2", A, S, n));
    REQUIRE(base != HashUtils::coin_message("serial1", BigInt(999), S, n));
    REQUIRE(base != HashUtils::coin_message("serial1", A, BigInt(888), n));
    REQUIRE(base != HashUtils::coin_message("serial1", A, S, n2));
}
