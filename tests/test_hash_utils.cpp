// test_hash_utils.cpp
//
// Unit tests for coin identifier hashing: m = H(serial || A || S). These
// tests matter because the whole point of hashing serial and the
// commitments together is that changing ANY of the three must change the
// identifier -- otherwise the bank's signature wouldn't actually be bound
// to the coin's commitments.

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
