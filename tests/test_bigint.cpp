// test_bigint.cpp
//
// Unit tests for the BigInt / GMP wrapper: the arithmetic primitives every
// other module (RSA, group ops, blinding) relies on. If something is wrong
// here, it will manifest confusingly everywhere else -- so it gets tested
// in isolation first.

#include "third_party/catch.hpp"
#include "ghostcash/bigint.hpp"
#include "ghostcash/rng.hpp"

TEST_CASE("BigInt: construction and string round-trip", "[bigint]") {
    BigInt a("123456789012345678901234567890");
    REQUIRE(a.to_string() == "123456789012345678901234567890");
}

TEST_CASE("BigInt: invalid numeral string throws", "[bigint]") {
    REQUIRE_THROWS_AS(BigInt("not_a_number"), std::invalid_argument);
}

TEST_CASE("BigInt: addition and subtraction", "[bigint]") {
    BigInt a(10), b(3);
    REQUIRE(BigInt::add(a, b) == BigInt(13));
    REQUIRE(BigInt::sub(a, b) == BigInt(7));
}

TEST_CASE("BigInt: mulmod reduces correctly", "[bigint]") {
    // 7 * 8 = 56, 56 mod 10 = 6
    BigInt r = BigInt::mulmod(BigInt(7), BigInt(8), BigInt(10));
    REQUIRE(r == BigInt(6));
}

TEST_CASE("BigInt: powmod matches known value", "[bigint]") {
    // 3^4 = 81, 81 mod 7 = 4
    BigInt r = BigInt::powmod(BigInt(3), BigInt(4), BigInt(7));
    REQUIRE(r == BigInt(4));
}

TEST_CASE("BigInt: invmod produces a true multiplicative inverse", "[bigint]") {
    BigInt n(2048583); // arbitrary composite-ish modulus for the test
    BigInt a(97);
    BigInt inv = BigInt::invmod(a, n);
    BigInt product = BigInt::mulmod(a, inv, n);
    REQUIRE(product == BigInt(1));
}

TEST_CASE("BigInt: invmod throws when no inverse exists", "[bigint]") {
    // gcd(4, 8) = 4 != 1, so 4 has no inverse mod 8
    REQUIRE_THROWS_AS(BigInt::invmod(BigInt(4), BigInt(8)), std::runtime_error);
}

TEST_CASE("BigInt: gcd basic cases", "[bigint]") {
    REQUIRE(BigInt::gcd(BigInt(12), BigInt(18)) == BigInt(6));
    REQUIRE(BigInt::gcd(BigInt(17), BigInt(5)) == BigInt(1));
}

TEST_CASE("BigInt: random_below stays in range and is non-zero", "[bigint]") {
    gmp_randstate_t& rng = Rng::instance();
    BigInt n(1000);
    for (int i = 0; i < 100; ++i) {
        BigInt r = BigInt::random_below(n, rng);
        REQUIRE(mpz_sgn(r.v) > 0);
        REQUIRE(mpz_cmp(r.v, n.v) < 0);
    }
}

TEST_CASE("BigInt: from_bytes matches manual big-endian interpretation", "[bigint]") {
    unsigned char bytes[] = {0x01, 0x00}; // big-endian -> 256
    BigInt r = BigInt::from_bytes(bytes, 2);
    REQUIRE(r == BigInt(256));
}

TEST_CASE("BigInt: bit_length matches expectations", "[bigint]") {
    REQUIRE(BigInt(1).bit_length() == 1);
    REQUIRE(BigInt(255).bit_length() == 8);
    REQUIRE(BigInt(256).bit_length() == 9);
}
