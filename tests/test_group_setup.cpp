// test_group_setup.cpp
//
// Unit tests for one-time DSA-style group setup (p, q, g). Uses smaller bit
// lengths than production (256/3072) so the test suite runs quickly --
// correctness of the construction doesn't depend on the specific sizes.

#include "third_party/catch.hpp"
#include "ghostcash/group_setup.hpp"
#include "ghostcash/rng.hpp"

TEST_CASE("GroupSetup: p and q have the requested bit lengths", "[group_setup]") {
    gmp_randstate_t& rng = Rng::instance();
    GroupParams group = GroupSetup::generate(/*q_bits=*/64, /*p_bits=*/256, rng);

    REQUIRE(group.q.bit_length() == 64);
    REQUIRE(group.p.bit_length() == 256);
}

TEST_CASE("GroupSetup: p and q are both prime", "[group_setup]") {
    gmp_randstate_t& rng = Rng::instance();
    GroupParams group = GroupSetup::generate(/*q_bits=*/64, /*p_bits=*/256, rng);

    REQUIRE(mpz_probab_prime_p(group.p.v, 40) > 0);
    REQUIRE(mpz_probab_prime_p(group.q.v, 40) > 0);
}

TEST_CASE("GroupSetup: q divides p - 1", "[group_setup]") {
    gmp_randstate_t& rng = Rng::instance();
    GroupParams group = GroupSetup::generate(/*q_bits=*/64, /*p_bits=*/256, rng);

    mpz_t p_minus_1, remainder;
    mpz_inits(p_minus_1, remainder, nullptr);
    mpz_sub_ui(p_minus_1, group.p.v, 1);
    mpz_mod(remainder, p_minus_1, group.q.v);

    REQUIRE(mpz_sgn(remainder) == 0);

    mpz_clears(p_minus_1, remainder, nullptr);
}

TEST_CASE("GroupSetup: g has order exactly q (g^q == 1, g != 1)", "[group_setup]") {
    gmp_randstate_t& rng = Rng::instance();
    GroupParams group = GroupSetup::generate(/*q_bits=*/64, /*p_bits=*/256, rng);

    REQUIRE(group.g != BigInt(1));

    BigInt g_to_q = BigInt::powmod(group.g, group.q, group.p);
    REQUIRE(g_to_q == BigInt(1));
}

TEST_CASE("GroupSetup: rejects p_bits <= q_bits", "[group_setup]") {
    gmp_randstate_t& rng = Rng::instance();
    REQUIRE_THROWS_AS(GroupSetup::generate(256, 256, rng), std::invalid_argument);
    REQUIRE_THROWS_AS(GroupSetup::generate(256, 128, rng), std::invalid_argument);
}
