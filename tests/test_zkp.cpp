// test_zkp.cpp
//
// Unit tests for the Schnorr-style proof (zkp.hpp) and the challenge hash:
// completeness (an honest response verifies), the verifier's input checks
// (bad y, wrong challenge, x = 0, A or S outside the subgroup), extraction
// of (a, s) from two transcripts, and a simulator showing a single transcript
// carries no information about a or s (honest-verifier zero knowledge).
//
// Uses a small group for test speed; nothing under test depends on the size.

#include "third_party/catch.hpp"
#include "ghostcash/rng.hpp"
#include "ghostcash/group_setup.hpp"
#include "ghostcash/hash_utils.hpp"
#include "ghostcash/zkp.hpp"

namespace {

struct ZkpFixture {
    GroupParams grp;
    BigInt a, s, A, S;

    ZkpFixture() : grp(GroupSetup::generate(/*q_bits=*/64, /*p_bits=*/256, Rng::instance())) {
        a = BigInt::random_below(grp.q, Rng::instance());
        s = BigInt::random_below(grp.q, Rng::instance());
        A = BigInt::powmod(grp.g, a, grp.p);
        S = BigInt::powmod(grp.g, s, grp.p);
    }

    BigInt challenge() { return BigInt::random_below(grp.q, Rng::instance()); }
};

} // namespace

TEST_CASE("Schnorr: an honest response verifies", "[zkp]") {
    ZkpFixture f;
    for (int i = 0; i < 10; ++i) {
        BigInt x = f.challenge();
        BigInt y = Schnorr::respond(f.a, f.s, x, f.grp.q);
        REQUIRE(Schnorr::verify(f.grp, f.A, f.S, x, y));
    }
}

TEST_CASE("Schnorr: a wrong response is rejected", "[zkp][attack]") {
    ZkpFixture f;
    BigInt x = f.challenge();
    BigInt y = Schnorr::respond(f.a, f.s, x, f.grp.q);
    BigInt bad = BigInt::mod(BigInt::add(y, BigInt(1)), f.grp.q);
    REQUIRE_FALSE(Schnorr::verify(f.grp, f.A, f.S, x, bad));
}

TEST_CASE("Schnorr: a response computed for a different challenge is rejected", "[zkp][attack]") {
    ZkpFixture f;
    BigInt x1 = f.challenge();
    BigInt x2 = BigInt::add(x1, BigInt(1));
    BigInt y_for_x1 = Schnorr::respond(f.a, f.s, x1, f.grp.q);
    REQUIRE_FALSE(Schnorr::verify(f.grp, f.A, f.S, x2, y_for_x1));
}

TEST_CASE("Schnorr: a prover who doesn't know a, s cannot answer", "[zkp][attack]") {
    ZkpFixture f;
    BigInt wrong_a = BigInt::random_below(f.grp.q, Rng::instance());
    BigInt x = f.challenge();
    BigInt y = Schnorr::respond(wrong_a, f.s, x, f.grp.q);
    REQUIRE_FALSE(Schnorr::verify(f.grp, f.A, f.S, x, y));
}

TEST_CASE("Schnorr: challenge x = 0 and x >= q are rejected", "[zkp][attack]") {
    ZkpFixture f;
    // x = 0 would make y = s, leaking s in a single spend.
    BigInt y0 = Schnorr::respond(f.a, f.s, BigInt(0), f.grp.q);
    REQUIRE_FALSE(Schnorr::verify(f.grp, f.A, f.S, BigInt(0), y0));

    BigInt xq = f.grp.q; // equals 0 mod q, but out of range as given
    BigInt yq = Schnorr::respond(f.a, f.s, xq, f.grp.q);
    REQUIRE_FALSE(Schnorr::verify(f.grp, f.A, f.S, xq, yq));
}

TEST_CASE("Schnorr: y outside [0, q) is rejected", "[zkp][attack]") {
    ZkpFixture f;
    BigInt x = f.challenge();
    BigInt y = Schnorr::respond(f.a, f.s, x, f.grp.q);
    // y + q is congruent to y mod q and would satisfy the equation, but is
    // not a canonical response.
    REQUIRE_FALSE(Schnorr::verify(f.grp, f.A, f.S, x, BigInt::add(y, f.grp.q)));
}

TEST_CASE("Schnorr: A or S outside the order-q subgroup is rejected", "[zkp][attack]") {
    ZkpFixture f;
    BigInt x = f.challenge();
    BigInt y = Schnorr::respond(f.a, f.s, x, f.grp.q);

    BigInt p_minus_1 = BigInt::sub(f.grp.p, BigInt(1)); // order 2, not in the subgroup
    REQUIRE_FALSE(Schnorr::is_group_element(f.grp, BigInt(0)));
    REQUIRE_FALSE(Schnorr::is_group_element(f.grp, BigInt(1)));
    REQUIRE_FALSE(Schnorr::is_group_element(f.grp, p_minus_1));
    REQUIRE_FALSE(Schnorr::is_group_element(f.grp, f.grp.p));
    REQUIRE(Schnorr::is_group_element(f.grp, f.A));

    REQUIRE_FALSE(Schnorr::verify(f.grp, p_minus_1, f.S, x, y));
    REQUIRE_FALSE(Schnorr::verify(f.grp, f.A, BigInt(1), x, y));
}

TEST_CASE("Schnorr: two transcripts with different challenges reveal a and s", "[zkp]") {
    ZkpFixture f;
    BigInt x1 = f.challenge();
    BigInt x2 = f.challenge();
    while (x1 == x2) x2 = f.challenge();

    BigInt y1 = Schnorr::respond(f.a, f.s, x1, f.grp.q);
    BigInt y2 = Schnorr::respond(f.a, f.s, x2, f.grp.q);

    BigInt a_out, s_out;
    REQUIRE(Schnorr::extract(f.grp, x1, y1, x2, y2, a_out, s_out));
    REQUIRE(a_out == f.a);
    REQUIRE(s_out == f.s);
}

TEST_CASE("Schnorr: two transcripts with the same challenge reveal nothing", "[zkp]") {
    ZkpFixture f;
    BigInt x = f.challenge();
    BigInt y = Schnorr::respond(f.a, f.s, x, f.grp.q);

    BigInt a_out, s_out;
    REQUIRE_FALSE(Schnorr::extract(f.grp, x, y, x, y, a_out, s_out));
}

TEST_CASE("Schnorr: a transcript can be simulated without a or s (honest-verifier zero knowledge)", "[zkp]") {
    // Pick x and y first, then solve for the commitment: S = g^y * A^-x.
    // The resulting (S, x, y) passes verification although the simulator
    // never knew s (or a) -- so a transcript, on its own, proves nothing a
    // verifier couldn't have produced by itself.
    ZkpFixture f;
    BigInt x = f.challenge();
    BigInt y = BigInt::random_below(f.grp.q, Rng::instance());

    BigInt A_inv = BigInt::invmod(f.A, f.grp.p);
    BigInt S_sim = BigInt::mulmod(BigInt::powmod(f.grp.g, y, f.grp.p),
                                  BigInt::powmod(A_inv, x, f.grp.p), f.grp.p);

    REQUIRE(Schnorr::verify(f.grp, f.A, S_sim, x, y));
}

TEST_CASE("HashUtils: challenge is deterministic, in [1, q-1], and bound to every field", "[zkp][hash_utils]") {
    ZkpFixture f;
    BigInt x = HashUtils::hash_challenge("bob", "t1", "n1", f.grp.q);

    REQUIRE(x == HashUtils::hash_challenge("bob", "t1", "n1", f.grp.q));
    REQUIRE(Schnorr::is_valid_challenge(f.grp, x));

    REQUIRE(x != HashUtils::hash_challenge("carol", "t1", "n1", f.grp.q));
    REQUIRE(x != HashUtils::hash_challenge("bob", "t2", "n1", f.grp.q));
    REQUIRE(x != HashUtils::hash_challenge("bob", "t1", "n2", f.grp.q));
}

TEST_CASE("HashUtils: challenge fields cannot be re-split", "[zkp][hash_utils]") {
    ZkpFixture f;
    // Same concatenation "ab" + "c" vs "a" + "bc": length-prefixing must
    // keep them apart.
    REQUIRE(HashUtils::hash_challenge("ab", "c", "n", f.grp.q) !=
            HashUtils::hash_challenge("a", "bc", "n", f.grp.q));
}

TEST_CASE("HashUtils: tag depends on both secrets", "[zkp][hash_utils]") {
    BigInt a(11), s(22);
    REQUIRE(HashUtils::hash_tag(a, s) == HashUtils::hash_tag(a, s));
    REQUIRE(HashUtils::hash_tag(a, s) != HashUtils::hash_tag(BigInt(12), s));
    REQUIRE(HashUtils::hash_tag(a, s) != HashUtils::hash_tag(a, BigInt(23)));
    REQUIRE(HashUtils::hash_tag(a, s) != HashUtils::hash_tag(s, a));
}
