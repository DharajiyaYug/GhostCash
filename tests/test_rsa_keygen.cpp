// test_rsa_keygen.cpp
//
// Unit tests for RSA keypair generation: the foundation the blind signature
// scheme sits on top of. Uses a smaller modulus than production (2048) for
// test speed; the construction being tested doesn't depend on the size.

#include "third_party/catch.hpp"
#include "ghostcash/rsa_keygen.hpp"
#include "ghostcash/rng.hpp"

TEST_CASE("RSAKeyGen: modulus has the requested bit length", "[rsa_keygen]") {
    gmp_randstate_t& rng = Rng::instance();
    RSAKeyPair kp = RSAKeyGen::generate(/*n_bits=*/512, rng);

    REQUIRE(kp.n.bit_length() == 512);
}

TEST_CASE("RSAKeyGen: public exponent is fixed at 65537", "[rsa_keygen]") {
    gmp_randstate_t& rng = Rng::instance();
    RSAKeyPair kp = RSAKeyGen::generate(/*n_bits=*/512, rng);

    REQUIRE(kp.e == BigInt(65537));
}

TEST_CASE("RSAKeyGen: d is a genuine RSA private exponent (encrypt/decrypt round-trip)", "[rsa_keygen]") {
    gmp_randstate_t& rng = Rng::instance();
    RSAKeyPair kp = RSAKeyGen::generate(/*n_bits=*/512, rng);

    BigInt message(424242);
    BigInt ciphertext = BigInt::powmod(message, kp.e, kp.n);
    BigInt recovered = BigInt::powmod(ciphertext, kp.d, kp.n);

    REQUIRE(recovered == message);
}

TEST_CASE("RSAKeyGen: repeated generation produces different keys", "[rsa_keygen]") {
    gmp_randstate_t& rng = Rng::instance();
    RSAKeyPair kp1 = RSAKeyGen::generate(/*n_bits=*/512, rng);
    RSAKeyPair kp2 = RSAKeyGen::generate(/*n_bits=*/512, rng);

    REQUIRE(kp1.n != kp2.n);
}
