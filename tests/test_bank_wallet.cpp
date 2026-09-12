// test_bank_wallet.cpp
//
// Unit tests for the full blind-signature issuance protocol: Bank + Wallet
// working together. Covers the honest-path round trip, plus negative tests
// standing in for the "simulate attacks and confirm they're caught" future
// work item -- a tampered coin and a forged/reused signature must both be
// rejected by verification. Also covers denomination handling: each
// denomination has its own independent RSA key, and a coin only verifies
// against the specific denomination it was actually signed under.
//
// Uses smaller RSA/group sizes than production for test speed; the protocol
// logic under test doesn't depend on the specific sizes.

#include "third_party/catch.hpp"
#include "ghostcash/rng.hpp"
#include "ghostcash/group_setup.hpp"
#include "ghostcash/bank.hpp"
#include "ghostcash/wallet.hpp"
#include "ghostcash/hash_utils.hpp"

namespace {

constexpr int kDefaultDenomination = 1;

// Shared fixture-style helper: builds a fresh (group, bank, wallet) triple
// at test-appropriate (small, fast) sizes. Each TEST_CASE gets its own
// independent instances -- Catch2 does not share state between cases.
struct Fixture {
    GroupParams group;
    Bank bank;
    Wallet wallet;

    Fixture()
        : group(GroupSetup::generate(/*q_bits=*/64, /*p_bits=*/256, Rng::instance())),
          wallet(group.p, group.q, group.g, Rng::instance()) {
        bank.add_denomination(kDefaultDenomination, /*rsa_bits=*/512, Rng::instance());
    }
};

} // namespace

TEST_CASE("Bank+Wallet: honest issuance produces a verifiable coin", "[bank_wallet]") {
    Fixture f;

    PendingWithdrawal pending;
    BigInt blinded_m = f.wallet.prepare_withdrawal(kDefaultDenomination, f.bank, pending);
    BigInt blind_sig = f.bank.blind_sign(kDefaultDenomination, blinded_m);
    Coin coin = f.wallet.unblind(f.bank, pending, blind_sig);

    BigInt m_check = HashUtils::hash_coin_identifier(coin.serial, coin.A, coin.S);
    REQUIRE(f.bank.verify(coin.denomination, m_check, coin.signature));
}

TEST_CASE("Bank+Wallet: bank never sees the unblinded identifier", "[bank_wallet]") {
    Fixture f;

    PendingWithdrawal pending;
    BigInt blinded_m = f.wallet.prepare_withdrawal(kDefaultDenomination, f.bank, pending);

    REQUIRE(blinded_m != pending.m);
}

TEST_CASE("Bank+Wallet: two withdrawals from the same wallet are unlinkable blinding-wise", "[bank_wallet]") {
    Fixture f;

    PendingWithdrawal p1, p2;
    BigInt b1 = f.wallet.prepare_withdrawal(kDefaultDenomination, f.bank, p1);
    BigInt b2 = f.wallet.prepare_withdrawal(kDefaultDenomination, f.bank, p2);

    // Different random secrets/serials/blinding factors each time -> the
    // blinded messages sent to the bank must differ.
    REQUIRE(b1 != b2);
    REQUIRE(p1.serial != p2.serial);
}

TEST_CASE("Bank+Wallet: same identifier blinded twice looks unrelated on the wire", "[bank_wallet]") {
    // Stronger version of the unlinkability property above: even if the
    // *same* coin identifier m were blinded twice (different random r each
    // time), the two blinded messages sent to the bank must still differ --
    // that's what makes blinding actually hide m rather than just permuting
    // a fixed transform of it.
    Fixture f;

    PendingWithdrawal pending;
    BigInt blinded_first = f.wallet.prepare_withdrawal(kDefaultDenomination, f.bank, pending);

    const BigInt& n = f.bank.public_modulus(kDefaultDenomination);
    const BigInt& e = f.bank.public_exponent(kDefaultDenomination);

    BigInt r2;
    for (;;) {
        r2 = BigInt::random_below(n, Rng::instance());
        if (BigInt::gcd(r2, n) == BigInt(1)) break;
    }
    BigInt blinded_second = BigInt::mulmod(pending.m, BigInt::powmod(r2, e, n), n);

    REQUIRE(blinded_first != blinded_second);
}

TEST_CASE("Denominations: bank supports multiple independent denomination keys", "[bank_wallet][denomination]") {
    Bank bank;
    bank.add_denomination(1, 512, Rng::instance());
    bank.add_denomination(5, 512, Rng::instance());
    bank.add_denomination(10, 512, Rng::instance());

    REQUIRE(bank.has_denomination(1));
    REQUIRE(bank.has_denomination(5));
    REQUIRE(bank.has_denomination(10));
    REQUIRE_FALSE(bank.has_denomination(20));

    // Every denomination's modulus must be genuinely independent.
    REQUIRE(bank.public_modulus(1) != bank.public_modulus(5));
    REQUIRE(bank.public_modulus(5) != bank.public_modulus(10));
    REQUIRE(bank.public_modulus(1) != bank.public_modulus(10));
}

TEST_CASE("Denominations: registering the same denomination twice is rejected", "[bank_wallet][denomination]") {
    Bank bank;
    bank.add_denomination(1, 512, Rng::instance());
    REQUIRE_THROWS_AS(bank.add_denomination(1, 512, Rng::instance()), std::invalid_argument);
}

TEST_CASE("Denominations: a coin only verifies against the denomination it was actually signed under", "[bank_wallet][denomination]") {
    GroupParams group = GroupSetup::generate(/*q_bits=*/64, /*p_bits=*/256, Rng::instance());
    Wallet wallet(group.p, group.q, group.g, Rng::instance());

    Bank bank;
    bank.add_denomination(1, 512, Rng::instance());
    bank.add_denomination(5, 512, Rng::instance());

    // Withdraw a coin explicitly as a "5".
    PendingWithdrawal pending;
    BigInt blinded_m = wallet.prepare_withdrawal(/*denomination=*/5, bank, pending);
    BigInt blind_sig = bank.blind_sign(5, blinded_m);
    Coin coin = wallet.unblind(bank, pending, blind_sig);

    REQUIRE(coin.denomination == 5);

    BigInt m_check = HashUtils::hash_coin_identifier(coin.serial, coin.A, coin.S);

    // Verifies correctly against denomination 5's key...
    REQUIRE(bank.verify(5, m_check, coin.signature));
    // ...but NOT against denomination 1's key, even though it's the same
    // bank and the same coin -- a merchant who mistakenly (or maliciously)
    // checks it as a "1" must reject it.
    REQUIRE_FALSE(bank.verify(1, m_check, coin.signature));
}

TEST_CASE("Attack simulation: tampering with the serial after issuance is caught", "[bank_wallet][attack]") {
    Fixture f;

    PendingWithdrawal pending;
    BigInt blinded_m = f.wallet.prepare_withdrawal(kDefaultDenomination, f.bank, pending);
    BigInt blind_sig = f.bank.blind_sign(kDefaultDenomination, blinded_m);
    Coin coin = f.wallet.unblind(f.bank, pending, blind_sig);

    Coin tampered = coin;
    tampered.serial += "00"; // attacker mutates the serial post-issuance

    BigInt m_tampered = HashUtils::hash_coin_identifier(tampered.serial, tampered.A, tampered.S);
    REQUIRE_FALSE(f.bank.verify(tampered.denomination, m_tampered, tampered.signature));
}

TEST_CASE("Attack simulation: tampering with commitment A after issuance is caught", "[bank_wallet][attack]") {
    Fixture f;

    PendingWithdrawal pending;
    BigInt blinded_m = f.wallet.prepare_withdrawal(kDefaultDenomination, f.bank, pending);
    BigInt blind_sig = f.bank.blind_sign(kDefaultDenomination, blinded_m);
    Coin coin = f.wallet.unblind(f.bank, pending, blind_sig);

    Coin tampered = coin;
    tampered.A = BigInt::add(tampered.A, BigInt(1)); // attacker swaps in a different commitment

    BigInt m_tampered = HashUtils::hash_coin_identifier(tampered.serial, tampered.A, tampered.S);
    REQUIRE_FALSE(f.bank.verify(tampered.denomination, m_tampered, tampered.signature));
}

TEST_CASE("Attack simulation: replaying another coin's signature on a new serial is caught", "[bank_wallet][attack]") {
    Fixture f;

    // Issue one real coin honestly.
    PendingWithdrawal pending;
    BigInt blinded_m = f.wallet.prepare_withdrawal(kDefaultDenomination, f.bank, pending);
    BigInt blind_sig = f.bank.blind_sign(kDefaultDenomination, blinded_m);
    Coin real_coin = f.wallet.unblind(f.bank, pending, blind_sig);

    // Attacker forges a new coin claiming a different serial, but reuses the
    // real coin's signature (attacker cannot produce a fresh valid signature
    // without the bank's private key).
    Coin forged{"attacker-chosen-serial", real_coin.A, real_coin.S, real_coin.signature, real_coin.denomination};

    BigInt m_forged = HashUtils::hash_coin_identifier(forged.serial, forged.A, forged.S);
    REQUIRE_FALSE(f.bank.verify(forged.denomination, m_forged, forged.signature));
}

TEST_CASE("Attack simulation: signature from a different bank is rejected", "[bank_wallet][attack]") {
    Fixture f;
    Bank rogue_bank; // a second, unrelated bank
    rogue_bank.add_denomination(kDefaultDenomination, /*rsa_bits=*/512, Rng::instance());

    PendingWithdrawal pending;
    BigInt blinded_m = f.wallet.prepare_withdrawal(kDefaultDenomination, f.bank, pending);
    BigInt blind_sig = f.bank.blind_sign(kDefaultDenomination, blinded_m);
    Coin coin = f.wallet.unblind(f.bank, pending, blind_sig);

    BigInt m_check = HashUtils::hash_coin_identifier(coin.serial, coin.A, coin.S);
    // Verifying against the rogue bank's public key must fail even though
    // the coin is perfectly valid under the real bank's key.
    REQUIRE_FALSE(rogue_bank.verify(coin.denomination, m_check, coin.signature));
}

TEST_CASE("Bank account: balance can be set and debited", "[bank][account]") {
    Bank bank;
    bank.set_balance("alice", 100);

    REQUIRE(bank.balance("alice") == 100);

    bank.debit("alice", 5);
    REQUIRE(bank.balance("alice") == 95);

    bank.debit("alice", 10);
    REQUIRE(bank.balance("alice") == 85);
}

TEST_CASE("Bank account: insufficient balance is rejected", "[bank][account]") {
    Bank bank;
    bank.set_balance("alice", 3);

    REQUIRE_THROWS_AS(bank.debit("alice", 5), std::invalid_argument);
    // A rejected debit must not partially apply.
    REQUIRE(bank.balance("alice") == 3);
}

TEST_CASE("Bank account: negative debit amount is rejected", "[bank][account]") {
    Bank bank;
    bank.set_balance("alice", 50);

    REQUIRE_THROWS_AS(bank.debit("alice", -5), std::invalid_argument);
    REQUIRE(bank.balance("alice") == 50);
}

TEST_CASE("Bank account: unknown account is rejected", "[bank][account]") {
    Bank bank;

    REQUIRE_THROWS_AS(bank.balance("alice"), std::invalid_argument);
    REQUIRE_THROWS_AS(bank.debit("alice", 1), std::invalid_argument);
}

TEST_CASE("Bank account: accounts are independent", "[bank][account]") {
    Bank bank;
    bank.set_balance("alice", 100);
    bank.set_balance("bob", 20);

    bank.debit("alice", 30);

    REQUIRE(bank.balance("alice") == 70);
    REQUIRE(bank.balance("bob") == 20); // untouched
}
