// test_clearance.cpp
//
// End-to-end, in-process tests of the whole protocol: withdrawal with a tag,
// offline payment (wallet <-> merchant, no bank), and redemption with
// double-spend tracing. Also the attack simulations the project promised:
// double spend, forged response, replayed transcript, a transcript redirected
// to a different receiver, forged signature, wrong denomination.
//
// Uses small RSA/group sizes for test speed.

#include "third_party/catch.hpp"
#include "ghostcash/rng.hpp"
#include "ghostcash/group_setup.hpp"
#include "ghostcash/bank.hpp"
#include "ghostcash/wallet.hpp"
#include "ghostcash/merchant.hpp"
#include "ghostcash/hash_utils.hpp"

namespace {

struct Fixture {
    GroupParams group;
    Bank bank;
    Wallet wallet;
    Merchant bob;
    Merchant carol;

    Fixture()
        : group(GroupSetup::generate(/*q_bits=*/64, /*p_bits=*/256, Rng::instance())),
          wallet(group.p, group.q, group.g, Rng::instance()),
          bob("bob", group, bank, Rng::instance()),
          carol("carol", group, bank, Rng::instance()) {
        bank.set_group(group);
        bank.add_denomination(1, /*rsa_bits=*/512, Rng::instance());
        bank.add_denomination(5, /*rsa_bits=*/512, Rng::instance());
        bank.set_balance("alice", 100);
        bank.set_balance("bob", 0);
        bank.set_balance("carol", 0);
    }
};

// Withdraws one coin for `user`, the way the real flow does it: blinded
// message and tag go to the bank, the blind signature comes back.
WalletCoin withdraw(Fixture& f, const std::string& user, int denom) {
    PendingWithdrawal pending;
    BigInt blinded = f.wallet.prepare_withdrawal(denom, f.bank, pending);
    BigInt blind_sig = f.bank.withdraw(user, denom, blinded, pending.tag);
    return f.wallet.finish_withdrawal(f.bank, pending, blind_sig);
}

// One full offline payment: wallet presents the coin, merchant challenges,
// wallet responds, merchant verifies. No bank involvement beyond the public
// key. Returns false if either side refuses.
bool pay(Fixture& f, Merchant& m, WalletCoin& wc, const std::string& time, Transcript& out) {
    PaymentSession session;
    if (!m.begin_payment(wc.coin, time, session)) return false;
    BigInt y;
    if (!f.wallet.pay(wc, m.id(), session.time, session.nonce, y)) return false;
    return m.finish_payment(session, y, out);
}

} // namespace

TEST_CASE("Clearance: honest withdraw, pay and redeem", "[clearance]") {
    Fixture f;

    WalletCoin wc = withdraw(f, "alice", 5);
    REQUIRE(f.bank.balance("alice") == 95);

    Transcript t;
    REQUIRE(pay(f, f.bob, wc, "t1", t));
    REQUIRE(f.bank.balance("bob") == 0); // nothing credited until redeemed

    DepositResult r = f.bank.deposit(t);
    REQUIRE(r.status == DepositStatus::Accepted);
    REQUIRE(f.bank.balance("bob") == 5);
    REQUIRE(f.bank.spent_count() == 1);
    REQUIRE(f.bank.flagged_accounts().empty());
}

TEST_CASE("Clearance: the wallet's tag is H(a, s) and is not part of the coin", "[clearance]") {
    Fixture f;
    PendingWithdrawal pending;
    f.wallet.prepare_withdrawal(5, f.bank, pending);
    REQUIRE(pending.tag == HashUtils::hash_tag(pending.a, pending.s));
}

TEST_CASE("Clearance: double spend at two receivers is detected and traced to the withdrawer", "[clearance][attack]") {
    Fixture f;

    WalletCoin honest = withdraw(f, "alice", 5);
    WalletCoin copy = honest; // a malicious wallet keeps a copy of the coin and its secrets

    Transcript to_bob, to_carol;
    REQUIRE(pay(f, f.bob, honest, "t1", to_bob));
    REQUIRE(pay(f, f.carol, copy, "t2", to_carol)); // the copy was never marked spent

    REQUIRE(f.bank.deposit(to_bob).status == DepositStatus::Accepted);

    DepositResult r = f.bank.deposit(to_carol);
    REQUIRE(r.status == DepositStatus::DoubleSpend);
    REQUIRE(r.flagged_account == "alice");
    REQUIRE(r.a == honest.a);
    REQUIRE(r.s == honest.s);

    REQUIRE(f.bank.is_flagged("alice"));
    REQUIRE(f.bank.balance("bob") == 5);
    REQUIRE(f.bank.balance("carol") == 0); // second depositor is not credited
}

TEST_CASE("Clearance: only the double spender is flagged", "[clearance][attack]") {
    Fixture f;
    f.bank.set_balance("dave", 100);

    WalletCoin cheat = withdraw(f, "alice", 5);
    WalletCoin cheat_copy = cheat;
    WalletCoin fair = withdraw(f, "dave", 5);

    Transcript t1, t2, t3;
    REQUIRE(pay(f, f.bob, cheat, "t1", t1));
    REQUIRE(pay(f, f.carol, cheat_copy, "t2", t2));
    REQUIRE(pay(f, f.bob, fair, "t3", t3));

    f.bank.deposit(t1);
    REQUIRE(f.bank.deposit(t2).status == DepositStatus::DoubleSpend);
    REQUIRE(f.bank.deposit(t3).status == DepositStatus::Accepted);

    REQUIRE(f.bank.is_flagged("alice"));
    REQUIRE_FALSE(f.bank.is_flagged("dave"));
}

TEST_CASE("Clearance: redeeming the same transcript twice is a duplicate, not an accusation", "[clearance][attack]") {
    Fixture f;
    WalletCoin wc = withdraw(f, "alice", 5);

    Transcript t;
    REQUIRE(pay(f, f.bob, wc, "t1", t));

    REQUIRE(f.bank.deposit(t).status == DepositStatus::Accepted);
    REQUIRE(f.bank.deposit(t).status == DepositStatus::Duplicate);

    REQUIRE(f.bank.balance("bob") == 5); // credited once
    REQUIRE_FALSE(f.bank.is_flagged("alice"));
}

TEST_CASE("Clearance: a forged response is rejected by the merchant", "[clearance][attack]") {
    Fixture f;
    WalletCoin wc = withdraw(f, "alice", 5);

    PaymentSession session;
    REQUIRE(f.bob.begin_payment(wc.coin, "t1", session));

    BigInt y;
    REQUIRE(f.wallet.pay(wc, "bob", session.time, session.nonce, y));
    BigInt forged = BigInt::mod(BigInt::add(y, BigInt(1)), f.group.q);

    Transcript t;
    REQUIRE_FALSE(f.bob.finish_payment(session, forged, t));
}

TEST_CASE("Clearance: a forged response in a transcript is rejected by the bank", "[clearance][attack]") {
    Fixture f;
    WalletCoin wc = withdraw(f, "alice", 5);

    Transcript t;
    REQUIRE(pay(f, f.bob, wc, "t1", t));
    t.y = BigInt::mod(BigInt::add(t.y, BigInt(1)), f.group.q);

    DepositResult r = f.bank.deposit(t);
    REQUIRE(r.status == DepositStatus::Invalid);
    REQUIRE(f.bank.balance("bob") == 0);
}

TEST_CASE("Clearance: a transcript redirected to another receiver is rejected", "[clearance][attack]") {
    // Whoever copies a transcript en route can't redeem it for themselves:
    // the challenge is recomputed for the receiver named in the transcript,
    // so changing the name breaks the proof.
    Fixture f;
    f.bank.set_balance("mallory", 0);
    WalletCoin wc = withdraw(f, "alice", 5);

    Transcript t;
    REQUIRE(pay(f, f.bob, wc, "t1", t));
    t.receiver_id = "mallory";

    REQUIRE(f.bank.deposit(t).status == DepositStatus::Invalid);
    REQUIRE(f.bank.balance("mallory") == 0);
}

TEST_CASE("Clearance: a wallet won't answer a challenge for a different receiver", "[clearance][attack]") {
    // The wallet derives x for the receiver it means to pay. A challenge
    // issued for someone else therefore yields a response that doesn't
    // verify against the issuer's challenge.
    Fixture f;
    WalletCoin wc = withdraw(f, "alice", 5);

    PaymentSession carol_session;
    REQUIRE(f.carol.begin_payment(wc.coin, "t1", carol_session));

    BigInt y; // Alice means to pay Bob, but is handed Carol's session data
    REQUIRE(f.wallet.pay(wc, "bob", carol_session.time, carol_session.nonce, y));

    Transcript t;
    REQUIRE_FALSE(f.carol.finish_payment(carol_session, y, t));
}

TEST_CASE("Clearance: a forged coin signature is rejected by the merchant", "[clearance][attack]") {
    Fixture f;
    WalletCoin wc = withdraw(f, "alice", 5);
    wc.coin.signature = BigInt::add(wc.coin.signature, BigInt(1));

    PaymentSession session;
    REQUIRE_FALSE(f.bob.begin_payment(wc.coin, "t1", session));
}

TEST_CASE("Clearance: claiming a different denomination is rejected", "[clearance][attack]") {
    Fixture f;
    WalletCoin wc = withdraw(f, "alice", 1); // a 1-coin
    Transcript t;
    REQUIRE(pay(f, f.bob, wc, "t1", t));

    t.coin.denomination = 5; // claim it is worth 5
    REQUIRE(f.bank.deposit(t).status == DepositStatus::Invalid);
    REQUIRE(f.bank.balance("bob") == 0);
}

TEST_CASE("Clearance: an honest wallet refuses to spend a coin twice", "[clearance]") {
    Fixture f;
    WalletCoin wc = withdraw(f, "alice", 5);

    Transcript t1, t2;
    REQUIRE(pay(f, f.bob, wc, "t1", t1));
    REQUIRE(wc.spent);
    REQUIRE_FALSE(pay(f, f.carol, wc, "t2", t2));
}

TEST_CASE("Clearance: redeeming to an unknown account is rejected", "[clearance]") {
    Fixture f;
    Merchant ghost("ghost", f.group, f.bank, Rng::instance()); // no bank account
    WalletCoin wc = withdraw(f, "alice", 5);

    Transcript t;
    REQUIRE(pay(f, ghost, wc, "t1", t));
    REQUIRE(f.bank.deposit(t).status == DepositStatus::Invalid);
    REQUIRE(f.bank.spent_count() == 0);
}

TEST_CASE("Withdrawal: insufficient balance is rejected and leaves no trace", "[clearance][account]") {
    Fixture f;
    f.bank.set_balance("poor", 2);

    PendingWithdrawal pending;
    BigInt blinded = f.wallet.prepare_withdrawal(5, f.bank, pending);
    REQUIRE_THROWS(f.bank.withdraw("poor", 5, blinded, pending.tag));
    REQUIRE(f.bank.balance("poor") == 2);

    // The same tag was not logged by the failed attempt, so it can be reused.
    f.bank.set_balance("poor", 10);
    REQUIRE_NOTHROW(f.bank.withdraw("poor", 5, blinded, pending.tag));
    REQUIRE(f.bank.balance("poor") == 5);
}

TEST_CASE("Withdrawal: a repeated tag is rejected", "[clearance][account]") {
    Fixture f;
    PendingWithdrawal pending;
    BigInt blinded = f.wallet.prepare_withdrawal(5, f.bank, pending);

    REQUIRE_NOTHROW(f.bank.withdraw("alice", 5, blinded, pending.tag));
    REQUIRE_THROWS(f.bank.withdraw("alice", 5, blinded, pending.tag));
    REQUIRE(f.bank.balance("alice") == 95); // charged once
}

TEST_CASE("Withdrawal: an unknown denomination is rejected without charging", "[clearance][account]") {
    Fixture f;
    PendingWithdrawal pending;
    BigInt blinded = f.wallet.prepare_withdrawal(5, f.bank, pending);
    REQUIRE_THROWS(f.bank.withdraw("alice", 7, blinded, pending.tag));
    REQUIRE(f.bank.balance("alice") == 100);
}

TEST_CASE("Clearance: a wallet that lies about its tag double-spends untraceably (k = 1 trust assumption)", "[clearance][limitation]") {
    // Documents the simple mode's limitation: the bank can't check the tag
    // against the blinded coin, so a lying wallet is detected as a double
    // spender but not identified. Cut-and-choose is the planned hardening.
    Fixture f;

    PendingWithdrawal pending;
    BigInt blinded = f.wallet.prepare_withdrawal(5, f.bank, pending);
    BigInt blind_sig = f.bank.withdraw("alice", 5, blinded, BigInt(123456789)); // wrong tag
    WalletCoin honest = f.wallet.finish_withdrawal(f.bank, pending, blind_sig);
    WalletCoin copy = honest;

    Transcript t1, t2;
    REQUIRE(pay(f, f.bob, honest, "t1", t1));
    REQUIRE(pay(f, f.carol, copy, "t2", t2));

    REQUIRE(f.bank.deposit(t1).status == DepositStatus::Accepted);
    DepositResult r = f.bank.deposit(t2);
    REQUIRE(r.status == DepositStatus::DoubleSpend);
    REQUIRE(r.flagged_account.empty());
    REQUIRE(f.bank.flagged_accounts().empty());
}
