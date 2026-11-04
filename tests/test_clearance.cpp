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
        : group(GroupSetup::generate(64, 256, Rng::instance())),
          wallet(group.p, group.q, group.g, Rng::instance()),
          bob("bob", group, bank, Rng::instance()),
          carol("carol", group, bank, Rng::instance()) {
        bank.set_group(group);
        bank.add_denomination(1, 512, Rng::instance());
        bank.add_denomination(5, 512, Rng::instance());
        bank.set_balance("alice", 100);
        bank.set_balance("bob", 0);
        bank.set_balance("carol", 0);
    }
};

WalletCoin withdraw(Fixture& f, const std::string& user, int denom) {
    WithdrawalBatch batch;
    auto candidates = f.wallet.prepare_batch(denom, f.bank, f.bank.withdraw_candidates(), batch);
    size_t keep = f.bank.begin_withdrawal(user, denom, candidates);
    BigInt blind_sig = f.bank.finish_withdrawal(user, Wallet::open_batch(batch, keep));
    return f.wallet.finish_withdrawal(f.bank, batch.candidates[keep], blind_sig);
}

bool pay(Fixture& f, Merchant& m, WalletCoin& wc, const std::string& time, Transcript& out) {
    PaymentSession session;
    if (!m.begin_payment(wc.coin, time, session)) return false;
    BigInt y;
    if (!f.wallet.pay(wc, m.id(), session.time, session.nonce, y)) return false;
    return m.finish_payment(session, y, out);
}
}

TEST_CASE("Clearance: honest withdraw, pay and redeem", "[clearance]") {
    Fixture f;

    WalletCoin wc = withdraw(f, "alice", 5);
    REQUIRE(f.bank.balance("alice") == 95);

    Transcript t;
    REQUIRE(pay(f, f.bob, wc, "t1", t));
    REQUIRE(f.bank.balance("bob") == 0);

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
    WalletCoin copy = honest;

    Transcript to_bob, to_carol;
    REQUIRE(pay(f, f.bob, honest, "t1", to_bob));
    REQUIRE(pay(f, f.carol, copy, "t2", to_carol));

    REQUIRE(f.bank.deposit(to_bob).status == DepositStatus::Accepted);

    DepositResult r = f.bank.deposit(to_carol);
    REQUIRE(r.status == DepositStatus::DoubleSpend);
    REQUIRE(r.flagged_account == "alice");
    REQUIRE(r.a == honest.a);
    REQUIRE(r.s == honest.s);

    REQUIRE(f.bank.is_flagged("alice"));
    REQUIRE(f.bank.balance("bob") == 5);
    REQUIRE(f.bank.balance("carol") == 0);
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

    REQUIRE(f.bank.balance("bob") == 5);
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
    Fixture f;
    WalletCoin wc = withdraw(f, "alice", 5);

    PaymentSession carol_session;
    REQUIRE(f.carol.begin_payment(wc.coin, "t1", carol_session));

    BigInt y;
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
    WalletCoin wc = withdraw(f, "alice", 1);
    Transcript t;
    REQUIRE(pay(f, f.bob, wc, "t1", t));

    t.coin.denomination = 5;
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
    Merchant ghost("ghost", f.group, f.bank, Rng::instance());
    WalletCoin wc = withdraw(f, "alice", 5);

    Transcript t;
    REQUIRE(pay(f, ghost, wc, "t1", t));
    REQUIRE(f.bank.deposit(t).status == DepositStatus::Invalid);
    REQUIRE(f.bank.spent_count() == 0);
}

TEST_CASE("Withdrawal: insufficient balance is rejected and leaves no trace", "[clearance][account]") {
    Fixture f;
    f.bank.set_balance("poor", 2);

    WithdrawalBatch batch;
    auto candidates = f.wallet.prepare_batch(5, f.bank, f.bank.withdraw_candidates(), batch);
    REQUIRE_THROWS(f.bank.begin_withdrawal("poor", 5, candidates));
    REQUIRE(f.bank.balance("poor") == 2);
    REQUIRE_FALSE(f.bank.has_open_withdrawal("poor"));

    f.bank.set_balance("poor", 10);
    REQUIRE_NOTHROW(withdraw(f, "poor", 5));
    REQUIRE(f.bank.balance("poor") == 5);
}

TEST_CASE("Withdrawal: a tag that was already logged is rejected", "[clearance][account]") {
    Fixture f;
    WithdrawalBatch first;
    auto c1 = f.wallet.prepare_batch(5, f.bank, f.bank.withdraw_candidates(), first);
    size_t keep = f.bank.begin_withdrawal("alice", 5, c1);
    f.bank.finish_withdrawal("alice", Wallet::open_batch(first, keep));
    REQUIRE(f.bank.balance("alice") == 95);

    WithdrawalBatch second;
    auto c2 = f.wallet.prepare_batch(5, f.bank, f.bank.withdraw_candidates(), second);
    c2[3].tag = c1[keep].tag;
    REQUIRE_THROWS(f.bank.begin_withdrawal("alice", 5, c2));
    REQUIRE(f.bank.balance("alice") == 95);
}

TEST_CASE("Withdrawal: the same tag twice in one batch is rejected", "[clearance][account]") {
    Fixture f;
    WithdrawalBatch batch;
    auto candidates = f.wallet.prepare_batch(5, f.bank, f.bank.withdraw_candidates(), batch);
    candidates[1].tag = candidates[0].tag;
    REQUIRE_THROWS(f.bank.begin_withdrawal("alice", 5, candidates));
}

TEST_CASE("Withdrawal: an unknown denomination is rejected without charging", "[clearance][account]") {
    Fixture f;
    WithdrawalBatch batch;
    auto candidates = f.wallet.prepare_batch(5, f.bank, f.bank.withdraw_candidates(), batch);
    REQUIRE_THROWS(f.bank.begin_withdrawal("alice", 7, candidates));
    REQUIRE(f.bank.balance("alice") == 100);
}

TEST_CASE("Cut-and-choose: the bank wants exactly k candidates", "[clearance][cutchoose]") {
    Fixture f;
    WithdrawalBatch batch;
    auto too_few = f.wallet.prepare_batch(5, f.bank, f.bank.withdraw_candidates() - 1, batch);
    REQUIRE_THROWS(f.bank.begin_withdrawal("alice", 5, too_few));
    REQUIRE(f.bank.withdraw_candidates() == kDefaultWithdrawCandidates);
}

TEST_CASE("Cut-and-choose: the account is charged only after the openings check out", "[clearance][cutchoose]") {
    Fixture f;
    WithdrawalBatch batch;
    auto candidates = f.wallet.prepare_batch(5, f.bank, f.bank.withdraw_candidates(), batch);
    size_t keep = f.bank.begin_withdrawal("alice", 5, candidates);
    REQUIRE(keep < candidates.size());
    REQUIRE(f.bank.open_withdrawal_index("alice") == keep);
    REQUIRE(f.bank.balance("alice") == 100);

    BigInt sig = f.bank.finish_withdrawal("alice", Wallet::open_batch(batch, keep));
    REQUIRE(f.bank.balance("alice") == 95);
    REQUIRE_FALSE(f.bank.has_open_withdrawal("alice"));

    WalletCoin wc = f.wallet.finish_withdrawal(f.bank, batch.candidates[keep], sig);
    BigInt m = HashUtils::coin_message(wc.coin.serial, wc.coin.A, wc.coin.S, f.bank.public_modulus(5));
    REQUIRE(f.bank.verify(5, m, wc.coin.signature));
}

TEST_CASE("Cut-and-choose: one withdrawal at a time, and no finish without a start", "[clearance][cutchoose]") {
    Fixture f;
    REQUIRE_THROWS(f.bank.finish_withdrawal("alice", {}));

    WithdrawalBatch b1, b2;
    auto c1 = f.wallet.prepare_batch(5, f.bank, f.bank.withdraw_candidates(), b1);
    auto c2 = f.wallet.prepare_batch(5, f.bank, f.bank.withdraw_candidates(), b2);
    size_t keep = f.bank.begin_withdrawal("alice", 5, c1);
    REQUIRE_THROWS(f.bank.begin_withdrawal("alice", 5, c2));

    REQUIRE_NOTHROW(f.bank.finish_withdrawal("alice", Wallet::open_batch(b1, keep)));
    REQUIRE_THROWS(f.bank.finish_withdrawal("alice", Wallet::open_batch(b1, keep)));
}

TEST_CASE("Cut-and-choose: false tags on every candidate are always caught", "[clearance][cutchoose][attack]") {
    Fixture f;
    WithdrawalBatch batch;
    auto candidates = f.wallet.prepare_batch(5, f.bank, f.bank.withdraw_candidates(), batch);
    for (size_t i = 0; i < candidates.size(); ++i) candidates[i].tag = BigInt(1000 + static_cast<long>(i));

    size_t keep = f.bank.begin_withdrawal("alice", 5, candidates);
    REQUIRE_THROWS(f.bank.finish_withdrawal("alice", Wallet::open_batch(batch, keep)));
    REQUIRE(f.bank.is_flagged("alice"));
    REQUIRE(f.bank.balance("alice") == 100);
}

TEST_CASE("Cut-and-choose: refusing to open a candidate, or opening it wrongly, is caught", "[clearance][cutchoose][attack]") {
    Fixture f;
    f.bank.set_balance("dave", 100);

    WithdrawalBatch b1;
    auto c1 = f.wallet.prepare_batch(5, f.bank, f.bank.withdraw_candidates(), b1);
    size_t keep1 = f.bank.begin_withdrawal("alice", 5, c1);
    auto missing = Wallet::open_batch(b1, keep1);
    missing.pop_back();
    REQUIRE_THROWS(f.bank.finish_withdrawal("alice", missing));
    REQUIRE(f.bank.is_flagged("alice"));

    WithdrawalBatch b2;
    auto c2 = f.wallet.prepare_batch(5, f.bank, f.bank.withdraw_candidates(), b2);
    size_t keep2 = f.bank.begin_withdrawal("dave", 5, c2);
    auto wrong = Wallet::open_batch(b2, keep2);
    wrong[0].r = BigInt::add(wrong[0].r, BigInt(1));
    REQUIRE_THROWS(f.bank.finish_withdrawal("dave", wrong));
    REQUIRE(f.bank.is_flagged("dave"));
    REQUIRE(f.bank.balance("dave") == 100);
}

TEST_CASE("Cut-and-choose: one false tag is caught unless the bank happens to keep it (probability 1/k)", "[clearance][cutchoose][limitation]") {
    Fixture f;
    bool caught = false, slipped = false;

    for (int attempt = 0; attempt < 300 && !(caught && slipped); ++attempt) {
        const std::string user = "m" + std::to_string(attempt);
        f.bank.set_balance(user, 100);

        WithdrawalBatch batch;
        auto candidates = f.wallet.prepare_batch(5, f.bank, f.bank.withdraw_candidates(), batch);
        candidates[0].tag = BigInt(123456789 + attempt);
        size_t keep = f.bank.begin_withdrawal(user, 5, candidates);

        if (keep != 0) {
            REQUIRE_THROWS(f.bank.finish_withdrawal(user, Wallet::open_batch(batch, keep)));
            REQUIRE(f.bank.is_flagged(user));
            caught = true;
            continue;
        }
        if (slipped) continue;

        BigInt sig = f.bank.finish_withdrawal(user, Wallet::open_batch(batch, keep));
        WalletCoin coin = f.wallet.finish_withdrawal(f.bank, batch.candidates[keep], sig);
        WalletCoin copy = coin;
        Transcript t1, t2;
        REQUIRE(pay(f, f.bob, coin, "t1-" + user, t1));
        REQUIRE(pay(f, f.carol, copy, "t2-" + user, t2));
        REQUIRE(f.bank.deposit(t1).status == DepositStatus::Accepted);
        DepositResult r = f.bank.deposit(t2);
        REQUIRE(r.status == DepositStatus::DoubleSpend);
        REQUIRE(r.flagged_account.empty());
        REQUIRE_FALSE(f.bank.is_flagged(user));
        slipped = true;
    }
    REQUIRE(caught);
    REQUIRE(slipped);
}
