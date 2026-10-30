// bank.hpp
//
// Bank role in the blind-signature issuance protocol.
//
// Per Chaum's construction, a coin's denomination isn't a field baked into
// the signed message -- it's encoded entirely by *which RSA key the bank
// used to sign it*. A $1 coin and a $10 coin look identical in structure
// (serial, commitments, signature); the only way to tell them apart is that
// they verify against different public keys. So the bank holds one
// independent RSA keypair per denomination it supports, and every
// signing/verifying operation is parameterized by which denomination is in
// play.
//
// The bank exposes exactly two cryptographic operations relevant at this
// stage:
//   1. blind_sign(denomination, m'): sign a blinded value under the given
//      denomination's key, never seeing the real coin id.
//   2. verify(denomination, m, s): check a (message, signature) pair
//      against the given denomination's public key -- used here mainly for
//      testing, but merchants and the bank itself will reuse this in the
//      double-spend clearance module.
//
// It also holds a minimal simulated account ledger (balance/debit), because
// real issuance charges the withdrawing user's account for the
// denomination withdrawn. This is intentionally NOT wired into
// blind_sign() itself -- the account debit and the blind signature are two
// separate operations, called separately by whoever orchestrates a
// withdrawal. Crucially, debiting an account does not weaken the blind
// signature's anonymity: the bank can know *whose account* it charged
// without learning *which coin identifier* it just blindly signed for that
// account -- those are two different pieces of information, and only the
// second one is protected by blinding.

#pragma once

#include "ghostcash/bigint.hpp"
#include "ghostcash/group_setup.hpp"
#include "ghostcash/hash_utils.hpp"
#include "ghostcash/rsa_keygen.hpp"
#include "ghostcash/transcript.hpp"
#include "ghostcash/zkp.hpp"
#include <gmp.h>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// Outcome of redeeming a transcript at the bank.
enum class DepositStatus {
    Accepted,    // new coin: stored, receiver credited
    Duplicate,   // exactly the same transcript again (resubmission); nobody accused
    DoubleSpend, // same coin, different challenge: secrets extracted
    Invalid      // signature, proof, receiver or serial check failed
};

struct DepositResult {
    DepositStatus status = DepositStatus::Invalid;
    std::string detail;          // why a transcript was rejected, or a note
    std::string flagged_account; // DoubleSpend: the account the tag traced to ("" if untraceable)
    BigInt a, s;                 // DoubleSpend: the extracted coin secrets
};

class Bank {
public:
    Bank() = default;

    // The public group (p, q, g), needed to verify proofs at deposit time.
    void set_group(GroupParams group) {
        group_ = std::move(group);
        has_group_ = true;
    }

    // Registers a new denomination, generating a fresh, independent RSA
    // keypair for it on the spot. Each denomination's keypair is completely
    // unrelated to every other denomination's -- there is no shared modulus.
    void add_denomination(int denomination, int rsa_bits, gmp_randstate_t& rng) {
        if (keys_.count(denomination)) {
            throw std::invalid_argument("Bank: denomination already registered");
        }
        keys_.emplace(denomination, RSAKeyGen::generate(rsa_bits, rng));
    }

    bool has_denomination(int denomination) const {
        return keys_.count(denomination) != 0;
    }

    // Sorted list of every denomination this bank currently supports.
    std::vector<int> denominations() const {
        std::vector<int> result;
        result.reserve(keys_.size());
        for (const auto& [denom, _] : keys_) result.push_back(denom);
        return result;
    }

    const BigInt& public_modulus(int denomination) const { return key_for(denomination).n; }
    const BigInt& public_exponent(int denomination) const { return key_for(denomination).e; }
    int modulus_bits(int denomination) const { return key_for(denomination).modulus_bits; }

    // Blind signing: given a blinded message m' = m * r^e mod n (computed
    // with the requested denomination's own n, e), the bank computes
    // s' = (m')^d mod n using that denomination's private exponent. Because
    // the bank never learns m (only the blinded m'), and never learns r, it
    // signs "blind" -- it has no way to link this signature to any coin
    // identifier it may later see.
    BigInt blind_sign(int denomination, const BigInt& blinded_message) const {
        const RSAKeyPair& k = key_for(denomination);
        return BigInt::powmod(blinded_message, k.d, k.n);
    }

    // Returns the two sides of the RSA verification equation, s^e mod n and
    // m mod n, computed under the given denomination's key, without
    // collapsing them into a bool. Lets a caller display "here's the actual
    // arithmetic" instead of just VALID/INVALID.
    std::pair<BigInt, BigInt> verify_check(int denomination, const BigInt& message, const BigInt& signature) const {
        const RSAKeyPair& k = key_for(denomination);
        BigInt lhs = BigInt::powmod(signature, k.e, k.n);
        BigInt rhs = BigInt::mod(message, k.n);
        return {lhs, rhs};
    }

    // Verifies an (unblinded) message/signature pair against ONE specific
    // denomination's public key: checks that s^e mod n == m. This does not
    // search across denominations -- whoever is verifying (a merchant, or
    // the bank at deposit time) must state which denomination the coin
    // claims to be, and the check only passes if that's the key that
    // actually signed it.
    bool verify(int denomination, const BigInt& message, const BigInt& signature) const {
        auto [lhs, rhs] = verify_check(denomination, message, signature);
        return lhs == rhs;
    }

    // Full withdrawal: debits `user` for the denomination, logs the tag
    // T = H(a || s) against that account, and blind-signs. The tag is the
    // only link between this account and the coin: it is a hash of secrets
    // that never appear in the coin, so it says nothing about the coin until
    // a double spend reveals a and s (see deposit()).
    //
    // Everything that can be rejected is checked before the account is
    // touched, so a failed withdrawal neither debits nor logs. A tag already
    // in the log is rejected: two coins sharing a tag would make tracing
    // ambiguous.
    //
    // Trust note: in this simple mode the bank cannot check that the tag
    // really is H(a || s) for the coin being signed (it only sees the blinded
    // m'). A wallet that lies about its tag cannot be traced. A cut-and-choose
    // extension would close that; see DESIGN.md.
    BigInt withdraw(const std::string& user, int denomination,
                    const BigInt& blinded_message, const BigInt& tag) {
        if (!has_denomination(denomination)) {
            throw std::invalid_argument("Bank: unknown denomination");
        }
        if (tag_log_.count(tag.to_string(16))) {
            throw std::invalid_argument("Bank: withdrawal tag already used");
        }
        debit(user, denomination); // throws on unknown account / insufficient balance
        tag_log_[tag.to_string(16)] = user;
        return blind_sign(denomination, blinded_message);
    }

    // Redeems a transcript. Checks the bank signature, the proof (against the
    // challenge recomputed for the named receiver) and the receiver account,
    // then consults the spent-coin database keyed by serial:
    //   - unseen serial: store the transcript, credit the receiver.
    //   - same coin, same challenge: Duplicate (a resubmission; no accusation).
    //   - same coin, different challenge: DoubleSpend. The two responses give
    //     a and s; H(a || s) is looked up in the withdrawal log to find the
    //     account to flag. The second depositor is not credited.
    DepositResult deposit(const Transcript& t) {
        if (!has_group_) throw std::logic_error("Bank: group parameters not set");

        const Coin& c = t.coin;
        if (!has_denomination(c.denomination)) return rejected("unknown denomination");

        BigInt m = HashUtils::hash_coin_identifier(c.serial, c.A, c.S);
        if (!verify(c.denomination, m, c.signature)) return rejected("bad bank signature");

        BigInt x = t.challenge(group_.q);
        if (!Schnorr::verify(group_, c.A, c.S, x, t.y)) return rejected("bad proof");

        auto it = spent_.find(c.serial);
        if (it == spent_.end()) {
            if (!balances_.count(t.receiver_id)) return rejected("unknown receiver account");
            spent_.emplace(c.serial, t);
            balances_[t.receiver_id] += c.denomination;
            DepositResult ok;
            ok.status = DepositStatus::Accepted;
            return ok;
        }

        const Transcript& prev = it->second;
        if (prev.coin.A != c.A || prev.coin.S != c.S) {
            return rejected("serial already used by a different coin");
        }

        BigInt prev_x = prev.challenge(group_.q);
        if (prev_x == x) {
            DepositResult dup;
            dup.status = DepositStatus::Duplicate;
            dup.detail = "transcript already redeemed";
            return dup;
        }

        BigInt a, s;
        if (!Schnorr::extract(group_, prev_x, prev.y, x, t.y, a, s)) {
            return rejected("could not extract secrets");
        }
        // Both transcripts verified, so this must hold; checked anyway so a
        // bank bug can never accuse anyone on bad arithmetic.
        if (BigInt::powmod(group_.g, a, group_.p) != c.A ||
            BigInt::powmod(group_.g, s, group_.p) != c.S) {
            return rejected("extracted secrets inconsistent with coin");
        }

        DepositResult r;
        r.status = DepositStatus::DoubleSpend;
        r.a = a;
        r.s = s;
        auto tag_it = tag_log_.find(HashUtils::hash_tag(a, s).to_string(16));
        if (tag_it != tag_log_.end()) {
            r.flagged_account = tag_it->second;
            flagged_.insert(tag_it->second);
        } else {
            r.detail = "double spend detected but the tag is not in the withdrawal log";
        }
        return r;
    }

    bool is_flagged(const std::string& user) const { return flagged_.count(user) != 0; }
    const std::set<std::string>& flagged_accounts() const { return flagged_; }
    size_t spent_count() const { return spent_.size(); }

    // ---- simulated account ledger --------------------------------
    //
    // Deliberately minimal (a plain in-memory map of user id -> integer
    // balance): this is just enough to demonstrate that issuance charges an
    // account, not a real accounting subsystem. No currency conversion, no
    // persistence, no concurrency handling.

    void set_balance(const std::string& user, int amount) {
        balances_[user] = amount;
    }

    int balance(const std::string& user) const {
        auto it = balances_.find(user);
        if (it == balances_.end()) {
            throw std::invalid_argument("Bank: unknown account: " + user);
        }
        return it->second;
    }

    // Debits `amount` from `user`'s balance. Throws if the account is
    // unknown, if amount is negative, or if the account doesn't have
    // sufficient balance -- this is the same rejection a real bank would
    // make before ever agreeing to blind-sign a withdrawal.
    void debit(const std::string& user, int amount) {
        auto it = balances_.find(user);
        if (it == balances_.end()) {
            throw std::invalid_argument("Bank: unknown account: " + user);
        }
        if (amount < 0) {
            throw std::invalid_argument("Bank: cannot debit a negative amount");
        }
        if (it->second < amount) {
            throw std::invalid_argument("Bank: insufficient balance for account: " + user);
        }
        it->second -= amount;
    }

private:
    const RSAKeyPair& key_for(int denomination) const {
        auto it = keys_.find(denomination);
        if (it == keys_.end()) {
            throw std::invalid_argument("Bank: unknown denomination");
        }
        return it->second;
    }

    static DepositResult rejected(std::string why) {
        DepositResult r;
        r.status = DepositStatus::Invalid;
        r.detail = std::move(why);
        return r;
    }

    std::map<int, RSAKeyPair> keys_;
    std::map<std::string, int> balances_;

    GroupParams group_;
    bool has_group_ = false;
    std::map<std::string, std::string> tag_log_;  // hex(T) -> withdrawing account
    std::map<std::string, Transcript> spent_;     // serial -> first redeemed transcript
    std::set<std::string> flagged_;               // accounts traced to a double spend
};
