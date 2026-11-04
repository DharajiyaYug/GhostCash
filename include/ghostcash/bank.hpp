#pragma once

#include "ghostcash/bigint.hpp"
#include "ghostcash/group_setup.hpp"
#include "ghostcash/hash_utils.hpp"
#include "ghostcash/public_keys.hpp"
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

enum class DepositStatus {
    Accepted,
    Duplicate,
    DoubleSpend,
    Invalid
};

struct DepositResult {
    DepositStatus status = DepositStatus::Invalid;
    std::string detail;
    std::string flagged_account;
    BigInt a, s;
};

struct BankPersistence;

class Bank : public PublicKeySource {
public:
    friend struct BankPersistence;

    Bank() = default;

    void set_group(GroupParams group) {
        group_ = std::move(group);
        has_group_ = true;
    }

    void add_denomination(int denomination, int rsa_bits, gmp_randstate_t& rng) {
        if (keys_.count(denomination)) {
            throw std::invalid_argument("Bank: denomination already registered");
        }
        keys_.emplace(denomination, RSAKeyGen::generate(rsa_bits, rng));
    }

    bool has_denomination(int denomination) const override {
        return keys_.count(denomination) != 0;
    }

    std::vector<int> denominations() const {
        std::vector<int> result;
        result.reserve(keys_.size());
        for (const auto& [denom, _] : keys_) result.push_back(denom);
        return result;
    }

    const BigInt& public_modulus(int denomination) const override { return key_for(denomination).n; }
    const BigInt& public_exponent(int denomination) const override { return key_for(denomination).e; }
    int modulus_bits(int denomination) const { return key_for(denomination).modulus_bits; }

    BigInt blind_sign(int denomination, const BigInt& blinded_message) const {
        const RSAKeyPair& k = key_for(denomination);
        return BigInt::powmod(blinded_message, k.d, k.n);
    }

    bool has_account(const std::string& user) const { return balances_.count(user) != 0; }

    bool has_group() const { return has_group_; }
    const GroupParams& group() const { return group_; }

    BigInt withdraw(const std::string& user, int denomination,
                    const BigInt& blinded_message, const BigInt& tag) {
        if (!has_denomination(denomination)) {
            throw std::invalid_argument("Bank: unknown denomination");
        }
        if (tag_log_.count(tag.to_string(16))) {
            throw std::invalid_argument("Bank: withdrawal tag already used");
        }
        debit(user, denomination);
        tag_log_[tag.to_string(16)] = user;
        return blind_sign(denomination, blinded_message);
    }

    DepositResult deposit(const Transcript& t) {
        if (!has_group_) throw std::logic_error("Bank: group parameters not set");

        const Coin& c = t.coin;
        if (!has_denomination(c.denomination)) return rejected("unknown denomination");

        BigInt m = HashUtils::coin_message(c.serial, c.A, c.S, public_modulus(c.denomination));
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
    std::map<std::string, std::string> tag_log_;
    std::map<std::string, Transcript> spent_;
    std::set<std::string> flagged_;
};
