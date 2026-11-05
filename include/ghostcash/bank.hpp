#pragma once

#include "ghostcash/bigint.hpp"
#include "ghostcash/cut_choose.hpp"
#include "ghostcash/group_setup.hpp"
#include "ghostcash/hash_utils.hpp"
#include "ghostcash/public_keys.hpp"
#include "ghostcash/rng.hpp"
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

    void add_denomination(int denomination, int rsa_bits, Rng& rng) {
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

    int withdraw_candidates() const { return withdraw_candidates_; }

    void set_withdraw_candidates(int k) {
        if (k < 1) throw std::invalid_argument("Bank: need at least one withdrawal candidate");
        withdraw_candidates_ = k;
    }

    size_t begin_withdrawal(const std::string& user, int denomination,
                            const std::vector<WithdrawCandidate>& candidates) {
        if (!has_denomination(denomination)) {
            throw std::invalid_argument("Bank: unknown denomination");
        }
        if (candidates.size() != static_cast<size_t>(withdraw_candidates_)) {
            throw std::invalid_argument("Bank: expected " + std::to_string(withdraw_candidates_) +
                                        " withdrawal candidates");
        }
        require_funds(user, denomination);
        if (pending_.count(user)) {
            throw std::invalid_argument("Bank: a previous withdrawal is still open; finish it first");
        }

        const BigInt& n = public_modulus(denomination);
        std::set<std::string> tags;
        for (const auto& c : candidates) {
            if (mpz_sgn(c.blinded_m.v) <= 0 || mpz_cmp(c.blinded_m.v, n.v) >= 0) {
                throw std::invalid_argument("Bank: blinded value out of range");
            }
            std::string t = c.tag.to_string(16);
            if (tag_log_.count(t) || !tags.insert(t).second) {
                throw std::invalid_argument("Bank: withdrawal tag already used");
            }
        }

        size_t keep = Rng::instance().index_below(candidates.size());
        pending_[user] = PendingCutChoose{denomination, candidates, keep};
        return keep;
    }

    BigInt finish_withdrawal(const std::string& user, const std::vector<CandidateOpening>& openings) {
        auto it = pending_.find(user);
        if (it == pending_.end()) {
            throw std::invalid_argument("Bank: no withdrawal in progress");
        }
        PendingCutChoose pc = std::move(it->second);
        pending_.erase(it);

        std::string failure = check_openings(pc, openings);
        if (!failure.empty()) {
            flagged_.insert(user);
            throw std::invalid_argument("Bank: cut-and-choose check failed (" + failure + "); account flagged");
        }

        const WithdrawCandidate& chosen = pc.candidates[pc.keep];
        std::string tag = chosen.tag.to_string(16);
        if (tag_log_.count(tag)) {
            throw std::invalid_argument("Bank: withdrawal tag already used");
        }
        debit(user, pc.denomination);
        tag_log_[tag] = user;
        return blind_sign(pc.denomination, chosen.blinded_m);
    }

    DepositResult deposit(const Transcript& t) {
        if (!has_group_) throw std::logic_error("Bank: group parameters not set");

        const Coin& c = t.coin;
        if (!has_denomination(c.denomination)) return rejected("unknown denomination");

        BigInt m = HashUtils::coin_message(c.serial, c.A, c.S, public_modulus(c.denomination));
        if (!verify(c.denomination, m, c.signature)) return rejected("bad bank signature");

        BigInt x = t.challenge(group_.q);
        if (!Schnorr::verify(group_, c.A, c.S, x, t.y)) return rejected("bad proof");

        const std::string key = coin_key(c);
        auto it = spent_.find(key);
        if (it == spent_.end()) {
            if (!balances_.count(t.receiver_id)) return rejected("unknown receiver account");
            spent_.emplace(key, t);
            balances_[t.receiver_id] += c.denomination;
            DepositResult ok;
            ok.status = DepositStatus::Accepted;
            return ok;
        }

        const Transcript& prev = it->second;
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

    bool has_open_withdrawal(const std::string& user) const { return pending_.count(user) != 0; }
    size_t open_withdrawal_index(const std::string& user) const {
        auto it = pending_.find(user);
        if (it == pending_.end()) throw std::invalid_argument("Bank: no withdrawal in progress");
        return it->second.keep;
    }

    bool is_flagged(const std::string& user) const { return flagged_.count(user) != 0; }
    const std::set<std::string>& flagged_accounts() const { return flagged_; }
    size_t spent_count() const { return spent_.size(); }

    static std::string coin_key(const Coin& c) {
        return std::to_string(c.denomination) + "|" + c.serial + "|" + c.A.to_string(16) + "|" + c.S.to_string(16);
    }

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
    struct PendingCutChoose {
        int denomination = 0;
        std::vector<WithdrawCandidate> candidates;
        size_t keep = 0;
    };

    void require_funds(const std::string& user, int amount) const {
        auto it = balances_.find(user);
        if (it == balances_.end()) {
            throw std::invalid_argument("Bank: unknown account: " + user);
        }
        if (it->second < amount) {
            throw std::invalid_argument("Bank: insufficient balance for account: " + user);
        }
    }

    std::string check_openings(const PendingCutChoose& pc, const std::vector<CandidateOpening>& openings) const {
        const size_t k = pc.candidates.size();
        if (openings.size() != k - 1) return "wrong number of openings";

        std::vector<bool> seen(k, false);
        const BigInt& n = public_modulus(pc.denomination);
        const BigInt& e = public_exponent(pc.denomination);
        const BigInt one(1);

        for (const auto& o : openings) {
            if (o.index >= k || o.index == pc.keep || seen[o.index]) return "bad candidate index";
            seen[o.index] = true;
            const std::string which = "candidate " + std::to_string(o.index);

            if (!in_range(o.a, group_.q) || !in_range(o.s, group_.q)) return which + ": secret out of range";
            if (!in_range(o.r, n) || BigInt::gcd(o.r, n) != one) return which + ": bad blinding factor";

            BigInt A = BigInt::powmod(group_.g, o.a, group_.p);
            BigInt S = BigInt::powmod(group_.g, o.s, group_.p);
            BigInt m = HashUtils::coin_message(o.serial, A, S, n);
            BigInt expected = BigInt::mulmod(m, BigInt::powmod(o.r, e, n), n);
            if (expected != pc.candidates[o.index].blinded_m) return which + ": blinded value does not match";
            if (HashUtils::hash_tag(o.a, o.s) != pc.candidates[o.index].tag) return which + ": tag does not match";
        }
        return "";
    }

    static bool in_range(const BigInt& x, const BigInt& bound) {
        return mpz_sgn(x.v) > 0 && mpz_cmp(x.v, bound.v) < 0;
    }

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
    int withdraw_candidates_ = kDefaultWithdrawCandidates;
    std::map<std::string, PendingCutChoose> pending_;
};
