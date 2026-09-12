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
#include "ghostcash/rsa_keygen.hpp"
#include <gmp.h>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

class Bank {
public:
    Bank() = default;

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

    std::map<int, RSAKeyPair> keys_;
    std::map<std::string, int> balances_;
};
