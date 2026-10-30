// public_keys.hpp
//
// The bank's *public* RSA keys, one per denomination, and the signature check
// that only needs them. Wallets and receivers (merchants) verify coins with
// this and never need the bank's private state, so they take a
// PublicKeySource& rather than a whole Bank:
//
//   - Bank implements it directly (in-process use, tests, the bank server);
//   - PublicKeyRing is a plain registry a client fills from the keys the bank
//     publishes over the network.

#pragma once

#include "ghostcash/bigint.hpp"
#include <map>
#include <stdexcept>
#include <utility>
#include <vector>

class PublicKeySource {
public:
    virtual ~PublicKeySource() = default;

    virtual bool has_denomination(int denomination) const = 0;
    virtual const BigInt& public_modulus(int denomination) const = 0;
    virtual const BigInt& public_exponent(int denomination) const = 0;

    // Returns the two sides of the RSA verification equation, s^e mod n and
    // m mod n, computed under the given denomination's key, without
    // collapsing them into a bool. Lets a caller display "here's the actual
    // arithmetic" instead of just VALID/INVALID.
    std::pair<BigInt, BigInt> verify_check(int denomination, const BigInt& message, const BigInt& signature) const {
        const BigInt& n = public_modulus(denomination);
        const BigInt& e = public_exponent(denomination);
        BigInt lhs = BigInt::powmod(signature, e, n);
        BigInt rhs = BigInt::mod(message, n);
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
};

// A client-side registry of the bank's public keys.
class PublicKeyRing : public PublicKeySource {
public:
    void add(int denomination, BigInt n, BigInt e) {
        keys_[denomination] = std::make_pair(std::move(n), std::move(e));
    }

    bool has_denomination(int denomination) const override {
        return keys_.count(denomination) != 0;
    }

    const BigInt& public_modulus(int denomination) const override { return at(denomination).first; }
    const BigInt& public_exponent(int denomination) const override { return at(denomination).second; }

    std::vector<int> denominations() const {
        std::vector<int> result;
        for (const auto& kv : keys_) result.push_back(kv.first);
        return result;
    }

private:
    const std::pair<BigInt, BigInt>& at(int denomination) const {
        auto it = keys_.find(denomination);
        if (it == keys_.end()) throw std::invalid_argument("PublicKeyRing: unknown denomination");
        return it->second;
    }

    std::map<int, std::pair<BigInt, BigInt>> keys_;
};
