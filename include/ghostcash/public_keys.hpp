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

    std::pair<BigInt, BigInt> verify_check(int denomination, const BigInt& message, const BigInt& signature) const {
        const BigInt& n = public_modulus(denomination);
        const BigInt& e = public_exponent(denomination);
        BigInt lhs = BigInt::powmod(signature, e, n);
        BigInt rhs = BigInt::mod(message, n);
        return {lhs, rhs};
    }

    bool verify(int denomination, const BigInt& message, const BigInt& signature) const {
        auto [lhs, rhs] = verify_check(denomination, message, signature);
        return lhs == rhs;
    }
};

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
