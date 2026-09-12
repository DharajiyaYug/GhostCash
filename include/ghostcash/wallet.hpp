// wallet.hpp
//
// Wallet role in the blind-signature issuance protocol (Chaum's construction):
//
//   1. Generate a coin: random serial number, and placeholder discrete-log
//      commitments A = g^a, S = g^s for freshly sampled secrets a, s.
//   2. Form m = H(serial || A || S).
//   3. Blind:   m' = m * r^e mod n,  for random blinding factor r coprime to n,
//      using the (n, e) of whichever denomination the wallet is requesting.
//   4. Send (denomination, m') to the bank, receive back s' = blind_sign(m').
//   5. Unblind: s = s' * r^-1 mod n.
//   6. The pair (m, s) -- equivalently the Coin{serial, A, S, s, denomination}
//      -- is now a valid bank signature (under that denomination's key) on
//      the *original* identifier, even though the bank only ever saw the
//      blinded m'.

#pragma once

#include "ghostcash/bigint.hpp"
#include "ghostcash/coin.hpp"
#include "ghostcash/bank.hpp"
#include "ghostcash/hash_utils.hpp"
#include <gmp.h>
#include <sstream>

// Everything the wallet needs to remember between "request a coin" and
// "unblind the bank's response" -- kept explicit (rather than hidden as
// mutable wallet state) so a wallet can have several withdrawals in flight.
struct PendingWithdrawal {
    int denomination; // which of the bank's keys this withdrawal targets
    std::string serial;
    BigInt A, S;
    BigInt m;        // unblinded identifier: H(serial || A || S)
    BigInt r;         // blinding factor used
    BigInt blinded_m; // m' sent to the bank
};

class Wallet {
public:
    Wallet(BigInt group_p, BigInt group_q, BigInt group_g, gmp_randstate_t& rng)
        : p_(std::move(group_p)), q_(std::move(group_q)), g_(std::move(group_g)), rng_(rng) {}

    // Step 1-3: generate a fresh coin's public parts and blind its identifier
    // against the requested denomination's public key (n, e). Returns the
    // blinded message to send to the bank, and stores the rest in
    // `out_pending` for later unblinding.
    BigInt prepare_withdrawal(int denomination, const Bank& bank, PendingWithdrawal& out_pending) {
        // Sample coin secrets a, s in [1, q-1] and form commitments A = g^a, S = g^s
        // in the prime-order subgroup, per the "Coin structure" specification.
        BigInt a = BigInt::random_below(q_, rng_);
        BigInt s = BigInt::random_below(q_, rng_);
        BigInt A = BigInt::powmod(g_, a, p_);
        BigInt S = BigInt::powmod(g_, s, p_);

        std::string serial = random_serial();
        BigInt m = HashUtils::hash_coin_identifier(serial, A, S);

        const BigInt& n = bank.public_modulus(denomination);
        const BigInt& e = bank.public_exponent(denomination);

        // m must be reduced mod n before blinding, since RSA operates in Z_n.
        BigInt m_mod_n = BigInt::mod(m, n);

        // Pick blinding factor r coprime to n (required for r to be invertible
        // mod n later, during unblinding).
        BigInt r;
        for (;;) {
            r = BigInt::random_below(n, rng_);
            if (BigInt::gcd(r, n) == BigInt(1)) break;
        }

        BigInt r_e = BigInt::powmod(r, e, n);
        BigInt blinded_m = BigInt::mulmod(m_mod_n, r_e, n);

        out_pending = PendingWithdrawal{denomination, serial, A, S, m_mod_n, r, blinded_m};
        return blinded_m;
    }

    // Step 5-6: given the bank's blind signature s' on m', remove the
    // blinding factor to recover a valid signature s on the original m, and
    // package the result as a Coin.
    Coin unblind(const Bank& bank, const PendingWithdrawal& pending, const BigInt& blind_signature) const {
        const BigInt& n = bank.public_modulus(pending.denomination);
        BigInt r_inv = BigInt::invmod(pending.r, n);
        BigInt signature = BigInt::mulmod(blind_signature, r_inv, n);

        return Coin{pending.serial, pending.A, pending.S, signature, pending.denomination};
    }

private:
    BigInt p_, q_, g_;
    gmp_randstate_t& rng_;

    // Serial numbers just need to be unique-ish for this milestone: draw a
    // 128-bit random value directly (independent of the group order q) and
    // render it as a hex string.
    std::string random_serial() {
        mpz_t tmp;
        mpz_init(tmp);
        mpz_urandomb(tmp, rng_, 128);
        BigInt r; mpz_set(r.v, tmp);
        mpz_clear(tmp);
        return r.to_string(16);
    }
};
