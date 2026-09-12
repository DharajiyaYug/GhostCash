// demo_interactive.cpp
//
// A compact, screenshot-friendly walkthrough of one blind-signature coin
// issuance -- including the bank debiting the withdrawing user's account,
// which is part of the issuance flow but deliberately kept separate from
// the cryptographic blind-signing step (see bank.hpp). Every line is tagged
// by who actually sees that data:
//
//   WALLET   data that never leaves the wallet
//   WIRE     exactly what's sent to the bank
//   BANK     what the bank does (account debit, blind signing)
//   VERIFY   the actual s^e mod n vs m mod n check, spelled out, for
//            every denomination the bank knows about
//
// Usage:
//   ./demo_interactive          interactive prompt for denomination
//   ./demo_interactive 5        withdraw a "5" directly, no prompt
//   ./demo_interactive --auto   never prompt (uses 1 if none given); for
//                               piping into a file or a screenshot script
//
// This is a presentation aid, not a correctness check -- see
// tests/test_bank_wallet.cpp for the actual test suite.

#include "ghostcash/bigint.hpp"
#include "ghostcash/rng.hpp"
#include "ghostcash/group_setup.hpp"
#include "ghostcash/bank.hpp"
#include "ghostcash/wallet.hpp"
#include "ghostcash/hash_utils.hpp"
#include "term_ui.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <sstream>

using term::bold;
using term::cyan;
using term::yellow;
using term::magenta;
using term::green;
using term::red;
using term::truncated;

namespace {

const std::string kUser = "wallet-user";
constexpr int kStartingBalance = 100;

std::string denoms_to_string(const std::vector<int>& denoms) {
    std::ostringstream os;
    for (size_t i = 0; i < denoms.size(); ++i) {
        if (i) os << "/";
        os << denoms[i];
    }
    return os.str();
}

// Reads a denomination choice from stdin, re-prompting on invalid input.
// Blank input picks the default (first available denomination).
int prompt_denomination(const std::vector<int>& denoms) {
    int def = denoms.front();
    for (;;) {
        std::cout << "Withdraw which denomination? [" << denoms_to_string(denoms)
                  << "] (default " << def << "): ";
        std::string line;
        if (!std::getline(std::cin, line)) return def;
        if (line.empty()) return def;
        int val = std::atoi(line.c_str());
        if (std::find(denoms.begin(), denoms.end(), val) != denoms.end()) return val;
        std::cout << "  " << red("Not a valid denomination, try again.") << "\n";
    }
}

} // namespace

int main(int argc, char** argv) {
    term::init(argc, argv);
    gmp_randstate_t& rng = Rng::instance();

    int requested_denomination = 0; // 0 = "not specified on the command line"
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (!arg.empty() && arg[0] != '-') requested_denomination = std::atoi(arg.c_str());
    }

    std::cout << bold("======================================================") << "\n";
    std::cout << bold("        GhostCash: Blind Signature Issuance") << "\n";
    std::cout << bold("======================================================") << "\n";
    std::cout << cyan("WALLET") << "=private   " << yellow("WIRE") << "=sent to bank   "
              << magenta("BANK") << "=bank action   " << bold("VERIFY") << "=math check\n\n";

    // --- Step 1: bank setup ------------------------------------------
    GroupParams group = GroupSetup::generate(/*q_bits=*/96, /*p_bits=*/512, rng);
    Bank bank;
    for (int denom : {1, 5, 10}) bank.add_denomination(denom, /*rsa_bits=*/1024, rng);
    std::vector<int> denoms = bank.denominations();
    bank.set_balance(kUser, kStartingBalance);

    std::cout << bold("[1] BANK SETUP") << "\n";
    std::cout << "    group: q=" << group.q.bit_length() << "-bit, p=" << group.p.bit_length() << "-bit\n";
    for (int d : denoms) {
        std::cout << "    " << magenta("[BANK]") << " denomination " << d << ": n="
                  << truncated(bank.public_modulus(d).to_string(), 14, 6)
                  << "  e=" << bank.public_exponent(d).to_string() << "\n";
    }
    std::cout << "    Independent RSA key per denomination -- a coin's value is\n"
                 "    determined entirely by which key signed it.\n";
    std::cout << "    " << magenta("[BANK]") << " user account balance = " << bank.balance(kUser) << "\n\n";

    if (requested_denomination != 0 &&
        std::find(denoms.begin(), denoms.end(), requested_denomination) == denoms.end()) {
        std::cout << red("Denomination " + std::to_string(requested_denomination) +
                          " isn't one the bank supports. Exiting.\n");
        return 1;
    }
    int denom = requested_denomination;
    if (denom == 0) {
        denom = (term::interactive_mode()) ? prompt_denomination(denoms) : denoms.front();
    }

    // --- Step 2: wallet prepares the coin (all private) ---------------
    Wallet wallet(group.p, group.q, group.g, rng);
    PendingWithdrawal pending;
    BigInt blinded_m = wallet.prepare_withdrawal(denom, bank, pending);

    std::cout << bold("[2] WALLET PREPARES COIN") << "\n";
    std::cout << "    " << cyan("[WALLET-PRIVATE]") << " denomination = " << denom << "\n";
    std::cout << "    " << cyan("[WALLET-PRIVATE]") << " serial = " << pending.serial << "\n";
    std::cout << "    " << cyan("[WALLET-PRIVATE]") << " A = g^a = " << truncated(pending.A.to_string(), 14, 6) << "\n";
    std::cout << "    " << cyan("[WALLET-PRIVATE]") << " S = g^s = " << truncated(pending.S.to_string(), 14, 6) << "\n";
    std::cout << "    " << cyan("[WALLET-PRIVATE]") << " m = H(serial||A||S) = "
              << truncated(pending.m.to_string(), 14, 6) << "\n";
    std::cout << "    " << cyan("[WALLET-PRIVATE]") << " r = " << truncated(pending.r.to_string(), 14, 6) << "\n";
    std::cout << "    These values stay inside the wallet until spending.\n\n";

    // --- Step 3: withdrawal request + account debit -------------------
    std::cout << bold("[3] WITHDRAWAL REQUEST") << "\n";
    std::cout << "    " << yellow("[ON THE WIRE]") << " denomination = " << denom << "\n";
    std::cout << "    " << yellow("[ON THE WIRE]") << " m' = m*r^e mod n = "
              << truncated(blinded_m.to_string(), 14, 6) << "\n";

    int before = bank.balance(kUser);
    bank.debit(kUser, denom);
    int after = bank.balance(kUser);
    std::cout << "    " << magenta("[BANK]") << " account balance: " << before << " -> " << after << "\n";
    std::cout << "    " << magenta("[BANK]") << " receives only denomination + m' -- never sees\n"
                 "           serial, A, S, m, or r (charging the account doesn't\n"
                 "           require knowing which coin identifier it belongs to).\n\n";

    // --- Step 4: bank blind-signs --------------------------------------
    BigInt blind_sig = bank.blind_sign(denom, blinded_m);
    std::cout << bold("[4] BANK BLIND-SIGNS") << "\n";
    std::cout << "    " << magenta("[BANK]") << " using denomination-" << denom << " private key\n";
    std::cout << "    " << magenta("[BANK]") << " s' = (m')^d mod n = "
              << truncated(blind_sig.to_string(), 14, 6) << "\n\n";

    // --- Step 5: wallet unblinds ----------------------------------------
    Coin coin = wallet.unblind(bank, pending, blind_sig);
    std::cout << bold("[5] WALLET UNBLINDS") << "\n";
    std::cout << "    " << cyan("[WALLET-PRIVATE]") << " s = s'*r^-1 mod n = "
              << truncated(coin.signature.to_string(), 14, 6) << "\n";
    std::cout << "    Final coin: serial=" << coin.serial << "  denomination=" << coin.denomination << "\n";
    std::cout << "    Signature is now valid on the original m, not the blinded m'.\n\n";

    // --- Step 6: verification, spelled out, for every denomination -----
    std::cout << bold("[6] VERIFY") << "   s^e mod n == m mod n\n";
    BigInt m_check = HashUtils::hash_coin_identifier(coin.serial, coin.A, coin.S);
    bool correct_ok = false;
    for (int d : denoms) {
        auto [lhs, rhs] = bank.verify_check(d, m_check, coin.signature);
        bool match = (lhs == rhs);
        if (d == coin.denomination) correct_ok = match;
        std::cout << "    denom " << d << ":  lhs=" << truncated(lhs.to_string(), 12, 4)
                   << "  rhs=" << truncated(rhs.to_string(), 12, 4) << "  -> "
                   << (match ? green("MATCH") : red("MISMATCH"))
                   << (d == coin.denomination ? "  (correct key)" : "") << "\n";
    }

    Coin tampered = coin;
    tampered.serial += "00";
    BigInt m_tampered = HashUtils::hash_coin_identifier(tampered.serial, tampered.A, tampered.S);
    auto [t_lhs, t_rhs] = bank.verify_check(tampered.denomination, m_tampered, tampered.signature);
    bool tamper_caught = (t_lhs != t_rhs);
    std::cout << "    tampered serial:  lhs=" << truncated(t_lhs.to_string(), 12, 4)
               << "  rhs=" << truncated(t_rhs.to_string(), 12, 4) << "  -> "
               << (tamper_caught ? green("MISMATCH (rejected)") : red("MATCH (unexpected!)")) << "\n\n";

    bool all_ok = correct_ok && tamper_caught &&
                  std::count_if(denoms.begin(), denoms.end(), [&](int d) {
                      return bank.verify(d, m_check, coin.signature);
                  }) == 1;

    std::cout << bold(all_ok ? green("=== Coin verified only under denomination-" +
                                      std::to_string(coin.denomination) + " key; tampering rejected. ===")
                              : red("=== Unexpected result -- see tests/ ===")) << "\n";
    return all_ok ? 0 : 1;
}
