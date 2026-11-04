#include "ghostcash/bigint.hpp"
#include "ghostcash/rng.hpp"
#include "ghostcash/group_setup.hpp"
#include "ghostcash/bank.hpp"
#include "ghostcash/wallet.hpp"
#include "ghostcash/hash_utils.hpp"

#include <iostream>

int main() {
    Rng& rng = Rng::instance();

    std::cout << "=== GhostCash: Blind Signature Issuance Demo ===\n\n";

    std::cout << "[1] Generating group parameters (q: 256-bit, p: 3072-bit)...\n";
    GroupParams group = GroupSetup::generate(256, 3072, rng);
    std::cout << "    q bit length: " << group.q.bit_length() << "\n";
    std::cout << "    p bit length: " << group.p.bit_length() << "\n\n";

    std::cout << "[2] Generating bank RSA-2048 keypair (denomination = 1)...\n";
    Bank bank;
    bank.add_denomination(1, 2048, rng);
    std::cout << "    n bit length: " << bank.public_modulus(1).bit_length() << "\n";
    std::cout << "    e = " << bank.public_exponent(1).to_string() << "\n\n";

    std::cout << "[3] Running blind issuance protocol...\n";
    Wallet wallet(group.p, group.q, group.g, rng);

    PendingWithdrawal pending;
    BigInt blinded_m = wallet.prepare_withdrawal(1, bank, pending);
    std::cout << "    Wallet generated coin, serial = " << pending.serial << "\n";
    std::cout << "    Wallet sends blinded message to bank (bank cannot see real m)\n";

    BigInt blind_sig = bank.blind_sign(1, blinded_m);
    std::cout << "    Bank signs blinded message, returns blind signature\n";

    Coin coin = wallet.unblind(bank, pending, blind_sig);
    std::cout << "    Wallet unblinds signature -> coin ready\n\n";

    std::cout << "[4] Verifying issued coin...\n";
    BigInt m_check = HashUtils::coin_message(coin.serial, coin.A, coin.S, bank.public_modulus(coin.denomination));
    bool valid = bank.verify(coin.denomination, m_check, coin.signature);
    std::cout << "    Signature valid: " << (valid ? "YES" : "NO") << "\n\n";

    std::cout << (valid ? "=== Demo completed successfully ===\n"
                         : "=== Demo completed, but verification FAILED (see tests/) ===\n");
    return valid ? 0 : 1;
}
