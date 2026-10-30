# GhostCash

Offline-capable, anonymous e-cash in C++ (GMP + OpenSSL): Chaum-style RSA blind
signatures for issuance, a Schnorr-style proof for payment, and double-spend
tracing at the bank. Users run a local **wallet** that holds their coins and
does all the cryptography; an **app server** handles logins and routes
payments; a **bank server** signs coins and clears payments.

See [DESIGN.md](DESIGN.md) for the protocol, the threat model and the design
decisions.

## How it works (short)

- A coin is `(serial, A = g^a, S = g^s, bank signature)`. The bank signs a
  full-domain hash of those fields **blind**: it never sees the coin. Its value
  comes from which denomination key signed it.
- **Generate (withdraw):** the wallet blinds the coin, sends it to the bank
  with a tag `T = H(a || s)`, the bank debits the account and logs `T -> account`,
  and the wallet unblinds the signature.
- **Transfer (pay):** wallet-to-wallet, relayed by the app, no bank contact.
  The receiver checks the signature, sends a challenge `x = H(receiver, time, nonce)`,
  and the payer answers `y = s + a*x`. The receiver checks `g^y == S * A^x`.
- **Redeem (deposit):** the receiver sends the transcript to the bank. A coin
  seen twice with different challenges gives `a` and `s`; the bank hashes them,
  finds the tag, and flags the account that withdrew the coin.

## Dependencies

- A C++17 compiler (g++ or clang++), `make` (or CMake >= 3.16)
- [GMP](https://gmplib.org/), OpenSSL `libcrypto`, SQLite3
- `python3` (only for the end-to-end script)

| Platform        | Command                                                              |
|-----------------|----------------------------------------------------------------------|
| Debian / Ubuntu | `sudo apt-get install build-essential libgmp-dev libssl-dev libsqlite3-dev python3` |
| Fedora / RHEL   | `sudo dnf install gcc-c++ make gmp-devel openssl-devel sqlite-devel python3`         |
| Windows         | use WSL (Ubuntu) and the Debian/Ubuntu line above                    |

The HTTP and JSON libraries (cpp-httplib, nlohmann/json) are vendored under
`third_party/`.

## Build and test

```sh
make                 # demos, unit tests, bank_server, app_server, wallet_agent
make run-tests       # unit tests (Catch2)
make e2e             # starts a bank, an app and 3 wallets and runs the whole scenario
E2E_FULL=1 make e2e  # same, at the specified sizes (256-bit q, 3072-bit p, 2048-bit RSA)
```

CMake also works: `cmake -S . -B build && cmake --build build -j`.

If GMP/OpenSSL are not found, `make print-config` shows what was detected, and
`make GMP_PREFIX=/path SSL_PREFIX=/path` points the build at a custom install.

## Run the system

```sh
scripts/run_demo.sh            # full-size parameters (first start takes a few seconds)
scripts/run_demo.sh --fast     # small parameters
```

This starts the bank (`:9000`), the app server (`:8000`) and two wallets. Open
<http://127.0.0.1:8081/> and <http://127.0.0.1:8082/> in two browser windows,
create an account in each (new accounts get a simulated balance of 100), then:

1. **Generate** a coin in wallet A.
2. **Transfer** it to wallet B's username (B must be signed in: the payment is
   interactive). The protocol steps are shown live.
3. In wallet B, **Redeem** the received payment: B's bank balance goes up.
4. To demo a double spend: in A, generate a coin, pay it to B, then tick
   *allow re-spending an already spent coin* and pay the same coin to a third
   user C (a third wallet: `./build/wallet_agent --port 8083 --data demo-data/wallet-c`).
   When B and C both redeem, the second is rejected as a double spend and
   `logs/bank.log` shows the account the bank traced it to.

Each program can also be started by hand. Their options (`--port`, `--state`,
`--data`, ...) are documented at the top of each source file in `src/`.

## Programs

| Program        | Role | Storage |
|----------------|------|---------|
| `wallet_agent` | local wallet: all client-side crypto, local web UI (`ui/index.html`), JSON API | SQLite, one file per user (coins **and their secrets**, received payments, history) |
| `app_server`   | login, user -> bank account, withdraw/redeem gateway, transfer message routing | JSON file (salted PBKDF2 password hashes) |
| `bank_server`  | RSA keys per denomination, balances, withdrawal tag log, spent-coin database, tracing | JSON snapshot after every change (contains private keys: keep it private) |

The app server never sees coin secrets and stores no coins. During a transfer
it sees the coin and who paid whom (the honest-operator assumption).

## Library layout (`include/ghostcash/`)

```
bigint, rng, group_setup, rsa_keygen   primitives
hash_utils                             full-domain hash for signing, tag, challenge
coin, transcript                       data types
public_keys                            bank public keys / signature check (PublicKeySource)
bank                                   blind signing, accounts, withdraw(tag), deposit(trace)
wallet                                 coin generation, blinding, tag, answering challenges
merchant                               receiver side: verify coin, challenge, verify response
zkp                                    Schnorr proof: respond / verify / extract
serialize                              JSON wire format and bank-state persistence
```

`src/` has the three programs, `src/net_common.hpp`, and two issuance demos
(`demo_issuance`, `demo_interactive`). `tests/` has the Catch2 unit and attack
tests; `scripts/e2e.py` is the end-to-end test.

## Tests

- Unit tests per module, plus attack simulations: double spend traced to the
  withdrawer, forged response, replayed transcript, transcript redirected to
  another receiver, forged signature, wrong denomination, subgroup and `x = 0`
  attacks.
- `scripts/e2e.py` drives the real servers over HTTP: signup, generate,
  transfer, redeem, double spend, forged redeem, offline receiver,
  insufficient balance, and a bank restart.

## Known limitations

- **Trusted tag (`k = 1`).** The bank cannot check that the tag a wallet sends
  really is `H(a || s)` for the coin it blind-signs, so a wallet that lies about
  its tag double-spends untraceably (it is still detected). Cut-and-choose would
  close this; it is not implemented. A dishonest bank could also log a false tag
  against an account.
- **Operators are assumed honest.** The app sees who pays whom, and timing and
  denomination could be correlated by an operator who logs it.
- **RNG.** GMP's Mersenne Twister, seeded from OS entropy; not a CSPRNG.
- **Plain HTTP.** No TLS yet; use only on localhost.
- **Wallet secrets are stored unencrypted** in the local SQLite file.
- Group generation is not the verifiable seeded FIPS 186 procedure.
- Coins are single-use: a received payment is redeemed, not re-spent.
