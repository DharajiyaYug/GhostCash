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
- **Generate (withdraw), with cut-and-choose:** the wallet prepares `k = 10`
  blinded candidate coins, each with a tag `T = H(a || s)`. The bank picks one
  at random to keep and the wallet opens the other nine; the bank checks that
  each opened candidate is well formed and its tag is honest. Only then does it
  debit the account, log the kept candidate's tag `T -> account` and sign it
  blind. A wallet with a false tag is caught (and flagged) with probability
  `(k-1)/k`. The wallet unblinds the signature.
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
E2E_TLS=0 make e2e   # same, without TLS (TLS is on by default)
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
   (You can also pay yourself; redeeming that payment returns the coin's value
   to your bank balance.)
4. To demo a double spend: in A, generate a coin, pay it to B, then tick
   *allow re-spending an already spent coin* and pay the same coin to a third
   user C (a third wallet: `./build/wallet_agent --port 8083 --data demo-data/wallet-c`).
   When B and C both redeem, the second is rejected as a double spend and
   `logs/bank.log` shows the account the bank traced it to.

Each program can also be started by hand:

```sh
./build/bank_server  --port 9000 --state bank_state.json --key dev-internal-key --candidates 10 [--fast] \
                     [--tls-cert server.crt --tls-key server.key]
./build/app_server   --port 8000 --bank-host 127.0.0.1 --bank-port 9000 --key dev-internal-key \
                     --users users.json --start-balance 100 \
                     [--tls-cert server.crt --tls-key server.key --bank-ca ca.crt]
./build/wallet_agent --port 8081 --app-host 127.0.0.1 --app-port 8000 --data ./wallet-data --ui ./ui \
                     [--app-ca ca.crt]
```

**TLS.** `scripts/run_demo.sh` turns TLS on by default (`--no-tls` turns it
off): `scripts/make_certs.sh demo-data/tls` creates a local certificate
authority and a certificate for `localhost` / `127.0.0.1`, the bank and app
server serve HTTPS (`--tls-cert`, `--tls-key`), and the app server and wallets
verify the server certificate against that CA (`--bank-ca`, `--app-ca`). The
browser-to-wallet connection stays plain HTTP on `127.0.0.1`: it never leaves
the machine, and HTTPS there would only produce a self-signed-certificate
warning.

`--fast` uses small crypto sizes. `--key` is the shared secret the app server
uses to call the bank; it must match on both. `--candidates` is `k`, the number
of cut-and-choose candidates per withdrawal.

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
bigint, group_setup, rsa_keygen        primitives
hash_utils                             full-domain hash for signing, tag, challenge
coin, transcript                       data types
public_keys                            bank public keys / signature check (PublicKeySource)
rng                                    all randomness, from OpenSSL RAND_bytes (CSPRNG)
cut_choose                             withdrawal candidate and opening types
bank                                   blind signing, accounts, cut-and-choose withdrawal, deposit(trace)
wallet                                 coin generation, blinding, candidates and openings, answering challenges
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

- **Cut-and-choose is probabilistic.** A wallet that puts one false tag among its
  `k` candidates escapes detection at withdrawal with probability `1/k` (10%);
  if it then double-spends, the double spend is still detected but cannot be
  traced. In the other cases it is caught and flagged at withdrawal. A larger `k`
  lowers the chance at the cost of more work per withdrawal.
- **One open withdrawal per account.** The bank refuses to start a new
  withdrawal while one is still open, so a cheater cannot restart until the
  bank keeps the false candidate. An open withdrawal is held in memory and is
  cleared when the bank restarts.
- A dishonest bank could log a false tag against an account.
- **Operators are assumed honest.** The app sees who pays whom, and timing and
  denomination could be correlated by an operator who logs it.
- **TLS uses a self-made CA.** Fine for a demo; a real deployment would use a
  certificate from a public CA. TLS hides traffic from the network, not from the
  app server, which still sees who pays whom.
- **Coins live on the device.** A wallet's coins and secrets are in a local
  SQLite file per username (in the agent's `--data` directory). Logging in as the
  same user from another machine, or another wallet with a different data
  directory, does not bring the coins along; there is no backup or sync yet.
- **Sessions are in memory.** Restarting the app server signs every wallet out;
  accounts and local coins are unaffected. Usernames may contain capital letters
  but are unique ignoring case.
- **Wallet secrets are stored unencrypted** in the local SQLite file.
- Group generation is not the verifiable seeded FIPS 186 procedure.
- Coins are single-use: a received payment is redeemed, not re-spent.
