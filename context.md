# GhostCash: full project context

Purpose of this file: hand this to a fresh Claude (or a new teammate) so they can continue the project without having seen any earlier conversation. It describes what exists, how every part works, exactly what is sent on the wire, how to build/run/test it, which decisions are made, and which are still open.

Last updated against `main` (commit hashes changed once when the history was rewritten to remove co-author lines; the file contents are the same as before). Everything described as "built" is in that commit and was verified: 74 unit test cases (376 assertions) pass, and `scripts/e2e.py` passes (about 45 checks).

---

## 0. How to work with the user (read first)

- The user is a student on a 4-person team (see section 1). They write casually, sometimes in Hinglish/Punjabi. Reply in simple, plain English.
- **Work in small steps.** They explicitly said so. They want to be asked before big forks, and they do want a plan checked with them before large builds.
- **Never bring up a "TA" or instructor review.** They were annoyed by it. Do not suggest checking anything with a TA.
- They said: skip web-dev concerns (two devices logged in at once, scaling, large-user hosting). The goal is a complete, working, impressive end-to-end demonstration of the cryptography on one laptop.
- Git: they authorised pushing **straight to `main`** (no feature branches needed). The remote is `https://github.com/DharajiyaYug/GhostCash`. A teammate also merges PRs on GitHub; always `git pull` (merge) before pushing.
- **No Claude attribution anywhere in git.** Do not add co-author trailers or "Generated with" lines to commits or PRs. The user saw "claude" in GitHub's Contributors list and asked for it removed; the nine commits carrying the trailer were rewritten and `main` was force-pushed (new commit hashes from the first rewritten commit onward). Teammates with older clones must run `git fetch` then `git reset --hard origin/main`.
- Be honest about what is and is not verified. Say so plainly if something wasn't run.
- When something is meant for teammates, start the message with one line naming the audience.
- A page-style "team discussion" document was started but **not published**; the user asked for the list in chat instead (section 13 has the list).

---

## 1. Project and course context

- Course project for **CS670** (cryptography, IIT Kanpur). Project name **GhostCash**: an anonymous, offline-capable e-cash system.
- Team: Bikramjeet Singh (230298), Dharajiya Yug (230362), Rudra Sinha (230880), Siddharth Miglani (231006). The repo belongs to Dharajiya Yug. The user (Bikramjeet) works from `C:\IITK\CS670\project`.
- **Mid-term report** (submitted) said: C++ with GMP; RSA-2048 blind signatures (Chaum); prime-order subgroup (256-bit q) of Z_p* for discrete-log commitments; coin = serial + `A = g^a` + `S = g^s` + bank blind signature; Schnorr-style proof of the relation `A = g^a, S = g^s, y = a*x + s`, **interactive** (commitment, challenge, response); tasks: (1) wallet and merchant terminal, (2) blind signature module, (3) ZKP module, (4) double-spend clearance, (5) integration/testing/attacks. At mid-term only task 2 was done.
- The mid-term report did **not** say where coins are stored, and it described only the blind-signature module as implemented. It claims all members contributed equally; git history is mostly one author (a point the team should fix, section 13).
- Report vs reality: the report's "commitment" step is redundant in the implementation, because `S` is already signed into the coin and acts as the Schnorr commitment (section 4.4).

---

## 2. Current status (snapshot)

Built and verified:
- Blind-signature issuance with per-denomination RSA keys (1, 5, 10).
- Withdrawal **tag** `T = H(a || s)` for tracing double spenders.
- Schnorr-style payment proof bound to the receiver; extraction of `(a, s)` from two transcripts.
- Bank: accounts, withdraw (debit + tag log + blind sign), deposit (verify, spent-coin DB, duplicate / double-spend handling, tracing), flagged accounts.
- Three networked programs: `bank_server`, `app_server`, `wallet_agent` (with local web UI at `ui/index.html`).
- Full-domain hash for signing; RNG seeded from OS entropy.
- UI features: Generate, Transfer (live protocol steps), Redeem, **Deposit** (pays the coin to yourself and redeems it), "allow re-spending a spent coin" demo toggle, history list.
- Usernames: letters/digits/underscore, 3-20 chars, case-insensitive unique.
- Paying yourself is allowed.

Not built (see sections 12 and 13): SQLite for bank/app (they still use JSON files), coins following the login (encrypted vault), cut-and-choose, TLS, "what the bank sees" panel, final report, secure-random for all secrets, encrypting the local wallet file.

Git: `main` = `origin/main` = `ee5fc42`. Working tree clean at the time of writing (this file was added after).

---

## 3. Architecture

```
 Wallet agent (one per user, on the user's machine)    App server (:8000)          Bank server (:9000)
 - ALL client-side cryptography (GMP/OpenSSL)          - signup/login              - RSA key per denomination
 - SQLite: <data-dir>/<username>.db                    - user -> bank account      - accounts / balances
     coins + secrets (a,s), received payments,         - withdraw/redeem gateway   - withdrawal tag log
     history                                           - transfer message relay    - spent-coin database
 - local web UI  http://127.0.0.1:8081/                  (mailbox per user)        - double-spend tracing
 - JSON API /api/...                                   - stores NO coin data       - flagged accounts
```

- Everything runs on one machine for the demo, on `127.0.0.1`. Plain HTTP. All programs are separate processes.
- The wallet agent talks only to the app server. The app server talks to the bank with a shared secret header `X-Internal-Key` (default `dev-internal-key`). The bank is not meant to be reachable by users.
- During a **transfer** two wallet agents talk to each other **through the app server's mailbox**; the bank is not contacted (this is the "offline" property: no bank contact while paying).
- The app server **takes the account name from the session**, never from the request body, when it calls the bank. So a user can only withdraw from their own account, and only redeem transcripts that name them as receiver.

Trust model (assumptions):
- Users may be malicious (double-spend, forged responses, replays, malformed values).
- App and bank operators are assumed honest-but-curious: they follow the protocol and do not log transfers. If they colluded they could correlate payments by timing and denomination. The app server does see, during a transfer, the coin and who paid whom.
- Blindness (bank cannot link a coin to its withdrawal) is a cryptographic property and holds even if the bank is curious.

---

## 4. Cryptography, exactly

### 4.1 Parameters

| Item | Full (default for servers) | `--fast` (server flag, e2e) | Unit tests |
|---|---|---|---|
| Subgroup order q | 256 bit | 128 bit | 64 bit |
| Field prime p | 3072 bit | 512 bit | 256 bit |
| RSA modulus n | 2048 bit | 1024 bit | 512 bit |
| RSA public exponent | 65537 (hex `10001`) | same | same |

- Group `(p, q, g)`: `q` random prime, `p = k*q + 1` prime with exact bit length, `g = h^((p-1)/q) mod p != 1`. Generated once on the bank's first start and persisted. Not the verifiable seeded FIPS 186 procedure.
- One independent RSA keypair per denomination (1, 5, 10). A coin's value is **not** in the signed message; it is determined by which key produced a valid signature. The coin carries `denomination` only so a verifier knows which public key to check.
- `demo_interactive` still uses reduced sizes (q 96, p 512, RSA 1024); the report's Figure 1 came from it. `demo_issuance` uses full size.
- Full-size first start of the bank takes about 2 seconds.

### 4.2 Coin

```
Coin { serial: string (128-bit random, lowercase hex), A = g^a mod p, S = g^s mod p,
       signature: RSA blind-signature value, denomination: int }
```
Secrets `a, s` are random in `[1, q-1]` and stay in the wallet (`WalletCoin`). Only `A`, `S` appear in the coin.

### 4.3 Withdrawal (blind signature + tag)

Wallet side (`Wallet::prepare_withdrawal`):
1. Sample `a, s` uniform in `[1, q-1]`; `A = g^a`, `S = g^s`; random 128-bit `serial`.
2. `m = FDH_n(serial, A, S)` (full-domain hash, below) with `n` = modulus of the requested denomination.
3. Random `r` coprime to `n`; blinded message `m' = m * r^e mod n`.
4. Tag `T = H_tag(a, s)` (below).
5. Send `(denomination, m', T)`; keep `(serial, A, S, m, r, a, s, T)` in a `PendingWithdrawal`.

Bank side (`Bank::withdraw`, in this order, so a failure never debits or logs):
1. Reject unknown denomination.
2. Reject a tag already in the log (`"Bank: withdrawal tag already used"`).
3. Debit the account (`debit` throws on unknown account, negative amount, insufficient balance). The debit amount equals the denomination.
4. Log `hex(T) -> account`.
5. Return `s' = m'^d mod n`.

Wallet (`finish_withdrawal`): `sig = s' * r^-1 mod n`; the wallet agent verifies `sig^e mod n == m mod n` before storing; stores coin + `(a, s)`.

**Full-domain hash** (`HashUtils::coin_message(serial, A, S, n)`):
```
base   = serial + "|" + decimal(A) + "|" + decimal(S)
stream = SHA256("ghostcash-fdh|" + i + "|" + base) for i = 0,1,2,...   (concatenated)
          until it covers ceil((bitlen(n) + 128) / 8) bytes
m      = int(stream, big-endian) mod n
```
(Reason: signing a 256-bit digest of a 2048-bit modulus with textbook RSA enables forgeries from combining signed values; FDH fills the domain.) The old `hash_coin_identifier` (plain SHA-256 of the same string) still exists only for hash-sensitivity tests; it is not what is signed.

**Tag** (`HashUtils::hash_tag(a, s)`): `SHA256("ghostcash-tag|" + field(hex(a)) + field(hex(s)))` interpreted as an integer, where `field(x) = len(x) + ":" + x + "|"`. The tag never appears in a coin; only `g^a` and `g^s` do, so the tag cannot be linked to a coin until a double spend reveals `a, s`.

Why `s` is NOT the account number (rejected idea): `S = g^s` is public in every coin, so every coin would carry the same value (all payments of a user linkable), account numbers are guessable (`g^n` can be tested), and the bank can't verify `s` at withdrawal because it signs blind (a user could put someone else's account in `s` to frame them, or a random number to escape tracing).

### 4.4 Payment proof (interactive Schnorr with a signed commitment)

`S` (signed by the bank inside the coin) is the Schnorr commitment, `A` the public key. No separate commitment message is needed at payment time.

1. Payer sends the coin to the receiver.
2. Receiver (`Merchant::begin_payment`) checks: denomination known; bank signature valid, i.e. `sig^e mod n == coin_message(serial, A, S, n)`; `A` and `S` are non-trivial elements of the order-q subgroup (`1 < e < p` and `e^q mod p == 1`). Then it creates a random 128-bit hex `nonce`, a `time` string (ISO UTC in the real system), and the challenge
   `x = (SHA256("ghostcash-challenge|" + field(receiver_id) + field(time) + field(nonce)) mod (q-1)) + 1`, so `x` is in `[1, q-1]` and never 0 (x = 0 would make `y = s`, leaking `s`).
3. Receiver sends `(time, nonce)` (not `x`) to the payer.
4. Payer (`Wallet::pay`) **re-derives x itself** for the receiver it means to pay (so a challenge relayed from someone else cannot be answered), then `y = s + a*x mod q`. An honest wallet refuses a coin it has marked spent.
5. Receiver (`finish_payment`) accepts iff `g^y == S * A^x mod p`, with `y` in `[0, q)`. It stores the **transcript** `(coin, receiver_id, time, nonce, y)`.

Properties (all tested): completeness; wrong `y` rejected; `y` for a different challenge rejected; `x = 0`, `x >= q`, `y` out of range rejected; `A` or `S` outside the subgroup (0, 1, p-1, p) rejected; two transcripts with different challenges give `a = (y1-y2)/(x1-x2) mod q`, `s = y1 - a*x1 mod q`; same challenge reveals nothing; a simulator (pick `x, y`, set `S = g^y * A^-x`) produces accepting transcripts without knowing `s`, showing one transcript carries no information (honest-verifier zero knowledge).

Why the challenge contains `receiver_id`: (1) two different receivers must get different challenges, otherwise a coin double-spent at both could not be solved for `a, s`; (2) the bank recomputes `x` for the receiver named in the transcript, so a transcript copied in transit can only ever credit that receiver (a transcript with the receiver changed fails the proof).

### 4.5 Redeem (`Bank::deposit`)

Input: a `Transcript`. Steps:
1. Unknown denomination -> `Invalid("unknown denomination")`.
2. Bank signature must verify -> else `Invalid("bad bank signature")`.
3. Recompute `x = challenge(receiver_id, time, nonce)`; `Schnorr::verify` must pass -> else `Invalid("bad proof")`.
4. Look up `serial` in the spent-coin map:
   - **Not found:** receiver account must exist (else `Invalid("unknown receiver account")`, nothing stored); store the transcript; credit `receiver_id` with the denomination; `Accepted`.
   - **Found, different `A`/`S`:** `Invalid("serial already used by a different coin")`.
   - **Found, same challenge** (`x` equal): `Duplicate` (a resubmission; nobody accused, nobody credited twice).
   - **Found, different challenge:** `DoubleSpend`. Extract `(a, s)` from the two transcripts, check `g^a == A` and `g^s == S`, look up `hex(H_tag(a, s))` in the tag log. If found: record `flagged_account` and add it to the flagged set. If not found: `DoubleSpend` with empty `flagged_account` and a detail note (untraceable, e.g. the wallet lied about its tag). The second depositor is **not** credited.

Spent-coin database is keyed by **serial**.

### 4.6 Known cryptographic limitations

- **Tag is trusted (the "k = 1" simple mode).** The bank sees only the blinded `m'`, so it cannot check that the tag equals `H(a||s)` for the coin it signs. A wallet that lies about its tag double-spends and is detected but cannot be named (test `[limitation]` documents this). A dishonest bank could also log a false tag. Planned optional hardening: cut-and-choose (wallet sends `k` blinded candidates, bank opens `k-1`, cheating succeeds with probability `1/k`).
- **RNG:** GMP Mersenne Twister seeded from 32 bytes of OpenSSL `RAND_bytes` (`Rng::instance()`). Better than clock seeding but not a CSPRNG. Wallet secrets, blinding factors and RSA primes all come from it.
- **Wallet secrets stored unencrypted** in the local SQLite file.
- No TLS; plain HTTP.
- Group generation not the verifiable FIPS 186 method.
- Coins are single-use; no change; a received payment is redeemed, not re-spent.
- The bank is trusted for availability and solvency.

---

## 5. Code map

### 5.1 Library `include/ghostcash/` (header-only)

| File | Contents |
|---|---|
| `bigint.hpp` | `BigInt` RAII wrapper over `mpz_t`. Statics: `add`, `sub`, `mulmod`, `powmod`, `invmod` (throws), `mod` (result in [0,n)), `gcd`, `random_below(n, rng)` (uniform in [1,n-1]), `from_bytes` (big-endian). Members: `==`, `!=`, `to_string(base)`, `bit_length()`, public `mpz_t v`. Constructors from `long` and `(string, base)` (throws on bad numeral). |
| `rng.hpp` | `Rng::instance()` returns the shared `gmp_randstate_t&` (Mersenne Twister seeded from `RAND_bytes`); `Rng::reseed(seed)` for tests. Not thread-safe (servers guard use with a mutex). |
| `group_setup.hpp` | `GroupParams {p, q, g}`; `GroupSetup::generate(q_bits, p_bits, rng)`. |
| `rsa_keygen.hpp` | `RSAKeyPair {n, e, d, modulus_bits}`; `RSAKeyGen::generate(bits, rng)` (textbook RSA, e = 65537, d from phi(n)). |
| `hash_utils.hpp` | `hash_coin_identifier` (plain digest, not signed), `coin_message(serial,A,S,n)` (FDH, what is signed), `hash_tag(a,s)`, `hash_challenge(receiver_id,time,nonce,q)`. |
| `coin.hpp` | `struct Coin {serial, A, S, signature, denomination}`. |
| `transcript.hpp` | `struct Transcript {coin, receiver_id, time, nonce, y}` with `challenge(q)` (recomputes x). |
| `public_keys.hpp` | `PublicKeySource` interface (`has_denomination`, `public_modulus`, `public_exponent`; non-virtual `verify_check`, `verify`). `PublicKeyRing` = client-side registry (`add`, `denominations`). `Bank` implements the interface too. Wallet and Merchant take a `PublicKeySource&`, so they work from published public keys without a `Bank`. |
| `zkp.hpp` | `Schnorr`: `is_group_element`, `is_valid_challenge`, `respond(a,s,x,q)`, `verify(grp,A,S,x,y)`, `extract(grp,x1,y1,x2,y2,a_out,s_out)`. |
| `bank.hpp` | `enum DepositStatus {Accepted, Duplicate, DoubleSpend, Invalid}`; `DepositResult {status, detail, flagged_account, a, s}`; `class Bank : PublicKeySource`: `set_group`, `add_denomination`, `denominations`, `blind_sign`, `withdraw(user, denom, blinded, tag)`, `deposit(transcript)`, `is_flagged`, `flagged_accounts`, `spent_count`, `has_account`, `has_group`, `group()`, ledger: `set_balance`, `balance`, `debit`. Private: `keys_` (denom -> RSAKeyPair), `balances_`, `group_`, `tag_log_` (hex tag -> account), `spent_` (serial -> Transcript), `flagged_`. `friend struct BankPersistence` (defined in `serialize.hpp`). |
| `wallet.hpp` | `PendingWithdrawal`, `WalletCoin {coin, a, s, spent}`, `class Wallet`: `prepare_withdrawal(denom, keys, pending)`, `unblind(keys, pending, blind_sig)`, `finish_withdrawal(...)` (returns `WalletCoin`), `pay(wc, receiver_id, time, nonce, y_out)`. |
| `merchant.hpp` | `PaymentSession {coin, time, nonce, x}`; `class Merchant(receiver_id, group, keys, rng)`: `begin_payment(coin, time, session)`, `finish_payment(session, y, transcript)`. |
| `serialize.hpp` | JSON helpers in `namespace wire`: `hex`/`from_hex`, `coin_to/from_json`, `transcript_to/from_json`, `group_to/from_json`, `params_to_json`, `ring_from_json`. `struct BankPersistence {save(Bank) -> json; load(Bank&, json)}` (whole-bank JSON snapshot; to be replaced by SQLite). |

### 5.2 Programs `src/`

| File | Role |
|---|---|
| `bank_server.cpp` | HTTP bank (section 6.1). Loads `--state` JSON or generates keys (`--fast` for small sizes), snapshots after every change. Mutex around the whole `Bank`. |
| `app_server.cpp` | HTTP app server (section 6.2). Users in `--users` JSON; sessions and mailboxes in memory. |
| `wallet_agent.cpp` | Local wallet (section 6.3): SQLite `Db` class, `Agent` state, inbox long-poll thread, message handlers `on_coin/on_challenge/on_response/on_result`, HTTP API, static UI mount. |
| `net_common.hpp` | `net::Args` (`--name value` / `--flag`), `reply`, `fail` (JSON `{"error":...}`), `read_file`, `write_file_atomic` (tmp + rename), `random_hex` (OpenSSL RAND_bytes), `now_iso`. |
| `demo_issuance.cpp`, `demo_interactive.cpp`, `term_ui.hpp` | Original blind-signature demos (CLI). |

Vendored: `third_party/httplib.h` (cpp-httplib 0.15.3), `third_party/nlohmann/json.hpp` (3.11.3), `tests/third_party/catch.hpp` (Catch2 single header).

### 5.3 Other

- `ui/index.html`: single-file wallet UI (vanilla JS), served by the wallet agent. Polls `/api/state` every 2 s. Uses `el()` DOM helper (no innerHTML of dynamic data).
- `scripts/e2e.py`: end-to-end test (section 9).
- `scripts/run_demo.sh`: starts bank, app, two wallets for a manual demo.
- `scripts/time_full_start.sh`: times the bank's first start at full size.
- `Makefile`, `CMakeLists.txt`, `DESIGN.md`, `README.md`, `.gitignore`, `.gitattributes` (LF for `*.sh`, `*.py`, `Makefile`).

---

## 6. Wire protocols: what is sent when

All bodies are JSON. Big integers are **lowercase hex strings** (no `0x`). Errors are `{"error": "message"}` with a 4xx/5xx status.

### 6.1 Bank server (default port 9000)

Options: `--port 9000 --state bank_state.json --key dev-internal-key [--fast]`.
Header `X-Internal-Key: <key>` is required on everything except `/health` and `/params` (403 `"forbidden"` otherwise).

| Request | Body | Success response | Errors |
|---|---|---|---|
| `GET /health` | | `{"ok":true}` | |
| `GET /params` | | `{"group":{"p":hex,"q":hex,"g":hex},"denominations":[{"denomination":1,"n":hex,"e":"10001"},{"denomination":5,...},{"denomination":10,...}]}` | |
| `POST /accounts` (internal) | `{"name":"alice","balance":100}` | `{"ok":true}` | 409 `"account exists"`; 400 negative balance |
| `GET /accounts/<name>/balance` (internal) | | `{"balance":95}` | 400 unknown account |
| `POST /withdraw` (internal) | `{"account":"alice","denomination":5,"blinded_m":hex,"tag":hex}` | `{"blind_signature":hex}` | 400 `"Bank: unknown denomination"`, `"Bank: withdrawal tag already used"`, `"Bank: unknown account: x"`, `"Bank: insufficient balance for account: x"` |
| `POST /deposit` (internal) | `{"transcript":{"coin":{"serial":hex,"A":hex,"S":hex,"signature":hex,"denomination":5},"receiver_id":"bob","time":"2026-...Z","nonce":hex,"y":hex}}` | `{"status":"accepted"\|"duplicate"\|"double_spend"\|"invalid","detail":str,"flagged_account":str,"amount":5}` | |
| `GET /admin/state` (internal) | | `{"balances":{"alice":94,...},"flagged":["alice"],"spent_count":3}` | |

The server prints one log line per event (`[bank] alice withdrew a 5 (balance 95)`, `[bank] deposit for carol: double_spend -> flagged alice`).

### 6.2 App server (default port 8000)

Options: `--port 8000 --bank-host 127.0.0.1 --bank-port 9000 --key dev-internal-key --users users.json --start-balance 100`.
Auth: header `X-Token: <token>` (token returned by signup/login: 16 random bytes, hex; held in memory; lost on restart).

| Request | Body | Response / behaviour |
|---|---|---|
| `GET /health` | | `{"ok":true}` |
| `POST /signup` | `{"username","password"}` | Username must match `[A-Za-z0-9_]{3,20}`, password >= 4 chars, unique ignoring case (409 `"username taken"`). Stores `{salt, hash}` (PBKDF2-HMAC-SHA256, 20000 iterations, 16-byte random salt, 32-byte hash, constant-time compare), opens the bank account with the start balance, returns `{"token","username"}`. |
| `POST /login` | `{"username","password"}` | Case-insensitive match; returns the **registered spelling** in `username`. 401 `"wrong username or password"`. |
| `GET /params` | | Proxy of bank `/params`. |
| `GET /balance` (token) | | Proxy of `/accounts/<me>/balance`. |
| `POST /withdraw` (token) | `{"denomination","blinded_m","tag"}` | Forwards to bank `/withdraw` with `account` = session user. Returns the bank's response. |
| `POST /redeem` (token) | `{"transcript":{...}}` | 403 unless `transcript.receiver_id` == session user; else forwards to bank `/deposit`. |
| `GET /users/<name>` (token) | | `{"exists":bool,"online":bool,"username":"canonical"}`. "Online" = polled the inbox within the last 30 s. |
| `POST /transfer/send` (token) | `{"to","type","transfer_id","payload"}` | `type` in `coin\|challenge\|response\|accepted\|reject`. Resolves `to` case-insensitively. 404 `"unknown user: x"`, 409 `"<name> is offline"`, 429 inbox full (100). Queues `{"from":<session user>,"type","transfer_id","payload"}` in the target's mailbox. Returns `{"ok":true}`. |
| `GET /transfer/inbox?wait=N` (token) | | Long poll (default 20 s, max 30). Updates the caller's "last seen". Returns `{"messages":[{from,type,transfer_id,payload},...]}` and clears the mailbox. |

### 6.3 Wallet agent (default port 8081)

Options: `--port 8081 --app-host 127.0.0.1 --app-port 8000 --data ./wallet-data --ui ./ui`. Listens on 127.0.0.1 only. One logged-in user at a time per agent. All handlers hold a global mutex (the transfer handler releases it while waiting).

| Request | Body | Response |
|---|---|---|
| `POST /api/signup`, `/api/login` | `{"username","password"}` | `{"ok":true,"username":<canonical>}`. Calls the app server, fetches `/params`, builds the group and `PublicKeyRing`, opens `<data>/<username>.db`, creates the `Wallet` and `Merchant`, starts the inbox thread. |
| `POST /api/logout` | | `{"ok":true}` |
| `GET /api/state` | | `{"logged_in":false}` or `{"logged_in":true,"username","bank_balance":int\|null,"denominations":[1,5,10],"coins":[{"id","denomination","serial","spent","created"}],"received":[{"id","from","amount","status","note","created"}],"history":[{"ts","kind","detail"}]}`. If the app server rejects the token (401, e.g. after an app restart) the agent clears its session and answers `logged_in:false`. |
| `POST /api/generate` | `{"denomination":5}` | `{"ok":true,"serial","denomination"}`; errors pass through the bank's message. |
| `POST /api/transfer` | `{"to":"bob","coin_id":1,"force":false}` | Blocks up to 30 s. `{"ok":bool,"message":str,"steps":[str,...]}`. `force:true` lets an already-spent coin be paid again (demo double spend). Errors: 400 invalid username / spent coin / coin already in a transfer; 404 unknown user or coin; 409 `"<name> is offline"`. Paying yourself is allowed. |
| `POST /api/redeem` | `{}` or `{"id":N}` | `{"results":[{"id","amount","status","detail"}]}` where status is the bank's `accepted\|duplicate\|double_spend\|invalid` (or `error`). |

UI **Deposit** button = JS: `POST /api/transfer {to: me, coin_id}` then `GET /api/state`, pick the newest pending received item from yourself, `POST /api/redeem {id}`. No new server endpoint.

### 6.4 Sequence: withdrawal (Generate)

```
UI -> wallet:  POST /api/generate {denomination:5}
wallet:        a,s,serial,A,S,m=FDH_n(...), r, m'=m*r^e, T=H(a,s)
wallet -> app: POST /withdraw {denomination:5, blinded_m:hex(m'), tag:hex(T)}   [X-Token]
app -> bank:   POST /withdraw {account:<session user>, denomination, blinded_m, tag}  [X-Internal-Key]
bank:          check denom, tag unused, debit, log T->account, s' = m'^d
bank -> app -> wallet: {blind_signature: hex(s')}
wallet:        sig = s'*r^-1; verify sig^e == m; INSERT coin (+ a, s) into SQLite; history "generated"
```
The bank and app never see `serial`, `A`, `S`, `m`, `r`, `a`, `s`.

### 6.5 Sequence: transfer (payer P, receiver R, both logged in, both agents polling their inbox)

Messages are relayed `POST /transfer/send` and delivered by `GET /transfer/inbox`. `transfer_id` = 8 random bytes hex, chosen by the payer. `from` is added by the app server from the sender's session.

```
1. P -> R  type "coin"      payload {"coin":{serial,A,S,signature,denomination}}
   R: if serial already in its transcripts -> reply "reject" {"reason":"coin already received"}
      Merchant.begin_payment: signature + subgroup checks; make time,nonce; remember session
2. R -> P  type "challenge" payload {"time":"...Z","nonce":hex}
   P: derive x = H(R, time, nonce); y = s + a*x mod q; mark coin spent in SQLite
3. P -> R  type "response"  payload {"y":hex}
   R: Merchant.finish_payment (g^y == S*A^x); INSERT transcript (status "pending", from_user = P)
4. R -> P  type "accepted"  payload {}      (or "reject" {"reason":"response did not verify"})
   P: transfer call returns {"ok":true, steps:[...]}
```
Steps shown in the UI: "sent the coin to R" / "R verified the coin and sent a challenge" / "answered the challenge (y = s + a*x)" / "R verified the proof and accepted the payment". No bank contact.

### 6.6 Sequence: redeem

```
UI -> wallet:  POST /api/redeem {id?}
wallet:        for each pending transcript:
wallet -> app: POST /redeem {transcript}        [X-Token]; app checks receiver_id == session user
app -> bank:   POST /deposit {transcript}
bank:          verify sig + proof; spent DB lookup; credit / duplicate / double_spend / invalid
wallet:        status accepted|duplicate -> transcript "redeemed"; double_spend|invalid -> "rejected"
               (transport errors leave it "pending" to retry); history entry added
```

### 6.7 Sequence: double-spend demo (what the bank does)

Alice pays coin X to Bob (tid1) and, with "allow re-spending" ticked, to Carol (tid2). The two challenges differ because the receiver id is in them. Bob redeems first -> `accepted`. Carol redeems -> bank finds serial X, different challenge, extracts `(a, s)`, hashes to the tag logged at Alice's withdrawal, logs `flagged alice`, replies `double_spend`, Carol is not credited. A wallet that lied about its tag gives `double_spend` with empty `flagged_account`.

---

## 7. Storage (current)

### 7.1 Bank: JSON snapshot (`--state`, default `bank_state.json`; the demo uses `demo-data/bank_state.json`)

```json
{ "group": {"p":hex,"q":hex,"g":hex},
  "keys": [{"denomination":1,"n":hex,"e":hex,"d":hex,"bits":2048}, ...],
  "balances": {"alice": 94, ...},
  "tag_log": {"<hex tag>": "alice", ...},
  "spent": {"<serial>": <transcript json>, ...},
  "flagged": ["alice"] }
```
Rewritten atomically (tmp + rename) after every change. Contains the **private** RSA exponents.

### 7.2 App server: `--users` JSON (`users.json`)

`{ "<username>": {"salt": hex, "hash": hex}, ... }`. Sessions and mailboxes are in memory only.

### 7.3 Wallet: SQLite per user, `<data-dir>/<username>.db` (username in its registered spelling)

```sql
coins(id INTEGER PK AUTOINCREMENT, serial TEXT UNIQUE, denom INTEGER, coin_json TEXT,
      a TEXT, s TEXT, spent INTEGER DEFAULT 0, created TEXT)          -- a, s in hex, UNENCRYPTED
transcripts(id INTEGER PK AUTOINCREMENT, serial TEXT UNIQUE, from_user TEXT, amount INTEGER,
            transcript_json TEXT, status TEXT DEFAULT 'pending',      -- pending|redeemed|rejected
            note TEXT DEFAULT '', created TEXT)
history(id INTEGER PK AUTOINCREMENT, ts TEXT, kind TEXT, detail TEXT)
```
The demo script uses `demo-data/wallet-a/` and `demo-data/wallet-b/`. **Coins exist only in the data directory where they were generated**; another data folder/machine shows an empty coin list for the same account (the bank balance still shows, since it is at the bank).

---

## 8. Build, run, demo

Environment (the user's machine): Windows 11; project at `C:\IITK\CS670\project`; **build and run inside WSL Ubuntu** (`wsl -d Ubuntu`, user `bsingh23`), project path there is `/mnt/c/IITK/CS670/project`. WSL has g++ 13, make, cmake, `libgmp-dev`, `libssl-dev`, `libsqlite3-dev`, python3 installed. The Windows MinGW g++ (6.3) is too old for the C++17 code.

```sh
make                  # demos, unit tests, bank_server, app_server, wallet_agent  (binaries in build/)
make run-tests        # unit tests  ->  "All tests passed (376 assertions in 74 test cases)"
make e2e              # builds servers, runs scripts/e2e.py (small sizes); E2E_FULL=1 for full sizes
scripts/run_demo.sh   # bank :9000, app :8000, wallet A :8081, wallet B :8082; --fast for small sizes
./build/wallet_agent --port 8083 --data demo-data/wallet-c    # a third wallet
```
CMake also builds everything (`cmake -S . -B build && cmake --build build -j`).

Manual demo (README has the same): open the wallet URLs in separate browser windows; sign up two or three users (start balance 100); Generate a 5-coin (balance 95); Transfer to another user (live steps); that user Redeems (balance 105); Deposit button returns an unspent coin to your own balance; double spend: pay a coin to B, tick "allow re-spending an already spent coin", pay it to C, redeem at B then C -> C is rejected and `logs/bank.log` shows the flagged account.

Ports used by tests: e2e uses bank 19000, app 18000, wallets 18081-18084.

---

## 9. Tests

Unit tests (Catch2) in `tests/`, 74 test cases:
- `test_bigint.cpp` (11), `test_group_setup.cpp` (5), `test_rsa_keygen.cpp` (4), `test_hash_utils.cpp` (8, includes FDH tests: deterministic, in [0,n), fills >2000 bits for a 2047-bit n, depends on every field and on n).
- `test_bank_wallet.cpp` (17): honest issuance, blindness, denominations, tamper/replay/other-bank attacks, ledger.
- `test_zkp.cpp` (13): completeness, rejection cases, extraction, simulator, challenge/tag hash properties.
- `test_clearance.cpp` (17): end-to-end in-process: withdraw/pay/redeem; double spend traced to the withdrawer; only the cheater is flagged; duplicate vs accusation; forged response; redirected transcript; wallet won't answer another receiver's challenge; forged signature; wrong denomination; honest wallet refuses re-spend; unknown receiver account; insufficient balance leaves no trace; repeated tag rejected; unknown denomination; the tag-lie limitation.

End-to-end `scripts/e2e.py` (starts real servers on temp ports; about 45 checks): [1] accounts (signup incl. capitalised "Erin", duplicate rejected, wrong password), [2] generate coins, [3] transfer and redeem, [4] double spend detected and traced (bank flags exactly alice), [5] forged/malformed requests (forged transcript invalid, redeem for someone else's id refused, withdraw without session refused, bank refuses calls without the internal key), [6] unknown/offline receivers and insufficient balance, [7] capitals / case-insensitive / paying yourself, [8] state survives a bank restart, [9] app server restart (wallet falls back to sign-in; accounts and local coins survive).

UI was exercised in a real browser (Puppeteer click-through): signup, generate, transfer (with different capitalisation), redeem, self-transfer, logout/login, Deposit. Those browser scripts are not in the repo.

---

## 10. History of notable bugs and design corrections (so they are not repeated)

- Wallet originally discarded `a, s` after computing `A, S` (fixed: `WalletCoin`).
- Signing a 256-bit hash with textbook RSA (fixed: FDH).
- Clock-seeded RNG (fixed: OS entropy seed).
- App server crashed when reloading `users.json` on restart: `for (auto& [k,v] : json::parse(raw).items())` dangles the temporary. Keep the parsed document alive in a variable. (Found by a restart test that e2e originally lacked.)
- Rejected idea: `s` = account number (see 4.3).
- A custodial/hosted wallet (server holds coins) was considered and rejected for the main design, because the operator would see every coin; see section 11.

---

## 11. Decisions made

1. **Client-side wallet**: secrets and cryptography run on the user's machine (local C++ wallet agent with a local web UI). Reason: a wallet run by the operator would see and be able to spend every coin and would remove the double-spend demo.
2. **App server is a gateway and relay**, bank is a separate server, bank reachable only with the internal key; the account comes from the session.
3. **Simple tag mode (k = 1)** for tracing; cut-and-choose optional later.
4. **Interactive proof**, receiver must be online; receiver-bound challenge.
5. **Transfer means pay**; a received payment must be redeemed; coins are not passed on.
6. **Deposit = pay yourself then redeem**; safe because the bank's spent database is the authority. A user who already paid the coin elsewhere and then deposits it is a double spender and is flagged.
7. **Usernames**: letters/digits/underscore, case-insensitive uniqueness, registered spelling preserved; the challenge is bound to the registered spelling.
8. **Demo runs on one laptop**; large-scale public hosting is out of scope for now. (GitHub Pages cannot host this: it only serves static files; an option later is a container on a host such as Render/Fly.io, or a tunnel for a temporary public link.)
9. **SQLite for everything** (the user chose this): bank and app server should move off JSON files.
10. **Push straight to `main`.**
11. Skip edge cases about the same account on two devices at once, and other web-development concerns.
12. The user wants **coins to follow the login** (log in anywhere, see your coins), kept private from the operator. Preferred direction so far: keep the local wallet and add an **encrypted vault** (details in 12.2). The alternatives were: a browser (JavaScript) wallet + encrypted vault, and a server-held (custodial) wallet; the user's reaction was to keep scope small and focus on the cryptographic demo.

---

## 12. Planned work (proposed, not built) and designs

### 12.1 SQLite for bank and app
Bank tables (suggested):
```sql
meta(key PK, value)                          -- 'group' -> {p,q,g}
keys(denom PK, n, e, d, bits)
accounts(name PK, balance INTEGER NOT NULL)
tag_log(tag PK, account NOT NULL, created)
spent(serial PK, receiver, denom, transcript_json, created)
flagged(account PK, reason, created)
```
Each mutating request (open account, withdraw, deposit) runs in one transaction (`BEGIN IMMEDIATE ... COMMIT`); on load, rebuild the in-memory `Bank` from the rows (needs restore helpers on `BankPersistence`, which is a friend of `Bank`). Shared `Db` wrapper (move it from `wallet_agent.cpp` into a header, add a transaction helper). App server: `users(username PK COLLATE NOCASE, salt, hash, created)` plus vault storage (12.2). Avoid WAL mode (problems on WSL's `/mnt/c`). Keep the HTTP APIs unchanged so `e2e.py` keeps working (change `--state` to a `--db` option in the scripts).

### 12.2 Coins follow the login: encrypted vault (preferred)
- The wallet serialises its coin store (coins with `a, s`, transcripts, history) to JSON and encrypts it with AES-256-GCM using a key derived from the password; the app server stores only the ciphertext + a version number. Log in with an empty data folder -> download, decrypt, restore.
- Keep login and encryption keys separate so the server never learns the encryption key: client derives `auth_key = PBKDF2(password, "ghostcash-auth|"+lower(username))` (sent as the "password") and `vault_key = PBKDF2(password, "ghostcash-vault|"+lower(username))` (never sent). The server hashes `auth_key` again with its own salt.
- Endpoints (suggested): `GET /vault` -> `{version, ciphertext, nonce}`; `PUT /vault {base_version, ciphertext, nonce}` accepted only if `base_version` equals the stored version (simple optimistic check); wallet pushes after each change and pulls on login. Ignore simultaneous multi-device edits (user said skip).
- Limits to state: a forgotten password loses the coins (unless a recovery key is added); a malicious operator could still change the served code; the server still sees metadata.
- The same encryption code can also encrypt the local wallet file at rest (item 13.5).

### 12.3 Demo polish
- "What the bank sees" panel: show the bank's records (accounts, withdrawal log with only tags/blinded values, spent serials, flagged accounts) so the unlinkability is visible (the withdrawal list and the spent list share nothing matchable). Needs a read-only bank view endpoint (e.g. via the app server, demo only).
- One-command demo start (exists: `scripts/run_demo.sh`) and a written demo script/walkthrough.

### 12.4 Optional
- Cut-and-choose (k > 1), TLS, a Dockerfile, an "amount" transfer that auto-picks coins, native Windows support.

---

## 13. Open decisions (with simple rationale and a suggestion)

Highest priority first (the user wants these written simply for teammates who missed the discussion):

1. **Trusting the tag.** A wallet can send a fake tag; then a double spend is detected but cannot be traced to a person. *Suggestion:* keep simple mode and state the limit; add cut-and-choose only if time remains.
2. **Random numbers.** Secrets come from GMP's Mersenne Twister (seeded well, but not designed for secrets). *Suggestion:* draw all secrets (a, s, r, serials, RSA primes, nonces) from OpenSSL `RAND_bytes` directly (replace `mpz_urandomm/urandomb` uses behind `BigInt::random_below` and the keygen/group code). Small, contained change.
3. **App server sees who pays whom.** *Suggestion:* keep; state the honest-operator assumption in the report.
4. **No TLS.** *Suggestion:* localhost-only for the demo, state it; add TLS only if hosting publicly.
5. **Wallet file unencrypted** (anyone with the file can spend the coins). *Suggestion:* encrypt it with a password-derived key; reuse the vault encryption.
6. **Coins follow the login** (12.2). *Suggestion:* encrypted vault, ignoring multi-device conflicts.
7. **Databases** (12.1). *Suggestion:* SQLite for bank and app.
8. **Website vs local program.** *Suggestion:* keep the local program, skip a public website and the JavaScript rewrite.
9. **"What the bank sees" panel + demo script** (12.3). *Suggestion:* add.
10. **Receiver must be online.** *Suggestion:* keep (matches the mid-term report); an offline (non-interactive) version is future work.
11. **Whole coins only (1, 5, 10).** *Suggestion:* keep; optionally add a coin-picking helper.
12. **Group generation is not the verifiable FIPS method.** *Suggestion:* keep, state it.
13. **Report and contributions.** The mid-term report covers only part of the system and the git history is mostly one author. *Suggestion:* write the final report from the real system (architecture, threat model, security argument: unforgeability, blindness, double-spend detection and tracing, zero knowledge; limitations), and have each member commit their own piece from now on.
14. **Windows.** Runs on Linux/WSL only. *Suggestion:* document WSL steps; no native port.

---

## 14. Practical notes for a new Claude session in this repo

- Do all builds/tests/runs in WSL (`wsl -d Ubuntu -- bash -lc 'cd /mnt/c/IITK/CS670/project && ...'`). Background processes started inside one `wsl` command die when it exits; to keep a stack alive for a browser test, run it in a long-lived background job.
- Use **Windows git** (from the Bash tool) for commits. WSL's git shows every file as modified because of CRLF/LF differences. Git identity configured: `bikkygill05` / `bsingh23@iitk.ac.in`. **Do not add `Co-Authored-By: Claude ...` or "Generated with Claude" lines** to commits or PR descriptions: the user does not want Claude listed as a contributor on GitHub (the trailers were stripped from history once and `main` was force-pushed; see section 0).
- Windows git has `core.autocrlf=true`; `.gitattributes` pins LF for scripts and the Makefile (they must stay LF to run under WSL).
- When editing files via Python snippets, a literal two-character `\n` in a heredoc can get collapsed by the tool; use a placeholder and replace with `chr(92)+'n'`.
- Headless Chrome UI tests: Chrome at `C:\Program Files\Google\Chrome\Application\chrome.exe`, `puppeteer-core` installed in a scratch folder; use **one browser instance per wallet page** (a background tab never gets frames and hangs on type/click).
- Before changing cryptography or wire formats, run `make run-tests` and `make e2e`; both must stay green. When adding bank persistence, keep the bank HTTP API stable.
- Vendored headers are large; they compile slowly (each of the three servers takes about 30 s to build).
