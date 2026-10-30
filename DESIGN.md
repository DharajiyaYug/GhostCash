# GhostCash: final design (v1)

Decisions below are final for the build unless marked "open".

## Threat model
- Users may be malicious: double-spend, forged responses, replayed transcripts, forged signatures, malformed group elements.
- The app and bank operators are honest-but-curious and do not log transfers. If they colluded they could correlate payments by timing and denomination. This is stated as a limitation, not claimed away.
- Blindness is cryptographic: the bank and app never see a coin at withdrawal.

## Components (three programs plus a shared library)

```
 wallet agent (per user, local)      app server (:8000)            bank server (:9000)
 - C++ crypto (GMP)                  - signup/login, sessions      - RSA key per denomination
 - local SQLite: coins, secrets,     - user -> bank account map    - accounts + balances
   transcripts, history              - forwards withdraw/redeem    - withdrawal log (tag -> acct)
 - web UI on http://localhost:8081   - routes transfers (push)     - spent DB keyed by serial
 - Generate / Transfer / Redeem      - stores NO coin data         - extraction + tracing
```

- Shared library `include/ghostcash/`: the existing blind-signature code plus `zkp`, `merchant`, `cutchoose`, serialization.
- Transport: HTTP + JSON (cpp-httplib, nlohmann/json, both vendored header-only). The receiver gets pushes through long-polling an inbox endpoint.
- Storage (as built): SQLite for the wallet's local coin store; the bank and the app server keep a JSON state file that is rewritten atomically after every change. Group parameters are generated once on the bank's first start and persisted in its state file.
- Big integers are hex strings in JSON.
- TLS is added last; no protocol logic depends on it.

## Parameters
- Group: q = 256-bit, p = 3072-bit, generated once. RSA: 2048-bit, one key per denomination (1, 5, 10).
- Tests and a `--fast` flag use reduced sizes. The spec sizes are used for the real servers and the demo.
- Withdrawal default is the simple mode (`k = 1`): the wallet sends the tag T = H(a || s) with its request and the bank trusts it. Cut-and-choose with k > 1 (e.g. k = 10) is an optional hardening, built only after the end-to-end system works.

## Protocol

### Registration
User signs up in the app with a username and password and a bank account. The app maps user to bank account. The wallet agent stores only the session token.

### Generate coin (withdraw)
Default (k = 1): the wallet makes one coin, sends (denom, m', T) to the bank, the bank debits the account, logs T -> account, and returns the blind signature. Steps 3 and 4 below (index j, opening) are skipped. The steps below describe the optional cut-and-choose hardening (k > 1).
1. Wallet makes k candidates. Each has fresh a_i, s_i, serial_i, A_i = g^a_i, S_i = g^s_i, m_i = FDH(serial_i || A_i || S_i), blinding r_i, m'_i = m_i * r_i^e mod n, and tag T_i = H(a_i || s_i).
2. Wallet sends (denom, {m'_i, T_i}) through the app to the bank.
3. Bank replies with random index j.
4. Wallet opens all i != j: serial_i, a_i, s_i, r_i.
5. Bank checks A_i, S_i, m_i, blinding and tag for every opened candidate. If all pass it debits the account, logs T_j -> account, and returns s'_j = (m'_j)^d.
6. Wallet unblinds, stores coin (serial, A, S, sig, denom) and secrets (a, s) in local SQLite.
Cheating wallet succeeds with probability 1/k. Failed check: reject the withdrawal and flag the account.

### Transfer (pay)
Payer and receiver are both logged in. Messages go through the app.
1. Payer sends the coin to the receiver's handle.
2. Receiver verifies the bank signature (under the claimed denomination key), checks A, S are in the order-q subgroup and not 1, then replies with challenge x = H(receiver_id, time, nonce) mod q, x != 0.
3. Payer recomputes x for the intended receiver, then answers y = s + a*x mod q.
4. Receiver checks g^y == S * A^x, stores the transcript (coin, receiver_id, time, nonce, y), and shows "received, pending redeem".
5. Payer marks the coin spent. No bank contact in this step.

### Redeem
Receiver submits the transcript through the app to the bank. The bank re-verifies signature and proof, recomputes x from (receiver_id, time, nonce), then looks up the serial:
- new: store transcript, credit receiver_id.
- same serial, identical (x, y): duplicate deposit, reject, no accusation.
- same serial, different x: double spend. Extract a = (y1-y2)/(x1-x2), s = y1 - a*x1. Check g^a = A and g^s = S. Look up H(a || s) in the withdrawal log, flag that account, reject the second deposit.

A received transcript is not spendable. To spend again, the receiver generates new coins.

## UI (served by the wallet agent)
Pages: login, balance (bank balance + local coins), Generate (pick denomination), Transfer (pick coin, enter receiver username, live step log of commitment/challenge/response), Redeem (pending transcripts), History. A "malicious mode" toggle re-pays an already spent coin, for the demo.

## Tests
- Unit tests per module: bigint, group, rsa, hash/FDH, zkp, cut-and-choose, merchant, clearance, serialization.
- Attack suite: double spend at two receivers (traced to the right account), forged y, y for a different challenge, replayed transcript, forged signature, wrong denomination, small-subgroup A, x = 0, repeated deposit, cheating tag at k > 1, insufficient balance.
- One end-to-end script: start bank, app and two wallet agents, run generate, transfer, redeem, then the double-spend scenario.

## Fixes to the existing code (Phase 0) -- status
1. Wallet keeps a and s (WalletCoin). Done.
2. Full-domain hash for the signed message (SHA-256 in counter mode into Z_n). Done.
3. RNG seeded from OpenSSL RAND_bytes instead of the clock. Done, but GMP's Mersenne Twister is still not a CSPRNG (documented in rng.hpp).
4. Subgroup and x != 0 checks on the verifier side. Done.
5. Parameter sizes: the servers use the specified sizes (256-bit q, 3072-bit p, 2048-bit RSA) by default and `--fast` for small ones; the unit tests use small sizes for speed; `demo_interactive` still uses reduced sizes.

## Build order and status
1. Phase 0 fixes. Done.
2. zkp. Done.
3. merchant + clearance with the tag lookup (in-process, tested). Done.
4. Serialization + persistence. Done.
5. Bank server. Done.
6. App server. Done.
7. Wallet agent + web UI. Done.
8. End-to-end script (`scripts/e2e.py`, also at full size with `E2E_FULL=1`). Done.
9. Optional: cut-and-choose (k > 1), TLS. Not done.

Not browser-tested: the web UI renders correctly against live data (headless Chrome screenshot) but its button handlers have not been clicked through in a browser; the end-to-end script exercises the same JSON API the buttons call.

## Open
- Deadline unknown; build order is not dated.
- The tag + cut-and-choose identity binding is our own CFN-style adaptation and has not been checked by the TA.
- A dishonest bank could log a false tag against an account. Accepted limitation (a registered public key U = g^u would fix it).
