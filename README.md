# GhostCash

A demo implementation of a Chaumian RSA blind-signature e-cash scheme
(bank/wallet issuance protocol), built on GMP for big-integer arithmetic
and OpenSSL (libcrypto) for SHA-256 hashing.

## Dependencies

- A C++17 compiler (g++ or clang++)
- [GMP](https://gmplib.org/) (`gmp.h` + `libgmp`)
- OpenSSL's `libcrypto` (`openssl/sha.h` + `libcrypto`)
- Either `make`, or CMake >= 3.16 (either works — pick one)

Install the two libraries first:

| Platform              | Command                                              |
|-----------------------|-------------------------------------------------------|
| Debian / Ubuntu       | `sudo apt-get install libgmp-dev libssl-dev`          |
| Fedora / RHEL         | `sudo dnf install gmp-devel openssl-devel`            |
| Arch                  | `sudo pacman -S gmp openssl`                          |
| macOS (Homebrew)      | `brew install gmp openssl@3`                          |

## Building with `make`

```sh
make               # builds demo_issuance, demo_interactive, run_tests
make run           # build + run the plain demo
make run-interactive  # build + run the narrated, step-by-step walkthrough
make run-tests
make clean
```

### The interactive walkthrough

`demo_interactive` prints one coin withdrawal end-to-end — including the
bank debiting the withdrawing user's simulated account — tagged by who
actually sees each piece of data:

- `WALLET` — serial, commitments, real identifier `m`, blinding factor `r`,
  and the final unblinded signature. **Never sent anywhere.**
- `WIRE` — the only two values actually sent to the bank: the requested
  denomination and the blinded message `m'`.
- `BANK` — the account debit, and blind-signing with the key for that
  denomination. Note the account debit and the cryptographic signing are
  two separate steps (see `bank.hpp`): the bank can know *whose* account
  it charged without learning *which coin identifier* it just blindly
  signed for that account.
- `VERIFY` — the actual RSA check spelled out (`lhs = s^e mod n` vs
  `rhs = m mod n`), computed against **every** denomination's key, so you
  can see the coin only matches the one it was actually signed under, plus
  a tamper check (flipping a digit in the serial) shown the same way.

```sh
make run-interactive               # prompts for a denomination (1/5/10)
./build/demo_interactive 10         # skip the prompt, withdraw a "10"
./build/demo_interactive --auto     # never prompt (defaults to 1); good for
                                     # piping into a file or a screenshot script
```

Output is ~45 lines, designed to fit in a single terminal screenshot.

### Denominations

`Bank` holds one independent RSA keypair per denomination (`add_denomination`);
a coin's value is never written into the signed message itself — it's
entirely determined by which key produced a valid signature over it. See
`tests/test_bank_wallet.cpp` for the tests that pin this down (a coin signed
as a "5" fails verification against the "1" key, etc.).

The Makefile auto-detects GMP/OpenSSL's include and library paths, in this
order:

1. `pkg-config` (works out of the box on most Linux distros, and for
   Homebrew's OpenSSL, which ships a `.pc` file).
2. `brew --prefix gmp` / `brew --prefix openssl` (covers Homebrew's GMP,
   which has no `.pc` file, and is a second chance for OpenSSL on macOS).
   This correctly resolves to `/opt/homebrew` on Apple Silicon or
   `/usr/local` on Intel Macs — whichever `brew` itself is using.
3. Plain `-lgmp` / `-lcrypto` with no extra `-I`/`-L`, for setups where the
   headers/libs already live on the compiler's default search path.

If none of those find your install (e.g. a from-source install in a custom
location), point the Makefile at it directly:

```sh
make GMP_PREFIX=/path/to/gmp SSL_PREFIX=/path/to/openssl
```

Run `make print-config` to see exactly which flags were auto-detected —
handy for diagnosing a build failure on an unfamiliar machine.

## Building with CMake

```sh
cmake -S . -B build
cmake --build build -j
./build/run_tests
./build/demo_issuance
```

`OpenSSL` is located via CMake's built-in `FindOpenSSL` module. `GMP` has no
official CMake package, so it's located manually via `pkg-config` (if
available) and a set of standard/Homebrew search paths. If it's installed
somewhere else:

```sh
cmake -S . -B build -DGMP_ROOT=/path/to/gmp
```

(For OpenSSL in a nonstandard location, CMake's own `-DOPENSSL_ROOT_DIR=...`
works as usual.)

## Layout

```
include/ghostcash/   public headers (bigint, group setup, RSA keygen,
                     blind-signature bank/wallet/coin, hashing, RNG)
src/demo_issuance.cpp     minimal end-to-end demo of the issuance protocol
src/demo_interactive.cpp  narrated, screenshot-friendly walkthrough (see above)
src/term_ui.hpp           terminal color/formatting helper, used only by
                          demo_interactive (not part of the ghostcash library)
tests/                    Catch2-based unit tests
```
