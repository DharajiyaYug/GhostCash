// coin.hpp
//
// A GhostCash coin, per the "Coin structure" specification: a serial number,
// the discrete-log commitments A = g^a, S = g^s, and the bank's blind
// signature over H(serial || A || S). Note: at this stage A and S are
// generated as plain random group elements standing in for the eventual
// Schnorr-proof commitments -- the ZKP module (next milestone) is what will
// give them their full meaning as a = coin secret, s = identity secret.
//
// `denomination` records which of the bank's per-denomination RSA keys was
// used to sign this coin. It's carried alongside the coin purely so a
// verifier knows which public key to check the signature against -- the
// denomination itself is never part of the hashed/signed message; the
// binding comes entirely from which key produced a valid signature.

#pragma once

#include "ghostcash/bigint.hpp"
#include <string>

struct Coin {
    std::string serial;
    BigInt A;           // g^a
    BigInt S;           // g^s
    BigInt signature;   // bank's signature over H(serial || A || S)
    int denomination;   // which denomination key this was signed under
};
