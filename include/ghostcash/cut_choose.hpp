#pragma once

#include "ghostcash/bigint.hpp"
#include <string>
#include <vector>

constexpr int kDefaultWithdrawCandidates = 10;

struct WithdrawCandidate {
    BigInt blinded_m;
    BigInt tag;
};

struct CandidateOpening {
    size_t index = 0;
    std::string serial;
    BigInt a, s, r;
};
