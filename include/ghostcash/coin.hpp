#pragma once

#include "ghostcash/bigint.hpp"
#include <string>

struct Coin {
    std::string serial;
    BigInt A;
    BigInt S;
    BigInt signature;
    int denomination = 0;
};
