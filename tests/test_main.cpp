// test_main.cpp
//
// Defines Catch2's main() exactly once for the whole test binary. Kept
// separate from actual test cases so that file never needs to change as
// tests are added.

#define CATCH_CONFIG_MAIN
#include "third_party/catch.hpp"
