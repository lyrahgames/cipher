#include <doctest/doctest.h>
//
#include <iomanip>
#include <iostream>
#include <random>
//
#include <gmpxx.h>
//
#include <lyrahgames/cipher/powmod.hpp>

using namespace std;
using namespace lyrahgames::cipher;

SCENARIO("Modular Exponentiation") {
  mt19937 rng{random_device{}()};

  constexpr int n = 10'0000;
  for (int i = 0; i < n; ++i) {
    const size_t x = rng();
    const size_t n = rng();
    size_t z = 1;
    for (size_t e = 0; e < 100; ++e) {
      CHECK(powmod(x, e, n) == z);
      z = (z * x) % n;
    }
  }
}
