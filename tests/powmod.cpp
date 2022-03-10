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

SCENARIO("Modular Exponentiation with 64-bit Unsigned Integers") {
  mt19937 rng{random_device{}()};
  constexpr int n = 10'0000;
  for (int i = 0; i < n; ++i) {
    const size_t x = uint32_t(rng());
    const size_t n = uint32_t(rng());
    size_t z = 1;
    for (size_t e = 0; e < 100; ++e) {
      CHECK(powmod(x, e, n) == z);
      z = (z * x) % n;
    }
  }
}

SCENARIO("Modular Exponentiation with GNU Multiple Precision") {
  gmp_randclass rng{gmp_randinit_default};
  constexpr int n = 1000;
  for (int i = 0; i < n; ++i) {
    const mpz_class x = rng.get_z_bits(512);
    const mpz_class n = rng.get_z_bits(512);
    mpz_class z = 1;
    for (mpz_class e = 0; e < 100; ++e) {
      CHECK(powmod(x, e, n) == z);
      z = (z * x) % n;
    }
  }
}
