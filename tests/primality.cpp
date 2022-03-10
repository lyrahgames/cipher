#include <doctest/doctest.h>
//
#include <iomanip>
#include <iostream>
#include <random>
//
#include <gmpxx.h>
//
#include <lyrahgames/cipher/primality.hpp>

using namespace std;
using namespace lyrahgames::cipher;

SCENARIO("Miller-Rabin Primality Test") {
  mt19937 rng{random_device{}()};
  const auto random = [&rng](size_t n) {
    return uniform_int_distribution<size_t>{0, n - 1}(rng);
  };

  const size_t n = 10'000;
  for (size_t i = 0; i < n; ++i) {
    CAPTURE(i);
    CHECK(naive::is_prime(i) == miller_rabin::is_probable_prime(i, 5, random));
  }
}
