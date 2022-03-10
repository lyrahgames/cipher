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

SCENARIO("Miller-Rabin Primality Test with GMP") {
  gmp_randclass rng(gmp_randinit_mt);
  rng.seed(random_device{}());
  const auto random = [&rng](const mpz_class& n) { return rng.get_z_range(n); };

  const size_t n = 1000;
  for (size_t i = 0; i < n; ++i) {
    const mpz_class x = rng.get_z_bits(512);
    CAPTURE(x);

    // const auto is_prime = naive::is_prime(x);
    const auto is_prime = miller_rabin::is_probable_prime(x, 5, random);
    if (is_prime) {
      MESSAGE("\nRandom 512-bit Prime Number: ");
      // CHECK(naive::is_prime(x));
    }

    // CHECK(is_prime == miller_rabin::is_probable_prime(x, 5, random));
  }
}
