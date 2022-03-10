#include <doctest/doctest.h>
//
#include <iomanip>
#include <iostream>
#include <random>
//
#include <lyrahgames/cipher/euclid.hpp>

using namespace std;
using namespace lyrahgames::cipher;

SCENARIO("Extented Euclidean Algorithm and Bezout's Identity") {
  mt19937 rng{random_device{}()};
  uniform_int_distribution<int> dist{1, 100'000};
  const auto random = [&] { return dist(rng); };

  const size_t n = 1'000'000;

  for (size_t i = 0; i < n; ++i) {
    const auto p = random();
    const auto q = random();
    const auto [d, a, b] = gcd_bezout(p, q);

    CHECK(d == gcd(p, q));
    CHECK(a * p + b * q == d);
  }
}
