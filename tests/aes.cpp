#include <iostream>
#include <numeric>
#include <random>
//
#include <doctest/doctest.h>
//
#include <lyrahgames/cipher/cipher.hpp>

using namespace std;
using namespace lyrahgames;

SCENARIO("") {
  mt19937 rng{random_device{}()};
  uniform_int_distribution<int> dist{1, 100'000};
  const auto random = [&] { return dist(rng); };

  const size_t n = 1'000'000;

  for (size_t i = 0; i < n; ++i) {
    const auto p = random();
    const auto q = random();
    const auto [d, a, b] = cipher::egcd(p, q);

    CHECK(d == gcd(p, q));
    CHECK(a * p + b * q == d);
  }
}

SCENARIO("") {
  mt19937 rng{random_device{}()};
  const size_t n = 1'000'000;
  for (size_t i = 0; i < n; ++i) {
    auto x = rng();
    auto y = rng();
    while (!y)  // y should not be zero
      y = rng();

    const auto [q, r] = cipher::f2_polynom_divmod(x, y);
    const auto t = cipher::f2_polynom_mul(q, y) ^ r;
    CHECK(x == t);
  }

  // modulo of high monomials for F(2^8)
  for (const auto [x, a, b] :
       {
           tuple                                     //
           {256u << 0, 0b0000'0001u, 0b0001'1011u},  // x^8
           {256u << 1, 0b0000'0010u, 0b0011'0110u},  // x^9
           {256u << 2, 0b0000'0100u, 0b0110'1100u},  // x^10
           {256u << 3, 0b0000'1000u, 0b1101'1000u},  // x^11
           {256u << 4, 0b0001'0001u, 0b1010'1011u},  // x^12
           {256u << 5, 0b0010'0011u, 0b0100'1101u},  // x^13
           {256u << 6, 0b0100'0110u, 0b1001'1010u},  // x^14
           {256u << 7, 0b1000'1101u, 0b0010'1111u},  // x^15
       })

  {
    // irreducible F(2) polynom in F(2^8):
    // x^8 + x^4 + x^3 + x + 1
    const auto [q, r] = cipher::f2_polynom_divmod(x, 0b1'0001'1011u);
    CHECK(q == a);
    CHECK(r == b);
  }

  {
    const auto [q, r] = cipher::f2_polynom_divmod(0b10110000u, 0b00011011u);
    CHECK(q == 0b00001100u);
    CHECK(r == 0b00000100u);
  }
}
