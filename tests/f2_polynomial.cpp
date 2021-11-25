#include <random>
//
#include <doctest/doctest.h>
//
#include <lyrahgames/cipher/cipher.hpp>

using namespace std;
using namespace lyrahgames;

SCENARIO("Extented Euclidean Algorithm and Bezout's Identity") {
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

SCENARIO("F(2) Polynomials mul-divmod Identity") {
  mt19937 rng{random_device{}()};
  const size_t n = 1'000'000;
  for (size_t i = 0; i < n; ++i) {
    auto x = rng();
    auto y = rng();
    // y should not be zero because division by zero is not allowed.
    while (!y) y = rng();

    const auto [q, r] = cipher::f2_polynomial_divmod(x, y);
    const auto t = cipher::f2_polynomial_mul(q, y) ^ r;
    CHECK(x == t);
  }
}

SCENARIO("divmod Operation for Polynomials over F(2)") {
  {
    const auto [q, r] = cipher::f2_polynomial_divmod(0b10110000u, 0b00011011u);
    CHECK(q == 0b00001100u);
    CHECK(r == 0b00000100u);
  }
}

SCENARIO("Division and Modulo of Monomials in F(2^8)") {
  // Choose irreducible modulo polynomial over F(2).
  // p(x) = x^8 + x^4 + x^3 + x + 1
  const auto p = 0b1'0001'1011u;

  // Iterate over given tests.
  // m(x) = q(x) * p(x) + r(x)
  for (const auto [x, a, b] :
       {
           tuple
           // x^8 = 1 * p(x) + (x^4 + x^3 + x + 1)
           {256u << 0, 0b0000'0001u, 0b0001'1011u},
           // x^9 = x * p(x) + (x^5 + x^4 + x^2 + x)
           {256u << 1, 0b0000'0010u, 0b0011'0110u},
           // x^10 = x^2 * p(x) + (x^6 + x^5 + x^3 + x^2)
           {256u << 2, 0b0000'0100u, 0b0110'1100u},
           // x^11 = x^3 * p(x) + (x^7 + x^6 + x^4 + x^3)
           {256u << 3, 0b0000'1000u, 0b1101'1000u},
           // x^12 = (x^4 + 1) * p(x) + (x^7 + x^5 + x^3 + x + 1)
           {256u << 4, 0b0001'0001u, 0b1010'1011u},
           // x^13 = (x^5 + x + 1) * p(x) + (x^6 + x^3 + x^2 + 1)
           {256u << 5, 0b0010'0011u, 0b0100'1101u},
           // x^14 = (x^6 + x^2 + x) * p(x) + (x^7 + x^4 + x^3 + x)
           {256u << 6, 0b0100'0110u, 0b1001'1010u},
           // x^15 = (x^7 + x^3 + x^2 + 1) * p(x) + (x^5 + x^3 + x^2 + x + 1)
           {256u << 7, 0b1000'1101u, 0b0010'1111u},
       })

  {
    const auto [q, r] = cipher::f2_polynomial_divmod(x, p);
    CHECK(q == a);
    CHECK(r == b);
  }
}

SCENARIO("Multiplicative Inverse of Polynomials in F(2^8)") {
  // Choose irreducible modulo polynomial over F(2).
  // p(x) = x^8 + x^4 + x^3 + x + 1
  // == 0b1'0001'1011 == 0x11b
  const auto p = 0b1'0001'1011u;

  // Iterate over given tests.
  for (uint16_t x = 0; const auto x_1 : array<uint16_t, 256>{
                           0x00, 0x01, 0x8d, 0xf6, 0xcb, 0x52, 0x7b, 0xd1,
                           0xe8, 0x4f, 0x29, 0xc0, 0xb0, 0xe1, 0xe5, 0xc7,

                           0x74, 0xb4, 0xaa, 0x4b, 0x99, 0x2b, 0x60, 0x5f,
                           0x58, 0x3f, 0xfd, 0xcc, 0xff, 0x40, 0xee, 0xb2,

                           0x3a, 0x6e, 0x5a, 0xf1, 0x55, 0x4d, 0xa8, 0xc9,
                           0xc1, 0x0a, 0x98, 0x15, 0x30, 0x44, 0xa2, 0xc2,

                           0x2c, 0x45, 0x92, 0x6c, 0xf3, 0x39, 0x66, 0x42,
                           0xf2, 0x35, 0x20, 0x6f, 0x77, 0xbb, 0x59, 0x19,

                           0x1d, 0xfe, 0x37, 0x67, 0x2d, 0x31, 0xf5, 0x69,
                           0xa7, 0x64, 0xab, 0x13, 0x54, 0x25, 0xe9, 0x09,

                           0xed, 0x5c, 0x05, 0xca, 0x4c, 0x24, 0x87, 0xbf,
                           0x18, 0x3e, 0x22, 0xf0, 0x51, 0xec, 0x61, 0x17,

                           0x16, 0x5e, 0xaf, 0xd3, 0x49, 0xa6, 0x36, 0x43,
                           0xf4, 0x47, 0x91, 0xdf, 0x33, 0x93, 0x21, 0x3b,

                           0x79, 0xb7, 0x97, 0x85, 0x10, 0xb5, 0xba, 0x3c,
                           0xb6, 0x70, 0xd0, 0x06, 0xa1, 0xfa, 0x81, 0x82,

                           0x83, 0x7e, 0x7f, 0x80, 0x96, 0x73, 0xbe, 0x56,
                           0x9b, 0x9e, 0x95, 0xd9, 0xf7, 0x02, 0xb9, 0xa4,

                           0xde, 0x6a, 0x32, 0x6d, 0xd8, 0x8a, 0x84, 0x72,
                           0x2a, 0x14, 0x9f, 0x88, 0xf9, 0xdc, 0x89, 0x9a,

                           0xfb, 0x7c, 0x2e, 0xc3, 0x8f, 0xb8, 0x65, 0x48,
                           0x26, 0xc8, 0x12, 0x4a, 0xce, 0xe7, 0xd2, 0x62,

                           0x0c, 0xe0, 0x1f, 0xef, 0x11, 0x75, 0x78, 0x71,
                           0xa5, 0x8e, 0x76, 0x3d, 0xbd, 0xbc, 0x86, 0x57,

                           0x0b, 0x28, 0x2f, 0xa3, 0xda, 0xd4, 0xe4, 0x0f,
                           0xa9, 0x27, 0x53, 0x04, 0x1b, 0xfc, 0xac, 0xe6,

                           0x7a, 0x07, 0xae, 0x63, 0xc5, 0xdb, 0xe2, 0xea,
                           0x94, 0x8b, 0xc4, 0xd5, 0x9d, 0xf8, 0x90, 0x6b,

                           0xb1, 0x0d, 0xd6, 0xeb, 0xc6, 0x0e, 0xcf, 0xad,
                           0x08, 0x4e, 0xd7, 0xe3, 0x5d, 0x50, 0x1e, 0xb3,

                           0x5b, 0x23, 0x38, 0x34, 0x68, 0x46, 0x03, 0x8c,
                           0xdd, 0x9c, 0x7d, 0xa0, 0xcd, 0x1a, 0x41, 0x1c}) {
    const uint16_t p = 0b1'0001'1011u;
    CAPTURE(x);
    CHECK(x_1 == cipher::f2_polynomial_inv(x, p));
    CHECK(x == cipher::f2_polynomial_inv(x_1, p));
    ++x;
  }
}
