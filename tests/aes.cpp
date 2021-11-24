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

  // multiplicative inverse for F(2^8)
  // x^8 + x^4 + x^3 + x + 1
  // == 0b1'0001'1011 == 0x11b
  for (const auto [x, x_1] : {
           tuple<uint32_t, uint32_t>  //
           {0x00, 0x00},
           {0x01, 0x01},
           {0x02, 0x8d},
           {0x03, 0xf6},
           {0x04, 0xcb},
           {0x05, 0x52},
           {0x06, 0x7b},
           {0x07, 0xd1},
           {0x08, 0xe8},
           {0x09, 0x4f},
           {0x0a, 0x29},
           {0x0b, 0xc0},
           {0x0c, 0xb0},
           {0x0d, 0xe1},
           {0x0e, 0xe5},
           {0x0f, 0xc7},

           {0x10, 0x74},
           {0x11, 0xb4},
           {0x12, 0xaa},
           {0x13, 0x4b},
           {0x14, 0x99},
           {0x15, 0x2b},
           {0x16, 0x60},
           {0x17, 0x5f},
           {0x18, 0x58},
           {0x19, 0x3f},
           {0x1a, 0xfd},
           {0x1b, 0xcc},
           {0x1c, 0xff},
           {0x1d, 0x40},
           {0x1e, 0xee},
           {0x1f, 0xb2},

           {0x20, 0x3a},
           {0x21, 0x6e},
           {0x22, 0x5a},
           {0x23, 0xf1},
           {0x24, 0x55},
           {0x25, 0x4d},
           {0x26, 0xa8},
           {0x27, 0xc9},
           {0x28, 0xc1},
           {0x29, 0x0a},
           {0x2a, 0x98},
           {0x2b, 0x15},
           {0x2c, 0x30},
           {0x2d, 0x44},
           {0x2e, 0xa2},
           {0x2f, 0xc2},

           {0x30, 0x2c},
           {0x31, 0x45},
           {0x32, 0x92},
           {0x33, 0x6c},
           {0x34, 0xf3},
           {0x35, 0x39},
           {0x36, 0x66},
           {0x37, 0x42},
           {0x38, 0xf2},
           {0x39, 0x35},
           {0x3a, 0x20},
           {0x3b, 0x6f},
           {0x3c, 0x77},
           {0x3d, 0xbb},
           {0x3e, 0x59},
           {0x3f, 0x19},

           {0x40, 0x1d},
           {0x41, 0xfe},
           {0x42, 0x37},
           {0x43, 0x67},
           {0x44, 0x2d},
           {0x45, 0x31},
           {0x46, 0xf5},
           {0x47, 0x69},
           {0x48, 0xa7},
           {0x49, 0x64},
           {0x4a, 0xab},
           {0x4b, 0x13},
           {0x4c, 0x54},
           {0x4d, 0x25},
           {0x4e, 0xe9},
           {0x4f, 0x09},

           {0x50, 0xed},
           {0x51, 0x5c},
           {0x52, 0x05},
           {0x53, 0xca},
           {0x54, 0x4c},
           {0x55, 0x24},
           {0x56, 0x87},
           {0x57, 0xbf},
           {0x58, 0x18},
           {0x59, 0x3e},
           {0x5a, 0x22},
           {0x5b, 0xf0},
           {0x5c, 0x51},
           {0x5d, 0xec},
           {0x5e, 0x61},
           {0x5f, 0x17},

           {0x60, 0x16},
           {0x61, 0x5e},
           {0x62, 0xaf},
           {0x63, 0xd3},
           {0x64, 0x49},
           {0x65, 0xa6},
           {0x66, 0x36},
           {0x67, 0x43},
           {0x68, 0xf4},
           {0x69, 0x47},
           {0x6a, 0x91},
           {0x6b, 0xdf},
           {0x6c, 0x33},
           {0x6d, 0x93},
           {0x6e, 0x21},
           {0x6f, 0x3b},

           {0x70, 0x79},
           {0x71, 0xb7},
           {0x72, 0x97},
           {0x73, 0x85},
           {0x74, 0x10},
           {0x75, 0xb5},
           {0x76, 0xba},
           {0x77, 0x3c},
           {0x78, 0xb6},
           {0x79, 0x70},
           {0x7a, 0xd0},
           {0x7b, 0x06},
           {0x7c, 0xa1},
           {0x7d, 0xfa},
           {0x7e, 0x81},
           {0x7f, 0x82},

           {0x80, 0x83},
           {0x81, 0x7e},
           {0x82, 0x7f},
           {0x83, 0x80},
           {0x84, 0x96},
           {0x85, 0x73},
           {0x86, 0xbe},
           {0x87, 0x56},
           {0x88, 0x9b},
           {0x89, 0x9e},
           {0x8a, 0x95},
           {0x8b, 0xd9},
           {0x8c, 0xf7},
           {0x8d, 0x02},
           {0x8e, 0xb9},
           {0x8f, 0xa4},

           {0x90, 0xde},
           {0x91, 0x6a},
           {0x92, 0x32},
           {0x93, 0x6d},
           {0x94, 0xd8},
           {0x95, 0x8a},
           {0x96, 0x84},
           {0x97, 0x72},
           {0x98, 0x2a},
           {0x99, 0x14},
           {0x9a, 0x9f},
           {0x9b, 0x88},
           {0x9c, 0xf9},
           {0x9d, 0xdc},
           {0x9e, 0x89},
           {0x9f, 0x9a},

           {0xa0, 0xfb},
           {0xa1, 0x7c},
           {0xa2, 0x2e},
           {0xa3, 0xc3},
           {0xa4, 0x8f},
           {0xa5, 0xb8},
           {0xa6, 0x65},
           {0xa7, 0x48},
           {0xa8, 0x26},
           {0xa9, 0xc8},
           {0xaa, 0x12},
           {0xab, 0x4a},
           {0xac, 0xce},
           {0xad, 0xe7},
           {0xae, 0xd2},
           {0xaf, 0x62},

           {0xb0, 0x0c},
           {0xb1, 0xe0},
           {0xb2, 0x1f},
           {0xb3, 0xef},
           {0xb4, 0x11},
           {0xb5, 0x75},
           {0xb6, 0x78},
           {0xb7, 0x71},
           {0xb8, 0xa5},
           {0xb9, 0x8e},
           {0xba, 0x76},
           {0xbb, 0x3d},
           {0xbc, 0xbd},
           {0xbd, 0xbc},
           {0xbe, 0x86},
           {0xbf, 0x57},

           {0xc0, 0x0b},
           {0xc1, 0x28},
           {0xc2, 0x2f},
           {0xc3, 0xa3},
           {0xc4, 0xda},
           {0xc5, 0xd4},
           {0xc6, 0xe4},
           {0xc7, 0x0f},
           {0xc8, 0xa9},
           {0xc9, 0x27},
           {0xca, 0x53},
           {0xcb, 0x04},
           {0xcc, 0x1b},
           {0xcd, 0xfc},
           {0xce, 0xac},
           {0xcf, 0xe6},

           {0xd0, 0x7a},
           {0xd1, 0x07},
           {0xd2, 0xae},
           {0xd3, 0x63},
           {0xd4, 0xc5},
           {0xd5, 0xdb},
           {0xd6, 0xe2},
           {0xd7, 0xea},
           {0xd8, 0x94},
           {0xd9, 0x8b},
           {0xda, 0xc4},
           {0xdb, 0xd5},
           {0xdc, 0x9d},
           {0xdd, 0xf8},
           {0xde, 0x90},
           {0xdf, 0x6b},

           {0xe0, 0xb1},
           {0xe1, 0x0d},
           {0xe2, 0xd6},
           {0xe3, 0xeb},
           {0xe4, 0xc6},
           {0xe5, 0x0e},
           {0xe6, 0xcf},
           {0xe7, 0xad},
           {0xe8, 0x08},
           {0xe9, 0x4e},
           {0xea, 0xd7},
           {0xeb, 0xe3},
           {0xec, 0x5d},
           {0xed, 0x50},
           {0xee, 0x1e},
           {0xef, 0xb3},

           {0xf0, 0x5b},
           {0xf1, 0x23},
           {0xf2, 0x38},
           {0xf3, 0x34},
           {0xf4, 0x68},
           {0xf5, 0x46},
           {0xf6, 0x03},
           {0xf7, 0x8c},
           {0xf8, 0xdd},
           {0xf9, 0x9c},
           {0xfa, 0x7d},
           {0xfb, 0xa0},
           {0xfc, 0xcd},
           {0xfd, 0x1a},
           {0xfe, 0x41},
           {0xff, 0x1c},
       }) {
    const auto p = 0b1'0001'1011u;
    CAPTURE(x);
    CHECK(x_1 == cipher::f2_polynom_inv(x, p));
  }
}
