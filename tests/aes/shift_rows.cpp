#include <doctest/doctest.h>
//
#include <array>
#include <iomanip>
#include <iostream>
#include <random>
//
#include <lyrahgames/cipher/aes/shift_rows.hpp>

using namespace std;
using namespace lyrahgames::cipher;

SCENARIO("AES 128-bit ShiftRows based on uint8_t Bijectivity") {
  for (size_t i = 0; i < 16; ++i) {
    CHECK(aes::inv_shift_rows_128_index(aes::shift_rows_128_index(i)) == i);
    CHECK(aes::shift_rows_128_index(aes::inv_shift_rows_128_index(i)) == i);
  }

  mt19937 rng{random_device{}()};
  array<uint8_t, 16> a{}, b{}, c{};

  constexpr size_t n = 100'000;
  for (size_t i = 0; i < n; ++i) {
    for (auto& x : a) x = rng();

    aes::shift_rows_128(a.data(), b.data());
    aes::inv_shift_rows_128(b.data(), c.data());

    REQUIRE(a == c);
  }
}
