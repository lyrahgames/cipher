#include <doctest/doctest.h>
//
#include <iomanip>
#include <iostream>
#include <random>
//
#include <lyrahgames/cipher/aes/mul2.hpp>

using namespace std;
using namespace lyrahgames::cipher;

SCENARIO("AES SIMD-like Rijndael's Galois Field Multiplication by 2") {
  mt19937 rng{random_device{}()};

  constexpr size_t n = 1'000'000;
  for (size_t i = 0; i < n; ++i) {
    uint64_t x = (rng() << 32) | rng();
    const auto y = aes::mul2(x);
    const auto z = (uint64_t(aes::mul2(uint8_t(x >> 56))) << 56) |
                   (uint64_t(aes::mul2(uint8_t(x >> 48))) << 48) |
                   (uint64_t(aes::mul2(uint8_t(x >> 40))) << 40) |
                   (uint64_t(aes::mul2(uint8_t(x >> 32))) << 32) |
                   (uint64_t(aes::mul2(uint8_t(x >> 24))) << 24) |
                   (uint64_t(aes::mul2(uint8_t(x >> 16))) << 16) |
                   (uint64_t(aes::mul2(uint8_t(x >> 8))) << 8) |
                   uint64_t(aes::mul2(uint8_t(x)));

    // MESSAGE(hex << setw(16) << setfill('0') << y);
    // MESSAGE(hex << setw(16) << setfill('0') << z);
    REQUIRE(y == z);
  }
}
