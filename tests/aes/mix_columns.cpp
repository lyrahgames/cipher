#include <doctest/doctest.h>
//
#include <array>
#include <iomanip>
#include <iostream>
#include <random>
//
#include <lyrahgames/cipher/aes/mix_columns.hpp>

using namespace std;
using namespace lyrahgames::cipher;

SCENARIO("AES 128-bit MixColumns based on uint8_t Bijectivity") {
  mt19937 rng{random_device{}()};
  array<uint8_t, 16> src, mix, inv;
  constexpr size_t n = 1'000'000;
  for (size_t i = 0; i < n; ++i) {
    for (auto& x : src) x = rng();

    aes::mix_columns_128(src.data(), mix.data());
    aes::inv_mix_columns_128(mix.data(), inv.data());

    REQUIRE(inv == src);
  }
}

SCENARIO(
    "AES 128-bit MixColumns based on uint8_t Correctness"
    " by Using NIST FIPS PUB 197 Advanced Encryption Standard (AES)"
    " Examples Appendix B") {
  array<uint8_t, 16> a, b;

  for (const auto& [src, dst] : {
           pair<array<uint8_t, 16>, array<uint8_t, 16>>       //
           {{0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae,  //
             0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5},
            {0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a,  //
             0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06, 0x26, 0x4c}},

           {{0x49, 0xdb, 0x87, 0x3b, 0x45, 0x39, 0x53, 0x89,  //
             0x7f, 0x02, 0xd2, 0xf1, 0x77, 0xde, 0x96, 0x1a},
            {0x58, 0x4d, 0xca, 0xf1, 0x1b, 0x4b, 0x5a, 0xac,  //
             0xdb, 0xe7, 0xca, 0xa8, 0x1b, 0x6b, 0xb0, 0xe5}},
       }) {
    aes::mix_columns_128(src.data(), a.data());
    aes::inv_mix_columns_128(dst.data(), b.data());

    REQUIRE(dst == a);
    REQUIRE(src == b);
  }
}

SCENARIO("AES 128-bit MixColumns based on uint64_t Correctness") {
  mt19937 rng{random_device{}()};

  array<uint64_t, 2> src, mix8, inv8;
  array<uint64_t, 2> mix64, inv64;

  constexpr size_t n = 1'000'000;

  for (size_t i = 0; i < n; ++i) {
    for (auto& x : src) x = rng();

    aes::mix_columns_128((const uint64_t*)src.data(), (uint64_t*)mix64.data());
    aes::mix_columns_128((const uint8_t*)src.data(), (uint8_t*)mix8.data());
    REQUIRE(mix8 == mix64);

    aes::inv_mix_columns_128((const uint64_t*)src.data(),
                             (uint64_t*)inv64.data());
    aes::inv_mix_columns_128((const uint8_t*)src.data(), (uint8_t*)inv8.data());
    REQUIRE(inv8 == inv64);
  }
}
