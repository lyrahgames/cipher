#pragma once
#include <cstdint>
//
#include <lyrahgames/cipher/aes/mul2.hpp>

namespace lyrahgames::cipher {

namespace aes {

constexpr void mix_columns_128(const uint8_t src[16],
                               uint8_t dst[16]) noexcept {
  constexpr auto mix_column = [](const uint8_t src[4],
                                 uint8_t col[4]) noexcept {
    {
      const uint8_t x = src[0];
      const uint8_t x2 = mul2(x);
      const uint8_t x3 = x2 ^ x;
      col[0] = x2;
      col[1] = x;
      col[2] = x;
      col[3] = x3;
    }
    {
      const uint8_t x = src[1];
      const uint8_t x2 = mul2(x);
      const uint8_t x3 = x2 ^ x;
      col[0] ^= x3;
      col[1] ^= x2;
      col[2] ^= x;
      col[3] ^= x;
    }
    {
      const uint8_t x = src[2];
      const uint8_t x2 = mul2(x);
      const uint8_t x3 = x2 ^ x;
      col[0] ^= x;
      col[1] ^= x3;
      col[2] ^= x2;
      col[3] ^= x;
    }
    {
      const uint8_t x = src[3];
      const uint8_t x2 = mul2(x);
      const uint8_t x3 = x2 ^ x;
      col[0] ^= x;
      col[1] ^= x;
      col[2] ^= x3;
      col[3] ^= x2;
    }
  };

  mix_column(&src[0], &dst[0]);
  mix_column(&src[4], &dst[4]);
  mix_column(&src[8], &dst[8]);
  mix_column(&src[12], &dst[12]);
}

constexpr void inv_mix_columns_128(const uint8_t src[16],
                                   uint8_t dst[16]) noexcept {
  constexpr auto inv_mix_column = [](const uint8_t src[4],
                                     uint8_t col[4]) noexcept {
    {
      const uint8_t x = src[0];
      const uint8_t x2 = mul2(x);
      const uint8_t x4 = mul2(x2);
      const uint8_t x8 = mul2(x4);
      const uint8_t x9 = x8 ^ x;
      const uint8_t x11 = x9 ^ x2;
      const uint8_t x13 = x9 ^ x4;
      const uint8_t x14 = x8 ^ x4 ^ x2;
      col[0] = x14;
      col[1] = x9;
      col[2] = x13;
      col[3] = x11;
    }
    {
      const uint8_t x = src[1];
      const uint8_t x2 = mul2(x);
      const uint8_t x4 = mul2(x2);
      const uint8_t x8 = mul2(x4);
      const uint8_t x9 = x8 ^ x;
      const uint8_t x11 = x9 ^ x2;
      const uint8_t x13 = x9 ^ x4;
      const uint8_t x14 = x8 ^ x4 ^ x2;
      col[0] ^= x11;
      col[1] ^= x14;
      col[2] ^= x9;
      col[3] ^= x13;
    }
    {
      const uint8_t x = src[2];
      const uint8_t x2 = mul2(x);
      const uint8_t x4 = mul2(x2);
      const uint8_t x8 = mul2(x4);
      const uint8_t x9 = x8 ^ x;
      const uint8_t x11 = x9 ^ x2;
      const uint8_t x13 = x9 ^ x4;
      const uint8_t x14 = x8 ^ x4 ^ x2;
      col[0] ^= x13;
      col[1] ^= x11;
      col[2] ^= x14;
      col[3] ^= x9;
    }
    {
      const uint8_t x = src[3];
      const uint8_t x2 = mul2(x);
      const uint8_t x4 = mul2(x2);
      const uint8_t x8 = mul2(x4);
      const uint8_t x9 = x8 ^ x;
      const uint8_t x11 = x9 ^ x2;
      const uint8_t x13 = x9 ^ x4;
      const uint8_t x14 = x8 ^ x4 ^ x2;
      col[0] ^= x9;
      col[1] ^= x13;
      col[2] ^= x11;
      col[3] ^= x14;
    }
  };

  inv_mix_column(&src[0], &dst[0]);
  inv_mix_column(&src[4], &dst[4]);
  inv_mix_column(&src[8], &dst[8]);
  inv_mix_column(&src[12], &dst[12]);
}

constexpr auto mix_columns_128(const uint64_t src[2],
                               uint64_t dst[2]) noexcept {
  constexpr auto mix = [](const uint64_t x) -> uint64_t {
    const auto x2 = mul2(x);
    const auto x3 = x2 ^ x;
    uint64_t result =
        ((x << 8) & 0xffffff00'ffffff00) | ((x >> 24) & 0x000000ff'000000ff);
    result ^=
        ((x << 16) & 0xffff0000'ffff0000) | ((x >> 16) & 0x0000ffff'0000ffff);
    result ^= x2;
    result ^=
        ((x3 << 24) & 0xff000000'ff000000) | ((x3 >> 8) & 0x00ffffff'00ffffff);
    return result;
  };

  dst[0] = mix(src[0]);
  dst[1] = mix(src[1]);
}

constexpr void inv_mix_columns_128(const uint64_t src[2],
                                   uint64_t dst[2]) noexcept {
  constexpr auto mix = [](const uint64_t x) -> uint64_t {
    const auto x2 = mul2(x);
    const auto x4 = mul2(x2);
    const auto x8 = mul2(x4);
    const auto x9 = x8 ^ x;
    const auto x11 = x9 ^ x2;
    const auto x13 = x9 ^ x4;
    const auto x14 = x8 ^ x4 ^ x2;
    uint64_t result = ((x9 << 8) & 0xffffff00'ffffff00) |  //
                      ((x9 >> 24) & 0x000000ff'000000ff);
    result ^= ((x11 << 24) & 0xff000000'ff000000) |
              ((x11 >> 8) & 0x00ffffff'00ffffff);
    result ^= ((x13 << 16) & 0xffff0000'ffff0000) |
              ((x13 >> 16) & 0x0000ffff'0000ffff);
    result ^= x14;
    return result;
  };

  dst[0] = mix(src[0]);
  dst[1] = mix(src[1]);
}

}  // namespace aes

}  // namespace lyrahgames::cipher
