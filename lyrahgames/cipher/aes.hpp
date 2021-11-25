#pragma once
#include <bit>
#include <tuple>
//
#include <lyrahgames/cipher/f2_polynomial.hpp>
#include <lyrahgames/cipher/galois.hpp>
#include <lyrahgames/cipher/meta.hpp>

namespace lyrahgames::cipher {

namespace aes {

constexpr auto substitution(uint8_t x) noexcept -> uint8_t {
  using namespace std;
  const auto p = 0b1'0001'1011u;
  const uint8_t b = f2_polynomial_inv(uint16_t(x), uint16_t(p));
  const uint8_t s =
      b ^ rotl(b, 1) ^ rotl(b, 2) ^ rotl(b, 3) ^ rotl(b, 4) ^ uint8_t(0x63);
  return s;
}

constexpr auto inv_substitution(uint8_t x) noexcept -> uint8_t {
  using namespace std;
  const uint8_t b = rotl(x, 1) ^ rotl(x, 3) ^ rotl(x, 6) ^ uint8_t(0x05);
  const auto p = 0b1'0001'1011u;
  const uint8_t s = f2_polynomial_inv(uint16_t(b), uint16_t(p));
  return s;
}

constexpr int shift_row_permutation[] = {
    0, 5, 10, 15,  //
    1, 6, 11, 12,  //
    2, 7, 8,  13,  //
    3, 4, 9,  14,  //
};

constexpr void mix_column(uint8_t* col) noexcept {
  uint8_t a[4], b[4], c[4];
  for (int i = 0; i < 4; ++i) {
    a[i] = col[i];
    b[i] = uint8_t(galois8(2) * galois8(a[i]));
    c[i] = uint8_t(galois8(3) * galois8(a[i]));
  }
  col[0] = b[0] ^ c[1] ^ a[2] ^ a[3];
  col[1] = a[0] ^ b[1] ^ c[2] ^ a[3];
  col[2] = a[0] ^ a[1] ^ b[2] ^ c[3];
  col[3] = c[0] ^ a[1] ^ a[2] ^ b[3];
}

constexpr void inv_mix_column(uint8_t* col) noexcept {
  uint8_t a[4], b[4], c[4], d[4];
  for (int i = 0; i < 4; ++i) {
    a[i] = uint8_t(galois8(9) * galois8(col[i]));
    b[i] = uint8_t(galois8(11) * galois8(col[i]));
    c[i] = uint8_t(galois8(13) * galois8(col[i]));
    d[i] = uint8_t(galois8(14) * galois8(col[i]));
  }
  col[0] = d[0] ^ b[1] ^ c[2] ^ a[3];
  col[1] = a[0] ^ d[1] ^ b[2] ^ c[3];
  col[2] = c[0] ^ a[1] ^ d[2] ^ b[3];
  col[3] = b[0] ^ c[1] ^ a[2] ^ d[3];
}

}  // namespace aes

}  // namespace lyrahgames::cipher
