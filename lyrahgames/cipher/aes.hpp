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

//
constexpr int shift_row_permutation[] = {
    0,  5,  10, 15,  //
    4,  9,  14, 3,   //
    8,  13, 2,  7,   //
    12, 1,  6,  11,  //
};
constexpr int inv_shift_row_permutation[] = {
    0,  13, 10, 7,   //
    4,  1,  14, 11,  //
    8,  5,  2,  15,  //
    12, 9,  6,  3,   //
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

constexpr void add_round_key(uint8_t* data, uint8_t* key) noexcept {
  for (int i = 0; i < 16; ++i) data[i] ^= key[i];
}

constexpr void sub_bytes(uint8_t* data) noexcept {
  for (int i = 0; i < 16; ++i) data[i] = substitution(data[i]);
}

constexpr void inv_sub_bytes(uint8_t* data) noexcept {
  for (int i = 0; i < 16; ++i) data[i] = inv_substitution(data[i]);
}

constexpr void shift_rows(uint8_t* data) noexcept {
  uint8_t t[16];
  for (int i = 0; i < 16; ++i) t[i] = data[i];
  for (int i = 0; i < 16; ++i) data[i] = t[shift_row_permutation[i]];
}

constexpr void inv_shift_rows(uint8_t* data) noexcept {
  uint8_t t[16];
  for (int i = 0; i < 16; ++i) t[i] = data[i];
  for (int i = 0; i < 16; ++i) data[i] = t[inv_shift_row_permutation[i]];
}

constexpr void mix_columns(uint8_t* data) noexcept {
  for (int i = 0; i < 4; ++i) mix_column(data + 4 * i);
}

constexpr void inv_mix_columns(uint8_t* data) noexcept {
  for (int i = 0; i < 4; ++i) inv_mix_column(data + 4 * i);
}

constexpr void encrypt(uint8_t* data, uint8_t* keys) noexcept {
  add_round_key(data, keys + 0);
  for (int i = 1; i < 10; ++i) {
    sub_bytes(data);
    shift_rows(data);
    mix_columns(data);
    add_round_key(data, keys + 16 * i);
  }
  sub_bytes(data);
  shift_rows(data);
  add_round_key(data, keys + 16 * 10);
}

constexpr void decrypt(uint8_t* data, uint8_t* keys) noexcept {
  add_round_key(data, keys + 16 * 10);
  inv_shift_rows(data);
  inv_sub_bytes(data);
  for (int i = 9; i > 0; --i) {
    add_round_key(data, keys + 16 * i);
    inv_mix_columns(data);
    inv_shift_rows(data);
    inv_sub_bytes(data);
  }
  add_round_key(data, keys + 0);
}

constexpr auto key_expansion(const uint8_t* key, uint8_t* round_keys) noexcept {
  for (int i = 0; i < 16; ++i) round_keys[i] = key[i];
  galois8 rc{1};
  for (int i = 1; i <= 10; ++i) {
    round_keys[16 * i + 0] = round_keys[16 * (i - 1) + 0] ^
                             substitution(round_keys[16 * i + 0 - 3]) ^
                             uint8_t(rc);
    rc *= galois8{2};
    round_keys[16 * i + 1] =
        round_keys[16 * (i - 1) + 1] ^ substitution(round_keys[16 * i + 1 - 3]);
    round_keys[16 * i + 2] =
        round_keys[16 * (i - 1) + 2] ^ substitution(round_keys[16 * i + 2 - 3]);
    round_keys[16 * i + 3] =
        round_keys[16 * (i - 1) + 3] ^ substitution(round_keys[16 * i + 3 - 7]);
    for (int j = 4; j < 16; ++j)
      round_keys[16 * i + j] =
          round_keys[16 * (i - 1) + j] ^ round_keys[16 * i + j - 4];
  }
}

}  // namespace aes

}  // namespace lyrahgames::cipher
