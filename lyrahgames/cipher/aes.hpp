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

}  // namespace aes

struct aes_block {
  std::array<uint8_t, 16> data;
};

constexpr auto aes_sub_bytes(aes_block block) noexcept -> aes_block {
  aes_block result;
  for (int i = 0; i < 16; ++i)
    result.data[i] = aes::substitution(block.data[i]);
  return result;
}

constexpr auto aes_shift_rows(aes_block block) noexcept -> aes_block {
  aes_block result{{
      block.data[0],
      block.data[5],
      block.data[10],
      block.data[15],

      block.data[1],
      block.data[6],
      block.data[11],
      block.data[12],

      block.data[2],
      block.data[7],
      block.data[8],
      block.data[13],

      block.data[3],
      block.data[4],
      block.data[9],
      block.data[14],
  }};
  return result;
}

constexpr auto aes_mix_columns(aes_block block) noexcept -> aes_block {
  aes_block result;

  return result;
}

}  // namespace lyrahgames::cipher
