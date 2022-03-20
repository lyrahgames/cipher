#pragma once
#include <cstdint>

namespace lyrahgames::cipher {

namespace aes {

constexpr void add_round_key_128(const uint8_t round_key[16],  //
                                 const uint8_t src[16],
                                 uint8_t dst[16]) noexcept {
  // Leave loop unrolling to compiler.
  for (size_t i = 0; i < 16; ++i) dst[i] = round_key[i] ^ src[i];
}

constexpr void add_round_key_128(const uint8_t round_key[16],
                                 uint8_t data[16]) noexcept {
  // Leave loop unrolling to compiler.
  for (size_t i = 0; i < 16; ++i) data[i] ^= round_key[i];
}

constexpr void add_round_key_128(const uint64_t round_key[2],
                                 uint64_t block[2]) noexcept {
  block[0] ^= round_key[0];
  block[1] ^= round_key[1];
}

}  // namespace aes

}  // namespace lyrahgames::cipher
