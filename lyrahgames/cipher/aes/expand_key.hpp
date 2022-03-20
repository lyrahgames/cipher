#pragma once
#include <cstdint>
#include <cstring>
//
#include <lyrahgames/cipher/aes/mul2.hpp>
#include <lyrahgames/cipher/aes/s_box.hpp>

namespace lyrahgames::cipher {

namespace aes {

constexpr void expand_key_128(uint8_t round_keys[16 * 11]) noexcept {
  uint8_t rc = 1;
  for (size_t p = 16; p <= 10 * 16; p += 16) {
    memcpy(&round_keys[p], &round_keys[p - 16], 16);
    round_keys[p + 0] ^= s_box(round_keys[p + 0 - 3]) ^ rc;
    round_keys[p + 1] ^= s_box(round_keys[p + 1 - 3]);
    round_keys[p + 2] ^= s_box(round_keys[p + 2 - 3]);
    round_keys[p + 3] ^= s_box(round_keys[p + 3 - 7]);
    for (int j = 4; j < 16; ++j) round_keys[p + j] ^= round_keys[p + j - 4];
    rc = mul2(rc);
  }
}

constexpr void expand_key_128(const uint8_t key[16],
                              uint8_t round_keys[16 * 11]) noexcept {
  memcpy(round_keys, key, 16);
  expand_key_128(round_keys);
}

}  // namespace aes

}  // namespace lyrahgames::cipher
