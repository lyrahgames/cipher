#pragma once
#include <cstdint>
//
#include <lyrahgames/cipher/aes/s_box.hpp>

namespace lyrahgames::cipher {

namespace aes {

constexpr void sub_bytes_128(uint8_t data[16]) noexcept {
  // Leave loop unrolling to the compiler.
  for (size_t i = 0; i < 16; ++i) data[i] = s_box(data[i]);
}

constexpr void inv_sub_bytes_128(uint8_t data[16]) noexcept {
  // Leave loop unrolling to the compiler.
  for (size_t i = 0; i < 16; ++i) data[i] = inv_s_box(data[i]);
}

}  // namespace aes

}  // namespace lyrahgames::cipher
