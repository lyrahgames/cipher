#pragma once
#include <cstdint>

namespace lyrahgames::cipher {

namespace aes {

constexpr size_t shift_rows_128_lut[] = {
    0,  5,  10, 15,  //
    4,  9,  14, 3,   //
    8,  13, 2,  7,   //
    12, 1,  6,  11,  //
};

constexpr size_t inv_shift_rows_128_lut[] = {
    0,  13, 10, 7,   //
    4,  1,  14, 11,  //
    8,  5,  2,  15,  //
    12, 9,  6,  3,   //
};

constexpr auto shift_rows_128_index(size_t index) noexcept -> size_t {
  return shift_rows_128_lut[index];
}

constexpr auto inv_shift_rows_128_index(size_t index) noexcept -> size_t {
  return inv_shift_rows_128_lut[index];
}

constexpr void shift_rows_128(const uint8_t src[16], uint8_t dst[16]) noexcept {
  // Leave loop unrolling to the compiler.
  for (size_t i = 0; i < 16; ++i) dst[i] = src[shift_rows_128_index(i)];
}

constexpr void inv_shift_rows_128(const uint8_t src[16],
                                  uint8_t dst[16]) noexcept {
  // Leave loop unrolling to the compiler.
  for (size_t i = 0; i < 16; ++i) dst[i] = src[inv_shift_rows_128_index(i)];
}

}  // namespace aes

}  // namespace lyrahgames::cipher
