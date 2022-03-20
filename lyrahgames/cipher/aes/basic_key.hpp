#pragma once
#include <lyrahgames/cipher/aes/basic_block.hpp>

namespace lyrahgames::cipher {

namespace aes {

struct alignas(16) basic_key {
  constexpr basic_key() noexcept = default;
  constexpr basic_key(uint8_t a0,
                      uint8_t a1,
                      uint8_t a2,
                      uint8_t a3,
                      uint8_t b0,
                      uint8_t b1,
                      uint8_t b2,
                      uint8_t b3,
                      uint8_t c0,
                      uint8_t c1,
                      uint8_t c2,
                      uint8_t c3,
                      uint8_t d0,
                      uint8_t d1,
                      uint8_t d2,
                      uint8_t d3) noexcept
      : data{uint64_t(a0) | (uint64_t(a1) << 8) | (uint64_t(a2) << 16) |
                 (uint64_t(a3) << 24) | (uint64_t(b0) << 32) |
                 (uint64_t(b1) << 40) | (uint64_t(b2) << 48) |
                 (uint64_t(b3) << 56),
             uint64_t(c0) | (uint64_t(c1) << 8) | (uint64_t(c2) << 16) |
                 (uint64_t(c3) << 24) | (uint64_t(d0) << 32) |
                 (uint64_t(d1) << 40) | (uint64_t(d2) << 48) |
                 (uint64_t(d3) << 56)} {}

  friend constexpr auto operator<=>(const basic_key&,
                                    const basic_key&) noexcept = default;

  uint64_t data[2];
};

static_assert(sizeof(basic_key) == 16);
static_assert(alignof(basic_key) == 16);

}  // namespace aes

}  // namespace lyrahgames::cipher
