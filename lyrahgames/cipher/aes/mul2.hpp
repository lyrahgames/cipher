#pragma once
#include <cstdint>

namespace lyrahgames::cipher {

namespace aes {

/// Interpret given argument as an element of Rijndael's Galois Field
/// and multiply it by '2'. This is equivalent to multiplying in F(2)
/// a given polynomial p by the first-order monomial
/// such that the result r is given by the following expression.
/// r(x) = x * p(x) mod q(x)
/// q(x) = x^8 + x^4 + x^3 + x + 1
constexpr auto mul2(uint8_t x) noexcept -> uint8_t {
  constexpr uint8_t mod = 0b0001'1011;
  return (x << 1) ^ ((int8_t(x) >> 7) & mod);
}

/// SIMD-like Rijndael's Galois Field Multiplication by '2'
/// of eight elements in parallel by using 64-bit unsigned integer.
constexpr auto mul2(uint64_t x) noexcept -> uint64_t {
  constexpr uint64_t mod = 0x1b'1b'1b'1b'1b'1b'1b'1b;
  uint64_t mask = x & 0x80'80'80'80'80'80'80'80;
  mask = (mask >> 1) | mask;
  mask = (mask >> 2) | mask;
  mask = (mask >> 4) | mask;
  return ((x << 1) & 0xfe'fe'fe'fe'fe'fe'fe'fe) ^ (mask & mod);
}

}  // namespace aes

}  // namespace lyrahgames::cipher
