#pragma once
#include <lyrahgames/cipher/f2_polynomial.hpp>

namespace lyrahgames::cipher {

struct galois8 {
  constexpr galois8() = default;
  explicit constexpr galois8(uint8_t x) : data{x} {}
  friend constexpr auto operator<=>(const galois8&,
                                    const galois8&) noexcept = default;
  uint8_t data;
};

constexpr auto operator+(galois8 x) noexcept -> galois8 {
  return x;
}

constexpr auto operator-(galois8 x) noexcept -> galois8 {
  return x;
}

constexpr auto operator+(galois8 x, galois8 y) noexcept -> galois8 {
  return galois8(x.data ^ y.data);
}

constexpr auto operator-(galois8 x, galois8 y) noexcept -> galois8 {
  return x + y;
}

constexpr auto operator*(galois8 x, galois8 y) noexcept -> galois8 {
  // uint16_t a = x.data;
  // uint16_t b = y.data;
  // uint16_t result = 0;
  // for (int i = 0; i < 8; ++i) {
  //   if ((b >> i) & 1) result ^= (a << i);
  // }
  // uint8_t mod = result >> 8;
  // if ((mod >> 0) & 1) result ^= 0b00011011;
  // if ((mod >> 1) & 1) result ^= 0b00110110;
  // if ((mod >> 2) & 1) result ^= 0b01101100;
  // if ((mod >> 3) & 1) result ^= 0b11011000;
  // if ((mod >> 4) & 1) result ^= 0b10101011;
  // if ((mod >> 5) & 1) result ^= 0b01001101;
  // if ((mod >> 6) & 1) result ^= 0b10011010;
  // return galois8(result);

  // const auto t = f2_polynomial_mul(uint16_t(x.data), uint16_t(y.data));
  // const auto [q, r] = f2_polynomial_divmod(t, uint16_t(0b1'0001'1011u));
  // return galois8(r);

  using namespace std;
  constexpr uint8_t mod = 0b0001'1011;

  auto p = x.data;  // p(x)
  auto q = y.data;  // q(x)
  uint8_t r = 0;    // result r(x) = p(x) * q(x)

  while (q) {
    r ^= (q & 1) ? p : 0;
    q >>= 1;
    p = (p << 1) ^ ((p & 0x80) ? mod : 0);  // p(x) = x * p(x)
  }

  return galois8(r);
}

constexpr auto operator~(galois8 x) noexcept -> galois8 {
  const auto p = 0b1'0001'1011u;
  return galois8(f2_polynomial_inv(uint16_t(x.data), uint16_t(p)));
}

constexpr auto operator/(galois8 x, galois8 y) noexcept {
  return x * ~y;
}

constexpr auto operator+=(galois8& x, galois8 y) noexcept -> galois8& {
  x.data ^= y.data;
  return x;
}

constexpr auto operator-=(galois8& x, galois8 y) noexcept -> galois8& {
  return x += y;
}

constexpr auto operator*=(galois8& x, galois8 y) noexcept -> galois8& {
  x = x * y;
  return x;
}

constexpr auto operator/=(galois8& x, galois8 y) noexcept -> galois8& {
  x = x / y;
  return x;
}

}  // namespace lyrahgames::cipher
