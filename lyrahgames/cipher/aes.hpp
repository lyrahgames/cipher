#pragma once
#include <bit>
#include <tuple>
//
#include <lyrahgames/cipher/meta.hpp>

namespace lyrahgames::cipher {

template <typename integer>
constexpr auto egcd(integer p, integer q) noexcept {
  integer s0 = 1, s1 = 0;
  integer t0 = 0, t1 = 1;
  while (q != 0) {
    const auto r = p / q;
    const auto a = p - r * q;
    const auto b = s0 - r * s1;
    const auto c = t0 - r * t1;
    p = q;
    q = a;
    s0 = s1;
    s1 = b;
    t0 = t1;
    t1 = c;
  }
  return std::tuple{p, s0, t0};
}

template <std::unsigned_integral uint>
constexpr auto f2_polynom_mul(uint m, uint n) noexcept {
  uint result = 0;
  for (int i = 0; i < 8 * sizeof(uint); ++i)
    if ((n >> i) & 1) result ^= m << i;
  return result;
}

template <std::unsigned_integral uint>
constexpr auto f2_polynom_divmod(uint m, uint n) noexcept {
  using std::bit_width;
  const auto t = bit_width(n);
  uint q = 0;
  auto s = bit_width(m);
  while (s >= t) {
    const auto shift = s - t;
    q ^= 1 << shift;
    m ^= n << shift;
    s = bit_width(m);
  }
  return std::pair{q, m};
}

template <std::unsigned_integral uint>
constexpr auto f2_polynom_inv(uint x, uint mod) noexcept {
  uint t0 = 0, t1 = 1;
  uint r0 = mod, r1 = x;
  while (r1) {
    const auto [q, r] = f2_polynom_divmod(r0, r1);
    r0 = r1;
    r1 = r;
    const auto t = t0 ^ f2_polynom_mul(q, t1);
    t0 = t1;
    t1 = t;
  }
  return t0;
}

constexpr auto aes_s_box(uint8_t x) noexcept {
  using namespace std;
  const auto p = 0b1'0001'1011u;
  const uint8_t b = f2_polynom_inv(uint16_t(x), uint16_t(p));
  const uint8_t s =
      b ^ rotl(b, 1) ^ rotl(b, 2) ^ rotl(b, 3) ^ rotl(b, 4) ^ uint8_t(0x63);
  return s;
}

struct galois256 {
  constexpr galois256() = default;
  explicit constexpr galois256(uint8_t x) : data{x} {}
  friend constexpr auto operator<=>(const galois256&,
                                    const galois256&) noexcept = default;
  uint8_t data;
};

constexpr auto operator+(galois256 x, galois256 y) noexcept {
  return galois256(x.data ^ y.data);
}

constexpr auto operator-(galois256 x, galois256 y) noexcept {
  return x + y;
}

constexpr auto operator*(galois256 x, galois256 y) noexcept {
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
  // return galois256(result);
  const auto t = f2_polynom_mul(uint16_t(x.data), uint16_t(y.data));
  const auto [q, r] = f2_polynom_divmod(t, uint16_t(0b1'0001'1011u));
  return galois256(r);
}

constexpr auto operator/(galois256 x, galois256 y) noexcept {
  return galois256(0);
}

}  // namespace lyrahgames::cipher
