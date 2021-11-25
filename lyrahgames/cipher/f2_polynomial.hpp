#pragma once
#include <bit>
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
constexpr auto f2_polynomial_mul(uint m, uint n) noexcept {
  uint result = 0;
  for (int i = 0; i < 8 * sizeof(uint); ++i)
    if ((n >> i) & 1) result ^= m << i;
  return result;
}

template <std::unsigned_integral uint>
constexpr auto f2_polynomial_divmod(uint m, uint n) noexcept {
  using namespace std;
  const auto t = bit_width(n);
  uint q = 0;
  auto s = bit_width(m);
  while (s >= t) {
    const auto shift = s - t;
    q ^= 1 << shift;
    m ^= n << shift;
    s = bit_width(m);
  }
  return pair{q, m};
}

template <std::unsigned_integral uint>
constexpr auto f2_polynomial_inv(uint x, uint mod) noexcept {
  uint t0 = 0, t1 = 1;
  uint r0 = mod, r1 = x;
  while (r1) {
    const auto [q, r] = f2_polynomial_divmod(r0, r1);
    r0 = r1;
    r1 = r;
    const auto t = t0 ^ f2_polynomial_mul(q, t1);
    t0 = t1;
    t1 = t;
  }
  return t0;
}

}  // namespace lyrahgames::cipher
