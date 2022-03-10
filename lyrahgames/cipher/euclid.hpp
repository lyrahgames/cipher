#pragma once
#include <tuple>

namespace lyrahgames::cipher {

// Extended Euclidean Algorithm
// Function returns the greatest common divisor
// and the Bezout coefficients.
// [d, a, b] = gcd_bezout(p, q)
// d = a * p + b * q
template <typename integer>
constexpr auto gcd_bezout(integer p, integer q) noexcept
    -> std::tuple<integer, integer, integer> {
  integer s0 = 1, s1 = 0;
  integer t0 = 0, t1 = 1;
  while (q != 0) {
    const integer r = p / q;
    const integer a = p - r * q;
    const integer b = s0 - r * s1;
    const integer c = t0 - r * t1;
    p = q;
    q = a;
    s0 = s1;
    s1 = b;
    t0 = t1;
    t1 = c;
  }
  return {p, s0, t0};
}

}  // namespace lyrahgames::cipher
