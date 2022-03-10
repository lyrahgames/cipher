#pragma once

namespace lyrahgames::cipher {

// Modular Exponentiation
// powmod(x, e, n) = x^e mod n
// The value 'n * n' should be representable
// by the underlying integer type.
template <typename integer>
constexpr auto powmod(integer x, integer e, integer n) noexcept -> integer {
  integer r = 1;
  integer y = x;
  while (e) {
    if ((e & 1) == 1)  //
      r = (r * y) % n;
    y = (y * y) % n;
    e >>= 1;
  }
  return r;
}

}  // namespace lyrahgames::cipher
