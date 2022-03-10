#pragma once
#include <cmath>
//
#include <lyrahgames/cipher/powmod.hpp>

namespace lyrahgames::cipher {

namespace naive {

template <typename integer>
constexpr bool is_prime(integer n) noexcept {
  using namespace std;
  if (n <= 1) return false;
  for (integer i = 2; i < sqrt(n + 1); ++i)
    if ((n % i) == 0) return false;
  return true;
}

}  // namespace naive

namespace miller_rabin {

// n > 3
template <typename integer>
constexpr bool is_probable_prime(integer n,
                                 size_t rounds,
                                 auto&& random) noexcept {
  using namespace std;

  if ((n <= 1) || (n == 4)) return false;
  if (n <= 5) return true;

  integer d = n - 1;
  integer r = 0;

  // Factor out powers of 2 such that n - 1 = 2^r * d
  while ((d & 1) == 0) {
    d /= 2;
    ++r;
  }

  const auto is_strong_prime_base = [&](integer a) {
    a = powmod(a, d, n);
    if ((a == 1) || (a == (n - 1))) return true;
    for (integer i = r; i > 1; --i) {
      a = (a * a) % n;
      if (a == (n - 1)) return true;
    }
    return false;
  };

  for (; rounds > 0; --rounds)
    if (!is_strong_prime_base(random(n - 3) + 2)) return false;
  return true;
}

}  // namespace miller_rabin

}  // namespace lyrahgames::cipher
