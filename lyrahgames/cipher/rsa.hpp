#pragma once
#include <gmpxx.h>

#include <cmath>
#include <iomanip>
#include <iostream>
//
#include <gmpxx.h>
//
#include <lyrahgames/cipher/primality.hpp>

namespace lyrahgames::cipher {

namespace rsa {

struct key_type {
  mpz_class module;
  mpz_class exponent;
};

inline auto random_prime(size_t bits, auto&& rng) -> mpz_class {
  mpz_class result = 30 * rng.get_z_bits(bits - 5) + 1;
  const auto random = [&rng](mpz_class n) { return rng.get_z_range(n); };
  constexpr size_t increments[] = {1, 7, 11, 13, 17, 19, 23, 29, 31};
  constexpr size_t rounds = 5;
  while (true) {
    // + 1
    if (miller_rabin::is_probable_prime(result, rounds, random)) return result;
    // + 7
    result += 6;
    if (miller_rabin::is_probable_prime(result, rounds, random)) return result;
    // + 11
    result += 4;
    if (miller_rabin::is_probable_prime(result, rounds, random)) return result;
    // + 13
    result += 2;
    if (miller_rabin::is_probable_prime(result, rounds, random)) return result;
    // + 17
    result += 4;
    if (miller_rabin::is_probable_prime(result, rounds, random)) return result;
    // + 19
    result += 2;
    if (miller_rabin::is_probable_prime(result, rounds, random)) return result;
    // + 23
    result += 4;
    if (miller_rabin::is_probable_prime(result, rounds, random)) return result;
    // + 29
    result += 6;
    if (miller_rabin::is_probable_prime(result, rounds, random)) return result;
    // + 31
    result += 2;
  }
}

inline void encrypt() {}

inline void decrypt() {}

}  // namespace rsa

}  // namespace lyrahgames::cipher
