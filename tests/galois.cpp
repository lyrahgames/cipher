#include <doctest/doctest.h>
//
#include <lyrahgames/cipher/cipher.hpp>

using namespace std;
using namespace lyrahgames;
using cipher::galois8;

SCENARIO("Multiplication and Division in F(2^8)") {
  // Multiplication
  for (int i = 0; i < 256; ++i) {
    for (int j = 0; j < 256; ++j) {
      // We expect F(2) polynomial computations to be correct.
      const auto k = cipher::f2_polynomial_mul(uint16_t(i), uint16_t(j));
      const auto [q, r] =
          cipher::f2_polynomial_divmod(k, uint16_t(0b1'0001'1011));

      CHECK(galois8(i) * galois8(j) == galois8(r));
    }
  }

  // Division
  for (int i = 0; i < 256; ++i) {
    for (int j = 1; j < 256; ++j) {
      const auto t = galois8(i) / galois8(j);
      CHECK(t * galois8(j) == galois8(i));
    }
  }
}
