#include <doctest/doctest.h>
//
#include <iomanip>
#include <iostream>
//
#include <lyrahgames/cipher/aes/s_box.hpp>

using namespace std;
using namespace lyrahgames::cipher;

SCENARIO("AES S-Box Bijectivity") {
  for (size_t i = 0; i < 256; ++i) {
    REQUIRE(aes::inv_s_box(aes::s_box(i)) == i);
    REQUIRE(aes::s_box(aes::inv_s_box(i)) == i);
  }
}
