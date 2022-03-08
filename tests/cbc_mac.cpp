#include <doctest/doctest.h>
//
#include <iomanip>
#include <iostream>
#include <random>
//
#include <lyrahgames/cipher/cipher.hpp>

using namespace std;
using namespace lyrahgames::cipher;

SCENARIO("CBC-MAC Examples") {
  random_device rng{};

  for (int i = 0; i < 3; ++i) {
    cbc_mac::key_type key{};
    for (auto& k : key) k = rng();

    cout << "key = " << cbc_mac::string(key) << endl;
    for (const auto& text : {
             "",
             "The quick brown fox jumps over the lazy dog",
             "The quick brown fox jumps over the lazy cog",
         }) {
      cout << cbc_mac::string(cbc_mac::mac(key, text)) << "  <-  "
           << "'" << text << "'" << '\n';
    }
    cout << endl;
  }
}
