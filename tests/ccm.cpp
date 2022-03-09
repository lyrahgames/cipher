#include <doctest/doctest.h>
//
#include <iomanip>
#include <iostream>
#include <random>
//
#include <lyrahgames/cipher/cipher.hpp>

using namespace std;
using namespace lyrahgames::cipher;

SCENARIO("CCM Examples") {
  random_device rng{};

  for (int i = 0; i < 3; ++i) {
    uint64_t nonce = (uint64_t(rng()) << 32) | rng();
    ccm::key_type key{};
    for (auto& k : key) k = rng();

    // cout << "nonce = " << nonce << '\n'  //
    //      << "key = " << ccm::string(key) << endl;
    for (const auto& text : initializer_list<string>{
             "The quick brown fox jumps over the lazy dog",
             "The quick brown fox jumps over the lazy cog",
             "Lorem ipsum dolor sit amet",
         }) {
      string ciphertext;
      ciphertext.resize(text.size() + 16);

      ccm::encrypt(nonce, key, text.data(), text.size(), ciphertext.data());

      // cout << text << endl << ciphertext << endl;

      auto check = ccm::decrypt(nonce, key, ciphertext.data(),
                                ciphertext.size(), ciphertext.data());

      // cout << ciphertext.substr(0, text.size()) << endl << endl;

      CHECK(check);
      CHECK(ciphertext.substr(0, text.size()) == text);

      // Make sure that a corruption is not valid.
      ccm::encrypt(nonce, key, text.data(), text.size(), ciphertext.data());
      ++ciphertext[1];
      check = ccm::decrypt(nonce, key, ciphertext.data(), ciphertext.size(),
                           ciphertext.data());
      CHECK(!check);
      CHECK(ciphertext.substr(0, text.size()) != text);
    }
  }
}
