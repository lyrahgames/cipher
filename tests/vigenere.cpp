#include <doctest/doctest.h>
//
#include <random>
#include <string>
//
#include <lyrahgames/cipher/cipher.hpp>

using namespace std;
using namespace lyrahgames;

TEST_CASE_TEMPLATE("Out-Of-Place Encryption and Decryption of Strings",
                   T,
                   char,
                   unsigned char,
                   cipher::ascii_block) {
  using block = T;
  // Choose the cipher to be used for en- and decryption.
  using cipher = cipher::vigenere<block>;

  // Run several Monte-Carlo tests.
  for (int i = 0; i < 1000; ++i) {
    // Choose random key.
    const auto key = cipher::random_key(random_device{});

    string ciphertext{};
    string checktext{};
    // Check en- and decryption for several example strings.
    for (auto& plaintext : initializer_list<string>{
             "Some simple example.",
             "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed "
             "do "
             "eiusmod tempor incididunt ut labore et dolore magna aliqua.",
             "Hello, World!"}) {
      // Prepare buffers of en- and decryption.
      ciphertext.resize(size(plaintext));
      checktext.resize(size(plaintext));

      // Do the out-of-place encrypt and decrypt.
      cipher::encrypt(key, plaintext, ciphertext);
      cipher::decrypt(key, ciphertext, checktext);
      CHECK(plaintext == checktext);

      // Do the in-place encrypt and decrypt.
      checktext = plaintext;
      cipher::encrypt(key, checktext);
      CHECK(checktext == ciphertext);
      cipher::decrypt(key, checktext);
      CHECK(plaintext == checktext);
    }
  }
}
