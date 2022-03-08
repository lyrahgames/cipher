#include <doctest/doctest.h>
//
#include <iomanip>
#include <iostream>
#include <string>
//
#include <lyrahgames/cipher/cipher.hpp>

using namespace std;
using namespace lyrahgames::cipher;

SCENARIO("SHA-1 Correctness") {
  for (const auto& [text, hash] : {
           pair<string, string>  //
           {"",                  //
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
           {"The quick brown fox jumps over the lazy dog",
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"},
           {"The quick brown fox jumps over the lazy cog",
            "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"},
           {"The quick brown fox jumps over the lazy dog and tries to c",
            "ebaf24aa563e1437691719f1bf66098c5b47d9f5"},
           {"The quick brown fox jumps over the lazy dog and tries to catch",
            "5c6bfa220e6fb5083c65f18ba81148906acffffe"},
           {"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do "
            "eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut "
            "enim ad minim veniam, quis nostrud exercitation ullamco laboris "
            "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in "
            "reprehenderit in voluptate velit esse cillum dolore eu fugiat "
            "nulla pariatur. Excepteur sint occaecat cupidatat non proident, "
            "sunt in culpa qui officia deserunt mollit anim id est laborum.",
            "cd36b370758a259b34845084a6cc38473cb95e27"},
       }) {
    CAPTURE(text);
    CHECK(sha1::string(sha1::hash(text)) == hash);
  }
}
