#include <iostream>
#include <numeric>
#include <random>
//
#include <doctest/doctest.h>
//
#include <lyrahgames/cipher/cipher.hpp>

using namespace std;
using namespace lyrahgames;

SCENARIO("AES Substitution Box and Inverse Substitution Box and Bijectivity") {
  for (uint8_t i = 0; const auto x : array<uint8_t, 256>{
                          0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,  //
                          0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  //
                          0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,  //
                          0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  //
                          0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,  //
                          0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  //
                          0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,  //
                          0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  //
                          0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,  //
                          0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  //
                          0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,  //
                          0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  //
                          0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,  //
                          0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  //
                          0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,  //
                          0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  //
                          0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,  //
                          0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  //
                          0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,  //
                          0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  //
                          0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,  //
                          0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  //
                          0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,  //
                          0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  //
                          0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,  //
                          0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  //
                          0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,  //
                          0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  //
                          0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,  //
                          0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  //
                          0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,  //
                          0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,  //
                      }) {
    CAPTURE(i);
    CHECK(cipher::aes::substitution(i) == x);
    CHECK(cipher::aes::inv_substitution(cipher::aes::substitution(i)) == i);
    ++i;
  }

  for (uint8_t i = 0; const auto x : array<uint8_t, 256>{
                          0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,  //
                          0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
                          0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,  //
                          0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
                          0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,  //
                          0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
                          0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,  //
                          0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
                          0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,  //
                          0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                          0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,  //
                          0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
                          0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,  //
                          0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                          0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,  //
                          0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
                          0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,  //
                          0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
                          0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,  //
                          0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                          0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,  //
                          0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                          0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,  //
                          0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
                          0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,  //
                          0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
                          0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,  //
                          0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
                          0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,  //
                          0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                          0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,  //
                          0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
                      }) {
    CAPTURE(i);
    CHECK(cipher::aes::inv_substitution(i) == x);
    CHECK(cipher::aes::substitution(cipher::aes::inv_substitution(i)) == i);
    ++i;
  }
}

SCENARIO("AES MixColumn and Inverse Bijectivity") {
  mt19937 rng{random_device{}()};
  const int n = 1'000'000;
  for (int i = 0; i < n; ++i) {
    uint32_t x = rng();
    auto y = x;
    auto col = reinterpret_cast<uint8_t*>(&y);
    cipher::aes::mix_column(col);
    cipher::aes::inv_mix_column(col);
    CHECK(x == y);
  }
}

SCENARIO("AES Encryption Test Block 1") {
  uint8_t round_keys[] = {
      0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,  //
      0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,  //

      0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1,  //
      0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05,  //

      0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43,  //
      0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f,  //

      0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e,  //
      0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b,  //

      0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f,  //
      0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00,  //

      0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87,  //
      0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc,  //

      0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd,  //
      0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00, 0x93, 0xfd,  //

      0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3,  //
      0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6, 0xdc, 0x4f,  //

      0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2,  //
      0x31, 0x2b, 0xf5, 0x60, 0x7f, 0x8d, 0x29, 0x2f,  //

      0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21,  //
      0x28, 0xd1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e,  //

      0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89,  //
      0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6,  //
  };

  for (auto& [plain, crypt] : {
           pair<array<uint8_t, 16>, array<uint8_t, 16>>       //
           {{0x5c, 0xf6, 0xee, 0x79, 0x2c, 0xdf, 0x05, 0xe1,  //
             0xba, 0x2b, 0x63, 0x25, 0xc4, 0x1a, 0x5f, 0x10},
            {0xe2, 0x48, 0x89, 0xba, 0xaa, 0xdd, 0x90, 0x6b,  //
             0x06, 0x30, 0x06, 0x59, 0x8b, 0x8c, 0xe4, 0x59}},

           {{0xe7, 0xe4, 0x59, 0xfa, 0xa1, 0x11, 0xb3, 0x37,  //
             0xaa, 0x52, 0x18, 0x59, 0x5c, 0x3b, 0xdc, 0x8d},
            {0x02, 0x0b, 0x3c, 0x68, 0x63, 0x35, 0xf1, 0xe4,  //
             0xfb, 0xcf, 0xdc, 0x9d, 0x34, 0xaa, 0xef, 0xe5}},

           {{0x31, 0x7a, 0xae, 0x07, 0x69, 0xad, 0xab, 0x88,  //
             0x4c, 0xba, 0x8f, 0x80, 0xc5, 0x4c, 0x6d, 0x26},
            {0x38, 0x37, 0x7a, 0x70, 0x42, 0x79, 0x10, 0x88,  //
             0x0d, 0x7f, 0x5c, 0xdd, 0x56, 0x58, 0x9a, 0xdd}},

           {{0x5b, 0x46, 0xc2, 0xcd, 0xfc, 0xee, 0x6e, 0x32,  //
             0x34, 0x8b, 0x12, 0xbe, 0xa7, 0x59, 0x82, 0x30},
            {0x41, 0x81, 0x29, 0x76, 0x8f, 0x10, 0x86, 0x11,  //
             0x74, 0xac, 0xfd, 0xdc, 0x2c, 0xb3, 0x32, 0x18}},

           {{0xb0, 0xc2, 0x64, 0x64, 0xc9, 0xd9, 0xc9, 0x9a,  //
             0xe1, 0x47, 0x73, 0xee, 0x81, 0x48, 0x54, 0x28},
            {0x16, 0xe6, 0xeb, 0x08, 0xa1, 0x57, 0x16, 0x91,  //
             0xf2, 0x09, 0x15, 0xa5, 0x12, 0x85, 0xe0, 0x54}},

           {{0xe6, 0x03, 0xab, 0x0c, 0x92, 0x09, 0x8e, 0xbf,  //
             0x08, 0xf9, 0x0b, 0xfc, 0xea, 0x33, 0xff, 0x98},
            {0x96, 0xef, 0xd8, 0x2c, 0x21, 0x14, 0xfc, 0xc2,  //
             0x00, 0xb2, 0xd9, 0x8a, 0xfa, 0x01, 0x32, 0x82}},

           {{0xf6, 0x47, 0x68, 0x70, 0x59, 0x11, 0xaa, 0x73,  //
             0xb6, 0x6c, 0x27, 0x10, 0xc5, 0x33, 0x50, 0xd6},
            {0xa5, 0xae, 0xe6, 0x06, 0x38, 0x57, 0x59, 0x0e,  //
             0x0e, 0xa7, 0x21, 0xd4, 0x35, 0x9f, 0xc4, 0x94}},

           {{0xa1, 0xf8, 0xd4, 0x88, 0x68, 0xc3, 0x52, 0x7c,  //
             0xbe, 0x63, 0xc5, 0x23, 0xa3, 0x09, 0x27, 0x41},
            {0x96, 0x08, 0x39, 0xd5, 0xfe, 0x56, 0x03, 0xf7,  //
             0xb5, 0x69, 0x08, 0x8c, 0x34, 0x72, 0xce, 0xfb}},

           {{0x56, 0x8f, 0x61, 0xaa, 0x34, 0x3c, 0x2e, 0x1b,  //
             0xca, 0x02, 0x84, 0x6d, 0xe6, 0x6a, 0x0a, 0xa4},
            {0x26, 0x54, 0x8f, 0x77, 0x07, 0x08, 0x42, 0x68,  //
             0x3e, 0x4e, 0x9a, 0x28, 0x50, 0xcd, 0x18, 0x37}},

           {{0x6f, 0x4a, 0x03, 0xda, 0x95, 0x27, 0x39, 0xdc,  //
             0xe1, 0x6a, 0x0a, 0x1d, 0x85, 0x1f, 0x27, 0x73},
            {0xb4, 0x7b, 0x46, 0xe5, 0xf1, 0x30, 0x32, 0xe5,  //
             0xcd, 0x9a, 0x60, 0xcd, 0x67, 0xd1, 0x73, 0x3b}},
       }) {
    uint8_t text[16];
    for (int i = 0; i < 16; ++i) text[i] = plain[i];
    cipher::aes::encrypt(text, round_keys);
    for (int i = 0; i < 16; ++i) CHECK(text[i] == crypt[i]);
    cipher::aes::decrypt(text, round_keys);
    for (int i = 0; i < 16; ++i) CHECK(text[i] == plain[i]);
  }
}

SCENARIO("AES Encryption Test Block 2") {
  uint8_t round_keys[] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  //
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,  //

      0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa,  //
      0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe,  //

      0xb6, 0x92, 0xcf, 0x0b, 0x64, 0x3d, 0xbd, 0xf1,  //
      0xbe, 0x9b, 0xc5, 0x00, 0x68, 0x30, 0xb3, 0xfe,  //

      0xb6, 0xff, 0x74, 0x4e, 0xd2, 0xc2, 0xc9, 0xbf,  //
      0x6c, 0x59, 0x0c, 0xbf, 0x04, 0x69, 0xbf, 0x41,  //

      0x47, 0xf7, 0xf7, 0xbc, 0x95, 0x35, 0x3e, 0x03,  //
      0xf9, 0x6c, 0x32, 0xbc, 0xfd, 0x05, 0x8d, 0xfd,  //

      0x3c, 0xaa, 0xa3, 0xe8, 0xa9, 0x9f, 0x9d, 0xeb,  //
      0x50, 0xf3, 0xaf, 0x57, 0xad, 0xf6, 0x22, 0xaa,  //

      0x5e, 0x39, 0x0f, 0x7d, 0xf7, 0xa6, 0x92, 0x96,  //
      0xa7, 0x55, 0x3d, 0xc1, 0x0a, 0xa3, 0x1f, 0x6b,  //

      0x14, 0xf9, 0x70, 0x1a, 0xe3, 0x5f, 0xe2, 0x8c,  //
      0x44, 0x0a, 0xdf, 0x4d, 0x4e, 0xa9, 0xc0, 0x26,  //

      0x47, 0x43, 0x87, 0x35, 0xa4, 0x1c, 0x65, 0xb9,  //
      0xe0, 0x16, 0xba, 0xf4, 0xae, 0xbf, 0x7a, 0xd2,  //

      0x54, 0x99, 0x32, 0xd1, 0xf0, 0x85, 0x57, 0x68,  //
      0x10, 0x93, 0xed, 0x9c, 0xbe, 0x2c, 0x97, 0x4e,  //

      0x13, 0x11, 0x1d, 0x7f, 0xe3, 0x94, 0x4a, 0x17,  //
      0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30, 0xc5,  //
  };

  for (auto& [plain, crypt] : {
           pair<array<uint8_t, 16>, array<uint8_t, 16>>  //

           {{0x5c, 0xf6, 0xee, 0x79, 0x2c, 0xdf, 0x05, 0xe1,   //
             0xba, 0x2b, 0x63, 0x25, 0xc4, 0x1a, 0x5f, 0x10},  //
            {0x1e, 0x57, 0xd2, 0x78, 0x7b, 0x62, 0xbc, 0xd0,   //
             0x23, 0x63, 0x85, 0xe9, 0x8e, 0x36, 0x27, 0x7f}},

           {{0xe7, 0xe4, 0x59, 0xfa, 0xa1, 0x11, 0xb3, 0x37,   //
             0xaa, 0x52, 0x18, 0x59, 0x5c, 0x3b, 0xdc, 0x8d},  //
            {0xfa, 0xd8, 0xda, 0x74, 0x09, 0x95, 0xe6, 0x21,   //
             0x9e, 0x9c, 0xd2, 0xf1, 0xc7, 0x81, 0x0a, 0x58}},

           {{0x31, 0x7a, 0xae, 0x07, 0x69, 0xad, 0xab, 0x88,   //
             0x4c, 0xba, 0x8f, 0x80, 0xc5, 0x4c, 0x6d, 0x26},  //
            {0xce, 0xa9, 0xf2, 0xc7, 0xdd, 0xa1, 0x1c, 0x40,   //
             0xb6, 0xa1, 0x12, 0x93, 0x37, 0xd3, 0x57, 0x1a}},

           {{0x5b, 0x46, 0xc2, 0xcd, 0xfc, 0xee, 0x6e, 0x32,   //
             0x34, 0x8b, 0x12, 0xbe, 0xa7, 0x59, 0x82, 0x30},  //
            {0x79, 0x4b, 0x14, 0xb3, 0xd7, 0x3b, 0xf6, 0x6e,   //
             0x2a, 0xa6, 0x60, 0x72, 0x23, 0x53, 0x5b, 0x96}},

           {{0xb0, 0xc2, 0x64, 0x64, 0xc9, 0xd9, 0xc9, 0x9a,   //
             0xe1, 0x47, 0x73, 0xee, 0x81, 0x48, 0x54, 0x28},  //
            {0x47, 0xa2, 0xfe, 0xed, 0x7f, 0xdd, 0xd6, 0xf1,   //
             0x1a, 0xcc, 0xa0, 0x49, 0x27, 0xda, 0x05, 0x5c}},

           {{0xe6, 0x03, 0xab, 0x0c, 0x92, 0x09, 0x8e, 0xbf,   //
             0x08, 0xf9, 0x0b, 0xfc, 0xea, 0x33, 0xff, 0x98},  //
            {0x04, 0x3e, 0x01, 0xbd, 0x61, 0x11, 0x71, 0x0e,   //
             0x3d, 0x54, 0x41, 0xd7, 0x3f, 0x54, 0x46, 0x4b}},

           {{0xf6, 0x47, 0x68, 0x70, 0x59, 0x11, 0xaa, 0x73,   //
             0xb6, 0x6c, 0x27, 0x10, 0xc5, 0x33, 0x50, 0xd6},  //
            {0x40, 0x90, 0xa0, 0xf8, 0xb4, 0x53, 0x67, 0xf0,   //
             0xbd, 0xe3, 0x4c, 0xf3, 0x5b, 0x98, 0x25, 0xed}},

           {{0xa1, 0xf8, 0xd4, 0x88, 0x68, 0xc3, 0x52, 0x7c,   //
             0xbe, 0x63, 0xc5, 0x23, 0xa3, 0x09, 0x27, 0x41},  //
            {0x08, 0xce, 0x2f, 0x4c, 0x2f, 0xd0, 0xcc, 0xc2,   //
             0xe7, 0x95, 0xd4, 0xd1, 0x2a, 0xe6, 0x1d, 0xca}},

           {{0x56, 0x8f, 0x61, 0xaa, 0x34, 0x3c, 0x2e, 0x1b,   //
             0xca, 0x02, 0x84, 0x6d, 0xe6, 0x6a, 0x0a, 0xa4},  //
            {0x83, 0xb1, 0x1b, 0x68, 0xbb, 0xfd, 0xcb, 0xe7,   //
             0x0c, 0xc2, 0x15, 0x36, 0x02, 0x68, 0xc2, 0xee}},

           {{0x6f, 0x4a, 0x03, 0xda, 0x95, 0x27, 0x39, 0xdc,   //
             0xe1, 0x6a, 0x0a, 0x1d, 0x85, 0x1f, 0x27, 0x73},  //
            {0xe8, 0x9f, 0xcf, 0xd8, 0x4d, 0x37, 0x5a, 0xde,   //
             0x8a, 0xcf, 0x0a, 0x75, 0xb3, 0x65, 0x2a, 0x78}},
       }) {
    uint8_t text[16];
    for (int i = 0; i < 16; ++i) text[i] = plain[i];
    cipher::aes::encrypt(text, round_keys);
    for (int i = 0; i < 16; ++i) CHECK(text[i] == crypt[i]);
    cipher::aes::decrypt(text, round_keys);
    for (int i = 0; i < 16; ++i) CHECK(text[i] == plain[i]);
  }
}
