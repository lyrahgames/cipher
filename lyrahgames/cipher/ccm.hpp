#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
//
#include <lyrahgames/cipher/cbc_mac.hpp>

namespace lyrahgames::cipher {

namespace ccm {

using namespace cbc_mac;

using block_type = mac_type;

// inline auto encryption(size_t nonce,
//                        const key_type& key,
//                        const char* data,
//                        size_t n) {
//   std::vector<char> result(16 * ((n - 1) / 16 + 3));
//   return result;
// }

constexpr void load(block_type& block,
                    uint64_t nonce,
                    uint64_t counter) noexcept {
  for (size_t i = 0; i < sizeof(nonce); ++i) {
    block[i] = nonce >> (56 - 8 * i);
    block[i + sizeof(nonce)] = counter >> (56 - 8 * i);
  }
}

inline auto encrypt(uint64_t nonce,
                    const key_type& key,
                    const char* data,
                    size_t n,
                    char* destination) noexcept {
  const auto tag = mac(key, data, n, nonce);
  // std::cout << "tag = " << cbc_mac::string(tag) << std::endl;

  uint8_t keys[11 * 16];
  aes::key_expansion(key.data(), keys);

  const size_t block_count = n >> 4;
  const size_t trailing_byte_count = n & 15;

  block_type block{};

  for (size_t i = 0; i < block_count; ++i) {
    load(block, nonce, i + 1);
    aes::encrypt(block.data(), keys);
    for (size_t j = 0; j < 16; ++j)  //
      *destination++ = (*data++) ^ block[j];
  }
  if (trailing_byte_count) {
    load(block, nonce, block_count + 1);
    aes::encrypt(block.data(), keys);
    for (size_t j = 0; j < trailing_byte_count; ++j)
      *destination++ = (*data++) ^ block[j];
  }

  // Add tag at the end
  load(block, nonce, 0);
  aes::encrypt(block.data(), keys);
  for (size_t j = 0; j < 16; ++j) {
    *destination++ = tag[j] ^ block[j];
    block[j] ^= tag[j];
  }
  // std::cout << "blk = " << cbc_mac::string(block) << std::endl;
}

inline bool decrypt(uint64_t nonce,
                    const key_type& key,
                    const char* data,
                    size_t n,
                    char* destination) {
  uint8_t keys[11 * 16];
  aes::key_expansion(key.data(), keys);

  const size_t message_size = n - sizeof(block_type);
  const size_t block_count = message_size >> 4;
  const size_t trailing_byte_count = message_size & 15;

  block_type block{};
  char* ptr = destination;

  for (size_t i = 0; i < block_count; ++i) {
    load(block, nonce, i + 1);
    aes::encrypt(block.data(), keys);
    for (size_t j = 0; j < 16; ++j)  //
      *ptr++ = (*data++) ^ block[j];
  }
  if (trailing_byte_count) {
    load(block, nonce, block_count + 1);
    aes::encrypt(block.data(), keys);
    for (size_t j = 0; j < trailing_byte_count; ++j)
      *ptr++ = (*data++) ^ block[j];
  }

  const auto tag = mac(key, destination, message_size, nonce);
  // std::cout << "tag = " << cbc_mac::string(tag) << std::endl;

  load(block, nonce, 0);
  aes::encrypt(block.data(), keys);
  for (size_t j = 0; j < 16; ++j) {
    if (uint8_t(*ptr++) != (block[j] ^ tag[j])) return false;
    // block[j] = *ptr++;
    // block[j] ^= tag[j];
  }

  // std::cout << "blk = " << cbc_mac::string(block) << std::endl;

  return true;
}

}  // namespace ccm

}  // namespace lyrahgames::cipher
