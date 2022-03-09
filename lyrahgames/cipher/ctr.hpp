#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>
//
#include <lyrahgames/cipher/aes.hpp>

namespace lyrahgames::cipher {

namespace ctr {

using key_type = std::array<uint8_t, 16>;
using block_type = std::array<uint8_t, 16>;

inline void load(block_type& block, uint64_t nonce, uint64_t counter) noexcept {
  for (size_t i = 0; i < sizeof(nonce); ++i) {
    block[i] = nonce >> (56 - 8 * i);
    block[i + sizeof(nonce)] = counter >> (56 - 8 * i);
  }
}

inline void keystream(block_type& block,
                      uint8_t* keys,
                      uint64_t nonce,
                      uint64_t counter) {
  load(block, nonce, i);
  aes::encrypt(block.data(), keys);
}

inline auto encryption(uint64_t nonce,
                       const key_type& key,
                       const char* data,
                       size_t n) -> std::vector<char> {
  constexpr size_t block_size = sizeof(block_type);

  if (!n) return {};

  const size_t block_count = n / block_size;
  const size_t block_tail = n % block_size;

  uint8_t keys[11 * 16];
  aes::key_expansion(key.data(), keys);

  std::vector<char> result(block_size * ((n - 1) / block_size + 1));
  block_type block{};

  for (size_t i = 0; i < block_count; ++i) {
    load(block, nonce, i);
    aes::encrypt(block.data(), keys);
    for (size_t j = 0; j < block_size; ++j)
      result[i * block_size + j] = (*data++) ^ block[j];
  }
  load(block, nonce, block_count);
  aes::encrypt(block.data(), keys);
  for (size_t j = 0; j < block_tail; ++j)
    result[block_count * block_size + j] = (*data++) ^ block[j];

  return result;
}

}  // namespace ctr

}  // namespace lyrahgames::cipher
