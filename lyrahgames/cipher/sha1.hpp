#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace lyrahgames::cipher {

namespace sha1 {

using czstring = const char*;
using block_type = std::array<uint32_t, 16>;
using hash_type = std::array<uint32_t, 5>;

constexpr size_t block_size = sizeof(block_type);
constexpr size_t block_size_mask = block_size - 1;
constexpr size_t block_size_shift = 6;

static_assert(8 * sizeof(hash_type) == 160);
static_assert(8 * sizeof(block_type) == 512);
static_assert(sizeof(block_type) == (size_t{1} << block_size_shift));

constexpr void compress(hash_type& h, block_type& block) noexcept {
  // for (auto x : block)
  //   std::cout << std::hex << std::setw(8) << std::setfill('0') << x << ' ';
  // std::cout << std::endl;

  uint32_t a = h[4];
  uint32_t b = h[3];
  uint32_t c = h[2];
  uint32_t d = h[1];
  uint32_t e = h[0];
  uint32_t f, k;

  const auto schedule = [&block](size_t i) {
    constexpr size_t mask = block_size / sizeof(uint32_t) - 1;
    const uint32_t tmp = block[i & mask] ^ block[(i + 2) & mask] ^
                         block[(i + 8) & mask] ^ block[(i + 13) & mask];
    const auto result = block[i & mask];
    block[i & mask] = (tmp << 1) | (tmp >> 31);
    return result;
  };

  const auto mix = [&](size_t it) {
    const uint32_t tmp = ((a << 5) | (a >> 27)) + f + e + k + schedule(it);
    e = d;
    d = c;
    c = (b << 30) | (b >> 2);
    b = a;
    a = tmp;
  };

  size_t it = 0;
  for (; it < 20; ++it) {
    f = (b & c) | ((~b) & d);
    k = 0x5a827999;
    mix(it);
  }
  for (; it < 40; ++it) {
    f = b ^ c ^ d;
    k = 0x6ed9eba1;
    mix(it);
  }
  for (; it < 60; ++it) {
    f = (b & c) | (b & d) | (c & d);
    k = 0x8f1bbcdc;
    mix(it);
  }
  for (; it < 80; ++it) {
    f = b ^ c ^ d;
    k = 0xca62c1d6;
    mix(it);
  }

  h[4] += a;
  h[3] += b;
  h[2] += c;
  h[1] += d;
  h[0] += e;
}

constexpr auto read(block_type& block, const char* ptr) noexcept {
  // Read block of 32-bit integers stored in big-endian format.
  for (size_t j = 0; j < block.size(); ++j) {
    block[j] = uint32_t(*ptr++) << 24;
    for (size_t k = 1; k < sizeof(uint32_t); ++k)
      block[j] |= uint32_t(*ptr++) << (24 - 8 * k);
  }
  return ptr;
}

constexpr auto read_tail(block_type& block, const char* ptr,
                         size_t trail_byte_count) noexcept {
  const size_t trail_uint32_count = trail_byte_count / sizeof(uint32_t);
  const size_t trail_uint32_byte_count =
      trail_byte_count & (sizeof(uint32_t) - 1);

  size_t j = 0;
  for (; j < trail_uint32_count; ++j) {
    block[j] = uint32_t(*ptr++) << 24;
    for (size_t k = 1; k < sizeof(uint32_t); ++k)
      block[j] |= uint32_t(*ptr++) << (24 - 8 * k);
  }
  block[j] = 0;
  size_t k = 0;
  for (; k < trail_uint32_byte_count; ++k)
    block[j] |= uint32_t(*ptr++) << (24 - 8 * k);

  // Append '1' bit and zero bits.
  block[j++] |= uint32_t(0x80) << (24 - 8 * k);

  return j;
}

constexpr auto hash(const char* data, size_t n) -> hash_type {
  // Initialization constants.
  constexpr uint32_t h0 = 0x67452301;
  constexpr uint32_t h1 = 0xefcdab89;
  constexpr uint32_t h2 = 0x98badcfe;
  constexpr uint32_t h3 = 0x10325476;
  constexpr uint32_t h4 = 0xc3d2e1f0;

  // Store the result as a 160-bit unsigned integer in little-endian format.
  hash_type result{h4, h3, h2, h1, h0};
  block_type block{};
  const size_t block_count = n >> block_size_shift;
  // Apply iterated hashing strategy.
  for (size_t i = 0; i < block_count; ++i) {
    // Read next block of data from input.
    data = read(block, data);
    // Compress the new block and the old hash into a new hash.
    compress(result, block);
  }
  // Prepare the last blocks with respective padding scheme.
  // Read the trailing bytes in the input that will not fill a whole block.
  size_t j = read_tail(block, data, n & block_size_mask);
  // A second block has to be used
  // if there is no space left for the message size.
  if (j > block.size() - 2) {
    block[j] = 0;
    compress(result, block);
    j = 0;
  }
  // Fill up with zero bits until message size.
  for (; j < block.size() - 2; ++j) block[j] = 0;
  // Append message size in bits to the padding.
  const uint64_t message_size = uint64_t(n) * 8;
  // 32-bit integers are already stored in little-endian format.
  // So, for the 64-bit integer only the halves have to be swapped.
  block[block.size() - 2] = message_size >> 32;
  block[block.size() - 1] = message_size;
  //
  compress(result, block);

  return result;
}

inline auto hash(czstring str) noexcept { return hash(str, std::strlen(str)); }

inline auto hash(const std::string& str) noexcept {
  return hash(str.c_str(), str.size());
}

inline auto string(const hash_type& h) {
  std::stringstream stream{};
  for (int i = 1; i <= h.size(); ++i)
    stream << std::hex << std::setw(8) << std::setfill('0') << h[h.size() - i];
  return stream.str();
}

}  // namespace sha1

}  // namespace lyrahgames::cipher
