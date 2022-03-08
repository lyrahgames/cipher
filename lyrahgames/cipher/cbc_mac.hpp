#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
//
#include <lyrahgames/cipher/aes.hpp>

namespace lyrahgames::cipher {

namespace cbc_mac {

using mac_type = std::array<uint8_t, 16>;
using key_type = std::array<uint8_t, 16>;

// CBC-MAC is the first algorithm in the ISO/IEC 9797-13 standard.
// Here, we use AES with 128-bit keys and blocks and padding strategy 3.
constexpr auto mac(const key_type& key, const char* data, size_t n) noexcept
    -> mac_type {
  // Prepare round keys for AES block encryption.
  uint8_t keys[11 * 16];
  aes::key_expansion(key.data(), keys);

  mac_type result{};

  // Here, padding strategy 3 is used.
  // This allows security for variable-length messages.
  // The size of the message in bits is stored
  // in a first block in big-endian format padded with zero bits.
  const auto message_size = n * 8;
  for (size_t i = 0; i < sizeof(size_t); ++i)
    result[15 - i] = message_size >> (8 * i);

  // The initialization vector (IV) has to be constant and zero.
  // Otherwise, the generated MAC is vulnerable.
  // XORing with zero is a no-op.

  // Now, use AES to get the first cipher block.
  aes::encrypt(result.data(), keys);

  const size_t block_count = n >> 4;
  const size_t trailing_byte_count = n & 15;
  // Iterate over whole blocks.
  for (size_t i = 0; i < block_count; ++i) {
    // Read the next characters from the input and
    // XOR these with the elements of the old cipher block.
    for (size_t j = 0; j < 16; ++j) result[j] ^= (*data++);
    // Again, use AES encryption.
    aes::encrypt(result.data(), keys);
  }
  if (trailing_byte_count) {
    // The last block cannot be filled with the trailing data.
    // Due to the XOR, we only have to read and XOR the available bytes.
    // The rest of result keeps the same and will again be encrypted.
    for (size_t j = 0; j < trailing_byte_count; ++j) result[j] ^= (*data++);
    aes::encrypt(result.data(), keys);
  }

  return result;
}

constexpr auto mac(const key_type& key, const char* str) noexcept {
  return mac(key, str, std::strlen(str));
}

inline auto mac(const key_type& key, const std::string& str) noexcept {
  return mac(key, str.c_str(), str.size());
}

inline auto string(const mac_type& m) {
  std::stringstream stream{};
  stream << std::hex << std::setfill('0');
  for (int i = 0; i < m.size(); ++i) stream << std::setw(2) << int(m[i]);
  return stream.str();
}

}  // namespace cbc_mac

}  // namespace lyrahgames::cipher
