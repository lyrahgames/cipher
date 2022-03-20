#pragma once
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
//
#include <lyrahgames/cipher/aes/add_round_key.hpp>
#include <lyrahgames/cipher/aes/basic_block.hpp>
#include <lyrahgames/cipher/aes/basic_key.hpp>
#include <lyrahgames/cipher/aes/expand_key.hpp>
#include <lyrahgames/cipher/aes/mix_columns.hpp>
#include <lyrahgames/cipher/aes/mul2.hpp>
#include <lyrahgames/cipher/aes/s_box.hpp>
#include <lyrahgames/cipher/aes/shift_rows.hpp>
#include <lyrahgames/cipher/aes/sub_bytes.hpp>

namespace lyrahgames::cipher {

namespace aes {

struct cipher {
  static constexpr size_t key_size = 16;
  static constexpr size_t block_size = 16;
  static constexpr size_t rounds = 10;

  using block_type = basic_block;
  using key_type = basic_key;
  struct round_keys_type;

  static constexpr auto random_block(auto&& rng) noexcept -> block_type;
  static constexpr auto random_key(auto&& rng) noexcept -> key_type;

  static constexpr auto expansion(const key_type& key) noexcept
      -> round_keys_type;

  /// Out-of-Place Block Encryption
  /// The given blocks 'src' and 'dst' do not have to be distinct.
  void encrypt(const round_keys_type& round_keys,
               const block_type& src,
               block_type& dst) noexcept;

  /// In-Place Block Encryption
  void encrypt(const round_keys_type& round_keys, block_type& block) noexcept;

  /// Function-Style Block Encryption
  auto encryption(const round_keys_type& round_keys,
                  const block_type& block) noexcept -> block_type;

  /// Out-of-Place Block Decryption
  /// The given blocks 'src' and 'dst' do not have to be distinct
  void decrypt(const round_keys_type& round_keys,
               const block_type& src,
               block_type& dst) noexcept;

  /// In-Place Block Decryption
  void decrypt(const round_keys_type& round_keys, block_type& block) noexcept;

  /// Function-Style Block Decryption
  auto decryption(const round_keys_type& round_keys,
                  const block_type& block) noexcept -> block_type;

 private:
  static void add_round_key(const block_type& round_key,
                            block_type& block) noexcept;
  //
  static void sub_bytes(block_type& block) noexcept;
  static void inv_sub_bytes(block_type& block) noexcept;
  //
  static void shift_rows(const block_type& src, block_type& dst) noexcept;
  static void inv_shift_rows(const block_type& src, block_type& dst) noexcept;
  //
  // src and dst must be distinct blocks.
  static void mix_columns(const block_type& src, block_type& dst) noexcept;
  static void inv_mix_columns(const block_type& src, block_type& dst) noexcept;

 private:
  // State
  block_type buffer{};
};

}  // namespace aes

using aes128 = aes::cipher;

}  // namespace lyrahgames::cipher

#include "aes.ipp"
