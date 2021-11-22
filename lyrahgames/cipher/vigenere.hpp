#pragma once
#include <random>
#include <vector>
//
#include <lyrahgames/cipher/meta.hpp>

namespace lyrahgames::cipher {

// The Vigenere cipher is not a block cipher due to the variable key size.
// Hence, de- and encryption either have to be stateful
// or directly done on ranges
template <generic::add_block T>
struct vigenere {
  using block = T;
  using key_type = std::vector<block>;

  /// Returns randomly generated key for additive cipher.
  static inline auto random_key(auto&& rng) {
    std::uniform_int_distribution<size_t> dist{2, 16};
    key_type key(dist(rng));
    for (auto& k : key)
      k = rng();
    return key;
  }

  static constexpr void encrypt(key_type key,
                                const generic::input_range<block> auto& input,
                                generic::output_range<block> auto& output) {
    assert(size(input) == size(output));
    auto it = begin(input);
    auto out = begin(output);
    for (; it != end(input);) {
      auto k = begin(key);
      for (; (k != end(key)) && (it != end(input)); ++k, ++it, ++out)
        *out = static_cast<block>(*it) + *k;
    }
  }

  static constexpr void decrypt(key_type key,
                                const generic::input_range<block> auto& input,
                                generic::output_range<block> auto& output) {
    assert(size(input) == size(output));
    auto it = begin(input);
    auto out = begin(output);
    for (; it != end(input);) {
      auto k = begin(key);
      for (; (k != end(key)) && (it != end(input)); ++k, ++it, ++out)
        *out = static_cast<block>(*it) - *k;
    }
  }

  static constexpr void encrypt(key_type key,
                                generic::range<block> auto& data) {
    encrypt(key, data, data);
  }

  /// In-Place Additive Decryption for Ranges of Blocks
  static constexpr void decrypt(key_type key,
                                generic::range<block> auto& data) {
    decrypt(key, data, data);
  }
};

}  // namespace lyrahgames::cipher
