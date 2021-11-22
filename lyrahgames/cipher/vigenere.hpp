#pragma once
#include <cassert>
#include <map>
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

  static constexpr auto frequency_analysis(
      block most_frequent,
      size_t key_size,
      const generic::input_range<block> auto& text) -> key_type {
    // Use (hash) map to count frequencies.
    std::vector<std::map<block, int>> frequency(key_size);
    // Count frequencies.
    for (size_t k = 0; auto c : text) {
      ++frequency[k][c];
      k = (k + 1) % key_size;
    }
    key_type key(key_size);
    for (size_t i = 0; i < key_size; ++i) {
      const auto max_it =
          std::max_element(begin(frequency[i]), end(frequency[i]),
                           [](auto x, auto y) { return x.second < y.second; });
      // Compute shift of most frequent block.
      key[i] = max_it->first - most_frequent;
    }
    return key;
  }
};

}  // namespace lyrahgames::cipher
