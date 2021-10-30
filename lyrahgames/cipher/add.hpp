#pragma once
#include <algorithm>
#include <cassert>
#include <map>
//
#include <lyrahgames/cipher/meta.hpp>

namespace lyrahgames::cipher {

template <generic::add_block T>
struct add {
  using block = T;

  /// Returns randomly generated key for additive cipher.
  static constexpr auto random_key(auto&& rng) {
    return block(std::forward<decltype(rng)>(rng)());
  }

  /// Additive Encryption for Single Block
  static constexpr auto encryption(block key, block data) -> block {
    return data + key;
  }

  /// Additive Decryption for Single Block
  static constexpr auto decryption(block key, block data) -> block {
    return data - key;
  }

  /// Additive Encryption for Single Block
  /// Alternative that operates directly on the given block.
  static constexpr void encrypt(block key, block& data) {
    data = encryption(key, data);
  }

  /// Additive Decryption for Single Block
  /// Alternative that operates directly on the given block.
  static constexpr void decrypt(block key, block& data) {
    data = decryption(key, data);
  }

  /// Out-Of-Place Additive Encryption for Ranges of Blocks
  static constexpr void encrypt(block key,
                                const generic::input_range<block> auto& input,
                                generic::output_range<block> auto& output) {
    assert(std::ranges::size(input) == std::ranges::size(output));
    // Use standard transform algorithm to
    // apply encryption on every contained block.
    std::transform(begin(input), end(input), begin(output), [key](auto data) {
      return encryption(key, static_cast<block>(data));
    });
  }

  /// Out-Of-Place Additive Decryption for Ranges of Blocks
  static constexpr void decrypt(block key,
                                const generic::input_range<block> auto& input,
                                generic::output_range<block> auto& output) {
    assert(std::ranges::size(input) == std::ranges::size(output));
    // Use standard transform algorithm to
    // apply decryption on every contained block.
    std::transform(begin(input), end(input), begin(output), [key](auto data) {
      return decryption(key, static_cast<block>(data));
    });
  }

  /// In-Place Additive Encryption for Ranges of Blocks
  static constexpr void encrypt(block key, generic::range<block> auto& data) {
    // Use standard transform algorithm to
    // apply encryption on every contained block.
    std::transform(begin(data), end(data), begin(data), [key](auto data) {
      return encryption(key, static_cast<block>(data));
    });
  }

  /// In-Place Additive Decryption for Ranges of Blocks
  static constexpr void decrypt(block key, generic::range<block> auto& data) {
    // Use standard transform algorithm to
    // apply decryption on every contained block.
    std::transform(begin(data), end(data), begin(data), [key](auto data) {
      return decryption(key, static_cast<block>(data));
    });
  }

  /// Does frequency analysis on given range of encrypted blocks and
  /// tries to estimate the key and returns it.
  static constexpr auto frequency_analysis(
      block most_frequent,
      const generic::input_range<block> auto& text) -> block {
    // Use (hash) map to count frequencies.
    std::map<block, int> frequency{};
    // Count frequencies.
    for (auto c : text)
      ++frequency[c];
    const auto max_it =
        std::max_element(begin(frequency), end(frequency),
                         [](auto x, auto y) { return x.second < y.second; });
    // Compute shift of most frequent block.
    return max_it->first - most_frequent;
  }
};

}  // namespace lyrahgames::cipher
