#pragma once
#include <lyrahgames/xstd/forward.hpp>

namespace lyrahgames::cipher {

using namespace lyrahgames::xstd;

/// Type to encode ASCII characters in the range [0,128)
/// for correct en- and decryption.
struct ascii_block {
  using char_type = unsigned char;
  static constexpr char_type mask = 0b0111'1111;

  // Default constructor to make type regular.
  constexpr ascii_block() = default;

  // Implicit Construction for Any to-char-forwardable Type.
  // Makes number will be in the range [0,128).
  constexpr ascii_block(generic::forwardable<char_type> auto&& x)
      : data(forward_construct<char_type>(x) & mask) {}

  // Implicit cast to the underlying character type.
  constexpr operator char_type() { return data; }

  // Induce total order to make type regular and comparable.
  friend constexpr auto operator<=>(const ascii_block&,
                                    const ascii_block&) noexcept = default;

  char_type data{};
};

constexpr auto operator+(ascii_block x, ascii_block y) -> ascii_block {
  // Apply mask to make sure range will be [0,128);
  // return (x.data + y.data) & ascii_block::mask;

  // We do not need to apply the mask due to
  // implicit constructor which automatically applies it.
  return x.data + y.data;
}

constexpr auto operator-(ascii_block x, ascii_block y) -> ascii_block {
  // Apply mask to make sure range will be [0,128);
  // return (x.data - y.data) & ascii_block::mask;

  // We do not need to apply the mask due to
  // implicit constructor which automatically applies it.
  return x.data - y.data;
}

constexpr auto operator++(ascii_block& x) -> ascii_block& {
  x = x + ascii_block{1};
  return x;
}

constexpr auto operator--(ascii_block& x) -> ascii_block& {
  x = x - ascii_block{1};
  return x;
}

}  // namespace lyrahgames::cipher
