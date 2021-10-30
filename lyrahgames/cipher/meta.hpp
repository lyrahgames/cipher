#pragma once
#include <concepts>
#include <ranges>
//
#include <lyrahgames/xstd/forward.hpp>

namespace lyrahgames::cipher {

namespace generic {

using namespace lyrahgames::xstd::generic;

template <typename T>
concept add_block = std::regular<T> && requires(const T x, const T y) {
  // { x + y } -> identical<T>;
  // { x - y } -> identical<T>;

  // Allows to use builtin types, such as char.
  { x + y } -> forwardable<T>;
  { x - y } -> forwardable<T>;

  // { x + y == y + x };
  // existence of neutral
  // { x + T{} == x };
  // existence of inverse
  // { x - x == T{} };
};

template <typename T, typename U>
concept input_range = std::ranges::input_range<T> &&
    forwardable<std::ranges::range_value_t<T>, U>;

template <typename T, typename U>
concept output_range = std::ranges::output_range<T, U>;

template <typename T, typename U>
concept range = input_range<T, U> && output_range<T, U>;

}  // namespace generic

}  // namespace lyrahgames::cipher
