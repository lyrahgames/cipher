#pragma once
#include <bit>
#include <tuple>
//
#include <lyrahgames/cipher/meta.hpp>

namespace lyrahgames::cipher {

template <typename integer>
constexpr auto egcd(integer p, integer q) noexcept {
  integer s0 = 1, s1 = 0;
  integer t0 = 0, t1 = 1;
  while (q != 0) {
    const auto r = p / q;
    const auto a = p - r * q;
    const auto b = s0 - r * s1;
    const auto c = t0 - r * t1;
    p = q;
    q = a;
    s0 = s1;
    s1 = b;
    t0 = t1;
    t1 = c;
  }
  return std::tuple{p, s0, t0};
}

template <std::unsigned_integral uint>
constexpr auto f2_polynom_mul(uint m, uint n) noexcept {
  uint result = 0;
  for (int i = 0; i < 8 * sizeof(uint); ++i)
    if ((n >> i) & 1) result ^= m << i;
  return result;
}

template <std::unsigned_integral uint>
constexpr auto f2_polynom_divmod(uint m, uint n) noexcept {
  using std::bit_width;
  const auto t = bit_width(n);
  uint q = 0;
  auto s = bit_width(m);
  while (s >= t) {
    const auto shift = s - t;
    q ^= 1 << shift;
    m ^= n << shift;
    s = bit_width(m);
  }
  return std::pair{q, m};
}

template <std::unsigned_integral uint>
constexpr auto f2_polynom_inv(uint x, uint mod) noexcept {
  uint t0 = 0, t1 = 1;
  uint r0 = mod, r1 = x;
  while (r1) {
    const auto [q, r] = f2_polynom_divmod(r0, r1);
    r0 = r1;
    r1 = r;
    const auto t = t0 ^ f2_polynom_mul(q, t1);
    t0 = t1;
    t1 = t;
  }
  return t0;
}

constexpr auto aes_s_box(uint8_t x) noexcept -> uint8_t {
  using namespace std;
  const auto p = 0b1'0001'1011u;
  const uint8_t b = f2_polynom_inv(uint16_t(x), uint16_t(p));
  const uint8_t s =
      b ^ rotl(b, 1) ^ rotl(b, 2) ^ rotl(b, 3) ^ rotl(b, 4) ^ uint8_t(0x63);
  return s;
}

constexpr auto aes_inv_s_box(uint8_t x) noexcept -> uint8_t {
  using namespace std;
  const uint8_t b = rotl(x, 1) ^ rotl(x, 3) ^ rotl(x, 6) ^ uint8_t(0x05);
  const auto p = 0b1'0001'1011u;
  const uint8_t s = f2_polynom_inv(uint16_t(b), uint16_t(p));
  return s;
}

struct aes_block {
  std::array<uint8_t, 16> data;
};

constexpr auto aes_sub_bytes(aes_block block) noexcept -> aes_block {
  aes_block result;
  for (int i = 0; i < 16; ++i) result.data[i] = aes_s_box(block.data[i]);
  return result;
}

constexpr auto aes_shift_rows(aes_block block) noexcept -> aes_block {
  aes_block result{{
      block.data[0],
      block.data[5],
      block.data[10],
      block.data[15],

      block.data[1],
      block.data[6],
      block.data[11],
      block.data[12],

      block.data[2],
      block.data[7],
      block.data[8],
      block.data[13],

      block.data[3],
      block.data[4],
      block.data[9],
      block.data[14],
  }};
  return result;
}

constexpr auto aes_mix_columns(aes_block block) noexcept -> aes_block {
  aes_block result;

  return result;
}

struct galois8 {
  constexpr galois8() = default;
  explicit constexpr galois8(uint8_t x) : data{x} {}
  friend constexpr auto operator<=>(const galois8&,
                                    const galois8&) noexcept = default;
  uint8_t data;
};

constexpr auto operator+(galois8 x) noexcept -> galois8 {
  return x;
}

constexpr auto operator-(galois8 x) noexcept -> galois8 {
  return x;
}

constexpr auto operator+(galois8 x, galois8 y) noexcept -> galois8 {
  return galois8(x.data ^ y.data);
}

constexpr auto operator-(galois8 x, galois8 y) noexcept -> galois8 {
  return x + y;
}

constexpr auto operator*(galois8 x, galois8 y) noexcept -> galois8 {
  // uint16_t a = x.data;
  // uint16_t b = y.data;
  // uint16_t result = 0;
  // for (int i = 0; i < 8; ++i) {
  //   if ((b >> i) & 1) result ^= (a << i);
  // }
  // uint8_t mod = result >> 8;
  // if ((mod >> 0) & 1) result ^= 0b00011011;
  // if ((mod >> 1) & 1) result ^= 0b00110110;
  // if ((mod >> 2) & 1) result ^= 0b01101100;
  // if ((mod >> 3) & 1) result ^= 0b11011000;
  // if ((mod >> 4) & 1) result ^= 0b10101011;
  // if ((mod >> 5) & 1) result ^= 0b01001101;
  // if ((mod >> 6) & 1) result ^= 0b10011010;
  // return galois8(result);

  // const auto t = f2_polynom_mul(uint16_t(x.data), uint16_t(y.data));
  // const auto [q, r] = f2_polynom_divmod(t, uint16_t(0b1'0001'1011u));
  // return galois8(r);

  using namespace std;
  constexpr uint8_t mod = 0b0001'1011;

  auto p = x.data;  // p(x)
  auto q = y.data;  // q(x)
  uint8_t r = 0;    // result r(x) = p(x) * q(x)

  while (q) {
    r ^= (q & 1) ? p : 0;
    q >>= 1;
    p = (p << 1) ^ ((p & 0x80) ? mod : 0);  // p(x) = x * p(x)
  }

  return galois8(r);
}

constexpr auto operator~(galois8 x) noexcept -> galois8 {
  const auto p = 0b1'0001'1011u;
  return galois8(f2_polynom_inv(uint16_t(x.data), uint16_t(p)));
}

constexpr auto operator/(galois8 x, galois8 y) noexcept {
  return x * ~y;
}

}  // namespace lyrahgames::cipher
