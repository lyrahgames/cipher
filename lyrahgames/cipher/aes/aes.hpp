#pragma once
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>

namespace lyrahgames::cipher {

struct aes128 {
  static constexpr size_t key_size = 16;
  static constexpr size_t block_size = 16;
  static constexpr size_t rounds = 10;

  static constexpr uint8_t s_box_lut[256] = {
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,  //
      0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  //
      0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,  //
      0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  //
      0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,  //
      0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  //
      0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,  //
      0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  //
      0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,  //
      0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  //
      0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,  //
      0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  //
      0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,  //
      0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  //
      0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,  //
      0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  //
      0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,  //
      0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  //
      0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,  //
      0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  //
      0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,  //
      0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  //
      0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,  //
      0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  //
      0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,  //
      0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  //
      0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,  //
      0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  //
      0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,  //
      0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  //
      0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,  //
      0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,  //
  };

  static constexpr std::array<uint8_t, 256> inv_s_box_lut{
      0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,  //
      0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,  //
      0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,  //
      0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,  //
      0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,  //
      0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,  //
      0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,  //
      0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,  //
      0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,  //
      0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,  //
      0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,  //
      0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,  //
      0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,  //
      0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,  //
      0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,  //
      0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,  //
      0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,  //
      0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,  //
      0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,  //
      0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,  //
      0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,  //
      0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,  //
      0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,  //
      0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,  //
      0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,  //
      0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,  //
      0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,  //
      0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,  //
      0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,  //
      0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,  //
      0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,  //
      0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,  //
  };

  static constexpr size_t shift_rows_lut[] = {
      0,  5,  10, 15,  //
      4,  9,  14, 3,   //
      8,  13, 2,  7,   //
      12, 1,  6,  11,  //
  };

  static constexpr size_t inv_shift_rows_lut[] = {
      0,  13, 10, 7,   //
      4,  1,  14, 11,  //
      8,  5,  2,  15,  //
      12, 9,  6,  3,   //
  };

  struct block_type {
    // Automatically fulfills 8-byte alignment.
    uint64_t data[block_size / sizeof(uint64_t)];
  };

  static_assert(sizeof(block_type) == block_size);
  static_assert(alignof(block_type) == alignof(uint64_t));

  static constexpr auto s_box(uint8_t x) noexcept -> uint8_t {
    return s_box_lut[x];
  }

  static constexpr auto inv_s_box(uint8_t x) noexcept -> uint8_t {
    return inv_s_box_lut[x];
  }

  static constexpr void sub_bytes(uint8_t* data) noexcept {
    for (size_t i = 0; i < block_size; ++i) data[i] = s_box(data[i]);
  }

  static constexpr void sub_bytes(block_type& block) noexcept {
    auto data = reinterpret_cast<uint8_t*>(block.data);
    for (size_t i = 0; i < block_size; ++i) data[i] = s_box(data[i]);
  }

  static constexpr void inv_sub_bytes(uint8_t* data) noexcept {
    for (size_t i = 0; i < block_size; ++i) data[i] = inv_s_box(data[i]);
  }

  static constexpr auto shift_rows_index(size_t index) noexcept -> size_t {
    return shift_rows_lut[index];
  }

  static constexpr auto inv_shift_rows_index(size_t index) noexcept -> size_t {
    return inv_shift_rows_lut[index];
  }

  static constexpr void add_round_key(const uint8_t* round_key,  //
                                      const uint8_t* src,
                                      uint8_t* dst) noexcept {
    for (size_t i = 0; i < block_size; ++i) dst[i] = round_key[i] ^ src[i];
  }

  static constexpr void add_round_key(const uint8_t* round_key,
                                      uint8_t* data) noexcept {
    for (size_t i = 0; i < block_size; ++i) data[i] ^= round_key[i];
  }

  static constexpr auto mul2(uint8_t x) noexcept -> uint8_t {
    constexpr uint8_t mod = 0b0001'1011;
    return (x << 1) ^ ((int8_t(x) >> 7) & mod);
  }

  static constexpr auto mul2(uint64_t x) noexcept -> uint64_t {
    constexpr uint64_t mod = 0x1b'1b'1b'1b'1b'1b'1b'1b;
    uint64_t mask = x & 0x80'80'80'80'80'80'80'80;
    mask = (mask >> 1) | mask;
    mask = (mask >> 2) | mask;
    mask = (mask >> 4) | mask;
    return ((x << 1) & 0xfe'fe'fe'ff) ^ (mask & mod);
  }

  static constexpr auto expand(uint8_t* round_keys) noexcept {
    uint8_t rc = 1;
    size_t q = 0;
    for (size_t p = block_size; p <= rounds * block_size; p += block_size) {
      memcpy(&round_keys[p], &round_keys[q], block_size);
      round_keys[p + 0] ^= s_box(round_keys[p + 0 - 3]) ^ rc;
      round_keys[p + 1] ^= s_box(round_keys[p + 1 - 3]);
      round_keys[p + 2] ^= s_box(round_keys[p + 2 - 3]);
      round_keys[p + 3] ^= s_box(round_keys[p + 3 - 7]);
      for (int j = 4; j < block_size; ++j)
        round_keys[p + j] ^= round_keys[p + j - 4];
      rc = mul2(rc);
      q = p;
    }
  }

  static constexpr auto expand(const uint8_t* key,
                               uint8_t* round_keys) noexcept {
    for (int i = 0; i < 16; ++i) round_keys[i] = key[i];
    expand(round_keys);
  }

  static constexpr void shift_rows_and_add_round_key(const uint8_t* round_key,
                                                     const uint8_t* src,
                                                     uint8_t* dst) noexcept {
    dst[0] = round_key[0] ^ src[shift_rows_index(0)];
    dst[1] = round_key[1] ^ src[shift_rows_index(1)];
    dst[2] = round_key[2] ^ src[shift_rows_index(2)];
    dst[3] = round_key[3] ^ src[shift_rows_index(3)];
    dst[4] = round_key[4] ^ src[shift_rows_index(4)];
    dst[5] = round_key[5] ^ src[shift_rows_index(5)];
    dst[6] = round_key[6] ^ src[shift_rows_index(6)];
    dst[7] = round_key[7] ^ src[shift_rows_index(7)];
    dst[8] = round_key[8] ^ src[shift_rows_index(8)];
    dst[9] = round_key[9] ^ src[shift_rows_index(9)];
    dst[10] = round_key[10] ^ src[shift_rows_index(10)];
    dst[11] = round_key[11] ^ src[shift_rows_index(11)];
    dst[12] = round_key[12] ^ src[shift_rows_index(12)];
    dst[13] = round_key[13] ^ src[shift_rows_index(13)];
    dst[14] = round_key[14] ^ src[shift_rows_index(14)];
    dst[15] = round_key[15] ^ src[shift_rows_index(15)];
  }

  static constexpr void mix_column(const uint8_t* src, uint8_t* col,  //
                                   size_t i, size_t j,                //
                                   size_t k, size_t l) noexcept {
    {
      const uint8_t x = src[i];
      const uint8_t x2 = mul2(x);
      const uint8_t x3 = x2 ^ x;
      col[0] = x2;
      col[1] = x;
      col[2] = x;
      col[3] = x3;
    }
    {
      const uint8_t x = src[j];
      const uint8_t x2 = mul2(x);
      const uint8_t x3 = x2 ^ x;
      col[0] ^= x3;
      col[1] ^= x2;
      col[2] ^= x;
      col[3] ^= x;
    }
    {
      const uint8_t x = src[k];
      const uint8_t x2 = mul2(x);
      const uint8_t x3 = x2 ^ x;
      col[0] ^= x;
      col[1] ^= x3;
      col[2] ^= x2;
      col[3] ^= x;
    }
    {
      const uint8_t x = src[l];
      const uint8_t x2 = mul2(x);
      const uint8_t x3 = x2 ^ x;
      col[0] ^= x;
      col[1] ^= x;
      col[2] ^= x3;
      col[3] ^= x2;
    }
  }

  static constexpr void mix_column(const uint8_t* src, uint8_t* col) noexcept {
    {
      const uint8_t x = src[0];
      const uint8_t x2 = mul2(x);
      const uint8_t x3 = x2 ^ x;
      col[0] = x2;
      col[1] = x;
      col[2] = x;
      col[3] = x3;
    }
    {
      const uint8_t x = src[1];
      const uint8_t x2 = mul2(x);
      const uint8_t x3 = x2 ^ x;
      col[0] ^= x3;
      col[1] ^= x2;
      col[2] ^= x;
      col[3] ^= x;
    }
    {
      const uint8_t x = src[2];
      const uint8_t x2 = mul2(x);
      const uint8_t x3 = x2 ^ x;
      col[0] ^= x;
      col[1] ^= x3;
      col[2] ^= x2;
      col[3] ^= x;
    }
    {
      const uint8_t x = src[3];
      const uint8_t x2 = mul2(x);
      const uint8_t x3 = x2 ^ x;
      col[0] ^= x;
      col[1] ^= x;
      col[2] ^= x3;
      col[3] ^= x2;
    }
  }

  static constexpr void shift_rows_and_mix_columns(const uint8_t* src,
                                                   uint8_t* dst) noexcept {
    mix_column(src, &dst[0],                              //
               shift_rows_index(0), shift_rows_index(1),  //
               shift_rows_index(2), shift_rows_index(3));
    mix_column(src, &dst[4],                              //
               shift_rows_index(4), shift_rows_index(5),  //
               shift_rows_index(6), shift_rows_index(7));
    mix_column(src, &dst[8],                              //
               shift_rows_index(8), shift_rows_index(9),  //
               shift_rows_index(10), shift_rows_index(11));
    mix_column(src, &dst[12],                               //
               shift_rows_index(12), shift_rows_index(13),  //
               shift_rows_index(14), shift_rows_index(15));
  }

  static constexpr void mix_columns(const uint8_t* src, uint8_t* dst) noexcept {
    mix_column(&src[0], &dst[0]);
    mix_column(&src[4], &dst[4]);
    mix_column(&src[8], &dst[8]);
    mix_column(&src[12], &dst[12]);
  }

  static constexpr auto mix_columns(const uint64_t src[2],
                                    uint64_t dst[2]) noexcept {
    {
      const auto x = src[0];
      const auto x2 = mul2(x);
      const auto x3 = x2 ^ x;
      dst[0] =
          ((x << 8) & 0xffffff00'ffffff00) | ((x >> 24) & 0x000000ff'000000ff);
      dst[0] ^=
          ((x << 16) & 0xffff000'ffff0000) | ((x >> 16) & 0x0000ffff'0000ffff);
      dst[0] ^= x2;
      dst[0] ^=
          ((x3 << 24) & 0xff000000'ff000000) | ((x >> 8) & 0x00ffffff'00ffffff);
    }
    {
      const auto x = src[1];
      const auto x2 = mul2(x);
      const auto x3 = x2 ^ x;
      dst[1] =
          ((x << 8) & 0xffffff00'ffffff00) | ((x >> 24) & 0x000000ff'000000ff);
      dst[1] ^=
          ((x << 16) & 0xffff000'ffff0000) | ((x >> 16) & 0x0000ffff'0000ffff);
      dst[1] ^= x2;
      dst[1] ^=
          ((x3 << 24) & 0xff000000'ff000000) | ((x >> 8) & 0x00ffffff'00ffffff);
    }
  }

  static constexpr void inv_mix_column(const uint8_t* src,
                                       uint8_t* col) noexcept {
    {
      const uint8_t x = src[0];
      const uint8_t x2 = mul2(x);
      const uint8_t x4 = mul2(x2);
      const uint8_t x8 = mul2(x4);
      const uint8_t x9 = x8 ^ x;
      const uint8_t x11 = x9 ^ x2;
      const uint8_t x13 = x9 ^ x4;
      const uint8_t x14 = x8 ^ x4 ^ x2;
      col[0] = x14;
      col[1] = x9;
      col[2] = x13;
      col[3] = x11;
    }
    {
      const uint8_t x = src[1];
      const uint8_t x2 = mul2(x);
      const uint8_t x4 = mul2(x2);
      const uint8_t x8 = mul2(x4);
      const uint8_t x9 = x8 ^ x;
      const uint8_t x11 = x9 ^ x2;
      const uint8_t x13 = x9 ^ x4;
      const uint8_t x14 = x8 ^ x4 ^ x2;
      col[0] ^= x11;
      col[1] ^= x14;
      col[2] ^= x9;
      col[3] ^= x13;
    }
    {
      const uint8_t x = src[2];
      const uint8_t x2 = mul2(x);
      const uint8_t x4 = mul2(x2);
      const uint8_t x8 = mul2(x4);
      const uint8_t x9 = x8 ^ x;
      const uint8_t x11 = x9 ^ x2;
      const uint8_t x13 = x9 ^ x4;
      const uint8_t x14 = x8 ^ x4 ^ x2;
      col[0] ^= x13;
      col[1] ^= x11;
      col[2] ^= x14;
      col[3] ^= x9;
    }
    {
      const uint8_t x = src[3];
      const uint8_t x2 = mul2(x);
      const uint8_t x4 = mul2(x2);
      const uint8_t x8 = mul2(x4);
      const uint8_t x9 = x8 ^ x;
      const uint8_t x11 = x9 ^ x2;
      const uint8_t x13 = x9 ^ x4;
      const uint8_t x14 = x8 ^ x4 ^ x2;
      col[0] ^= x9;
      col[1] ^= x13;
      col[2] ^= x11;
      col[3] ^= x14;
    }
  }

  static constexpr void inv_mix_columns(const uint8_t* src,
                                        uint8_t* dst) noexcept {
    inv_mix_column(&src[0], &dst[0]);
    inv_mix_column(&src[4], &dst[4]);
    inv_mix_column(&src[8], &dst[8]);
    inv_mix_column(&src[12], &dst[12]);
  }

  static constexpr void encrypt(const uint8_t* keys,  //
                                const uint8_t* src, uint8_t* dst) noexcept {
    uint8_t tmp[block_size];
    add_round_key(keys, src, tmp);
    for (size_t i = 1; i < rounds; ++i) {
      sub_bytes(tmp);
      shift_rows_and_mix_columns(tmp, dst);
      add_round_key(&keys[block_size * i], dst, tmp);
    }
    sub_bytes(tmp);
    shift_rows_and_add_round_key(&keys[block_size * rounds], tmp, dst);
  }

  static constexpr void shift_rows(uint8_t* data) noexcept {
    uint8_t t[16];
    for (int i = 0; i < 16; ++i) t[i] = data[i];
    for (int i = 0; i < 16; ++i) data[i] = t[shift_rows_index(i)];
  }

  static constexpr void inv_shift_rows(uint8_t* data) noexcept {
    uint8_t t[16];
    for (int i = 0; i < 16; ++i) t[i] = data[i];
    for (int i = 0; i < 16; ++i) data[i] = t[inv_shift_rows_index(i)];
  }

  static constexpr void decrypt(const uint8_t* keys,  //
                                const uint8_t* src, uint8_t* dst) noexcept {
    uint8_t tmp[block_size];
    add_round_key(keys + block_size * rounds, src, tmp);
    inv_shift_rows(tmp);
    inv_sub_bytes(tmp);
    for (size_t i = rounds - 1; i > 0; --i) {
      add_round_key(keys + block_size * i, tmp, dst);
      inv_mix_columns(dst, tmp);
      inv_shift_rows(tmp);
      inv_sub_bytes(tmp);
    }
    add_round_key(keys, tmp, dst);
  }
};

}  // namespace lyrahgames::cipher
