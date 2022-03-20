namespace lyrahgames::cipher {

constexpr void aes128::expand_key(uint8_t* round_keys) noexcept {
  uint8_t rc = 1;
  for (size_t p = block_size; p <= rounds * block_size; p += block_size) {
    memcpy(&round_keys[p], &round_keys[p - block_size], block_size);
    round_keys[p + 0] ^= s_box(round_keys[p + 0 - 3]) ^ rc;
    round_keys[p + 1] ^= s_box(round_keys[p + 1 - 3]);
    round_keys[p + 2] ^= s_box(round_keys[p + 2 - 3]);
    round_keys[p + 3] ^= s_box(round_keys[p + 3 - 7]);
    for (int j = 4; j < block_size; ++j)
      round_keys[p + j] ^= round_keys[p + j - 4];
    rc = mul2(rc);
  }
}

constexpr void aes128::expand_key(const uint8_t* key,
                                  uint8_t* round_keys) noexcept {
  // for (int i = 0; i < 16; ++i) round_keys[i] = key[i];
  memcpy(round_keys, key, block_size);
  expand_key(round_keys);
}

constexpr aes128::round_keys_type::round_keys_type(
    const key_type& key) noexcept {
  expand_key((const uint8_t*)key.data, (uint8_t*)data);
};

constexpr void aes128::encrypt(const uint8_t* keys,  //
                               const uint8_t* src,
                               uint8_t* dst) noexcept {
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

// inline void aes128::encrypt(const round_keys_type& round_keys,  //
//                             block_type& src,
//                             block_type& dst) noexcept {
//   add_round_key(round_keys.data[0], src);
//   for (size_t i = 1; i < rounds; ++i) {
//     sub_bytes(src);
//     shift_rows(src, dst);
//     mix_columns(dst, src);
//     add_round_key(round_keys.data[i], src);
//   }
//   sub_bytes(src);
//   shift_rows(src, dst);
//   add_round_key(round_keys.data[rounds], dst);
// }

inline void aes128::encrypt(const round_keys_type& round_keys,
                            const block_type& src,
                            block_type& dst) noexcept {
  buffer = src;
  add_round_key(round_keys.data[0], buffer);
  for (size_t i = 1; i < rounds; ++i) {
    sub_bytes(buffer);
    shift_rows(buffer, dst);
    mix_columns(dst, buffer);
    add_round_key(round_keys.data[i], buffer);
  }
  sub_bytes(buffer);
  shift_rows(buffer, dst);
  add_round_key(round_keys.data[rounds], dst);
}

inline void aes128::encrypt(const round_keys_type& round_keys,
                            block_type& block) noexcept {
  encrypt(round_keys, block, block);
}

inline auto aes128::encryption(const round_keys_type& round_keys,
                               const block_type& block) noexcept -> block_type {
  block_type result{};
  encrypt(round_keys, block, result);
  return result;
}

constexpr void aes128::decrypt(const uint8_t* keys,  //
                               const uint8_t* src,
                               uint8_t* dst) noexcept {
  uint8_t tmp[block_size];
  add_round_key(keys + block_size * rounds, src, dst);
  inv_shift_rows(dst, tmp);
  inv_sub_bytes(tmp);
  for (size_t i = rounds - 1; i > 0; --i) {
    add_round_key(keys + block_size * i, tmp);
    inv_mix_columns(tmp, dst);
    inv_shift_rows(dst, tmp);
    inv_sub_bytes(tmp);
  }
  add_round_key(keys, tmp, dst);
}

// inline void aes128::decrypt(const round_keys_type& round_keys,  //
//                             block_type& src,
//                             block_type& dst) noexcept {
//   add_round_key(round_keys.data[rounds], src);
//   inv_shift_rows(src, dst);
//   inv_sub_bytes(dst);
//   for (size_t i = rounds - 1; i > 0; --i) {
//     add_round_key(round_keys.data[i], dst);
//     inv_mix_columns(dst, src);
//     inv_shift_rows(src, dst);
//     inv_sub_bytes(dst);
//   }
//   add_round_key(round_keys.data[0], dst);
// }

inline void aes128::decrypt(const round_keys_type& round_keys,  //
                            const block_type& src,
                            block_type& dst) noexcept {
  buffer = src;
  add_round_key(round_keys.data[rounds], buffer);
  inv_shift_rows(buffer, dst);
  inv_sub_bytes(dst);
  for (size_t i = rounds - 1; i > 0; --i) {
    add_round_key(round_keys.data[i], dst);
    inv_mix_columns(dst, buffer);
    inv_shift_rows(buffer, dst);
    inv_sub_bytes(dst);
  }
  add_round_key(round_keys.data[0], dst);
}

inline void aes128::decrypt(const round_keys_type& round_keys,
                            block_type& block) noexcept {
  decrypt(round_keys, block, block);
}

inline auto aes128::decryption(const round_keys_type& round_keys,
                               const block_type& block) noexcept -> block_type {
  block_type result{};
  decrypt(round_keys, block, result);
  return result;
}

constexpr auto aes128::s_box(uint8_t x) noexcept -> uint8_t {
  return s_box_lut[x];
}

constexpr auto aes128::inv_s_box(uint8_t x) noexcept -> uint8_t {
  return inv_s_box_lut[x];
}

constexpr auto aes128::mul2(uint8_t x) noexcept -> uint8_t {
  constexpr uint8_t mod = 0b0001'1011;
  return (x << 1) ^ ((int8_t(x) >> 7) & mod);
}

constexpr auto aes128::mul2(uint64_t x) noexcept -> uint64_t {
  constexpr uint64_t mod = 0x1b'1b'1b'1b'1b'1b'1b'1b;
  uint64_t mask = x & 0x80'80'80'80'80'80'80'80;
  mask = (mask >> 1) | mask;
  mask = (mask >> 2) | mask;
  mask = (mask >> 4) | mask;
  return ((x << 1) & 0xfe'fe'fe'fe'fe'fe'fe'fe) ^ (mask & mod);
}

constexpr void aes128::sub_bytes(uint8_t* data) noexcept {
  for (size_t i = 0; i < block_size; ++i) data[i] = s_box(data[i]);
}

inline void aes128::sub_bytes(aes128::block_type& block) noexcept {
  sub_bytes(reinterpret_cast<uint8_t*>(block.data));
}

constexpr void aes128::inv_sub_bytes(uint8_t* data) noexcept {
  for (size_t i = 0; i < block_size; ++i) data[i] = inv_s_box(data[i]);
}

inline void aes128::inv_sub_bytes(aes128::block_type& block) noexcept {
  inv_sub_bytes(reinterpret_cast<uint8_t*>(block.data));
}

constexpr auto aes128::shift_rows_index(size_t index) noexcept -> size_t {
  return shift_rows_lut[index];
}

constexpr auto aes128::inv_shift_rows_index(size_t index) noexcept -> size_t {
  return inv_shift_rows_lut[index];
}

constexpr void aes128::shift_rows(const uint8_t* src, uint8_t* dst) noexcept {
  for (size_t i = 0; i < block_size; ++i) dst[i] = src[shift_rows_index(i)];
}

inline void aes128::shift_rows(const block_type& src,
                               block_type& dst) noexcept {
  shift_rows(reinterpret_cast<const uint8_t*>(src.data),
             reinterpret_cast<uint8_t*>(dst.data));
}

constexpr void aes128::inv_shift_rows(const uint8_t* src,
                                      uint8_t* dst) noexcept {
  for (size_t i = 0; i < block_size; ++i) dst[i] = src[inv_shift_rows_index(i)];
}

inline void aes128::inv_shift_rows(const block_type& src,
                                   block_type& dst) noexcept {
  inv_shift_rows(reinterpret_cast<const uint8_t*>(src.data),
                 reinterpret_cast<uint8_t*>(dst.data));
}

constexpr void aes128::add_round_key(const uint8_t* round_key,  //
                                     const uint8_t* src,
                                     uint8_t* dst) noexcept {
  for (size_t i = 0; i < block_size; ++i) dst[i] = round_key[i] ^ src[i];
}

constexpr void aes128::add_round_key(const uint8_t* round_key,
                                     uint8_t* data) noexcept {
  for (size_t i = 0; i < block_size; ++i) data[i] ^= round_key[i];
}

constexpr void aes128::add_round_key(const uint64_t* round_key,
                                     uint64_t* block) noexcept {
  block[0] ^= round_key[0];
  block[1] ^= round_key[1];
}

inline void aes128::add_round_key(const block_type& round_key,
                                  block_type& block) noexcept {
  add_round_key(reinterpret_cast<const uint64_t*>(round_key.data),
                reinterpret_cast<uint64_t*>(block.data));
}

constexpr void aes128::shift_rows_and_add_round_key(const uint8_t* round_key,
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

constexpr void aes128::mix_column(const uint8_t* src,
                                  uint8_t* col,  //
                                  size_t i,
                                  size_t j,  //
                                  size_t k,
                                  size_t l) noexcept {
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

constexpr void aes128::mix_column(const uint8_t* src, uint8_t* col) noexcept {
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

constexpr void aes128::shift_rows_and_mix_columns(const uint8_t* src,
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

constexpr void aes128::mix_columns(const uint8_t* src, uint8_t* dst) noexcept {
  mix_column(&src[0], &dst[0]);
  mix_column(&src[4], &dst[4]);
  mix_column(&src[8], &dst[8]);
  mix_column(&src[12], &dst[12]);
}

constexpr auto aes128::mix_columns(const uint64_t x) noexcept -> uint64_t {
  const auto x2 = mul2(x);
  const auto x3 = x2 ^ x;
  uint64_t result =
      ((x << 8) & 0xffffff00'ffffff00) | ((x >> 24) & 0x000000ff'000000ff);
  result ^=
      ((x << 16) & 0xffff0000'ffff0000) | ((x >> 16) & 0x0000ffff'0000ffff);
  result ^= x2;
  result ^=
      ((x3 << 24) & 0xff000000'ff000000) | ((x3 >> 8) & 0x00ffffff'00ffffff);
  return result;
}

constexpr auto aes128::mix_columns(const uint64_t src[2],
                                   uint64_t dst[2]) noexcept {
  dst[0] = mix_columns(src[0]);
  dst[1] = mix_columns(src[1]);
}

inline void aes128::mix_columns(const block_type& src,
                                block_type& dst) noexcept {
  mix_columns(reinterpret_cast<const uint64_t*>(src.data),
              reinterpret_cast<uint64_t*>(dst.data));
}

constexpr void aes128::inv_mix_column(const uint8_t* src,
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

constexpr void aes128::inv_mix_columns(const uint8_t* src,
                                       uint8_t* dst) noexcept {
  inv_mix_column(&src[0], &dst[0]);
  inv_mix_column(&src[4], &dst[4]);
  inv_mix_column(&src[8], &dst[8]);
  inv_mix_column(&src[12], &dst[12]);
}

constexpr auto aes128::inv_mix_columns(const uint64_t x) noexcept -> uint64_t {
  const auto x2 = mul2(x);
  const auto x4 = mul2(x2);
  const auto x8 = mul2(x4);
  const auto x9 = x8 ^ x;
  const auto x11 = x9 ^ x2;
  const auto x13 = x9 ^ x4;
  const auto x14 = x8 ^ x4 ^ x2;
  uint64_t result =
      ((x9 << 8) & 0xffffff00'ffffff00) | ((x9 >> 24) & 0x000000ff'000000ff);
  result ^=
      ((x11 << 24) & 0xff000000'ff000000) | ((x11 >> 8) & 0x00ffffff'00ffffff);
  result ^=
      ((x13 << 16) & 0xffff0000'ffff0000) | ((x13 >> 16) & 0x0000ffff'0000ffff);
  result ^= x14;
  return result;
}

constexpr void aes128::inv_mix_columns(const uint64_t src[2],
                                       uint64_t dst[2]) noexcept {
  dst[0] = inv_mix_columns(src[0]);
  dst[1] = inv_mix_columns(src[1]);
}

inline void aes128::inv_mix_columns(const block_type& src,
                                    block_type& dst) noexcept {
  inv_mix_columns(reinterpret_cast<const uint64_t*>(src.data),
                  reinterpret_cast<uint64_t*>(dst.data));
}

}  // namespace lyrahgames::cipher
