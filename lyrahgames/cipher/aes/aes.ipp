namespace lyrahgames::cipher {

namespace aes {

struct cipher::round_keys_type {
  constexpr round_keys_type(const key_type& key) noexcept;
  friend constexpr auto operator<=>(const round_keys_type&,
                                    const round_keys_type&) noexcept = default;

  constexpr const auto& operator[](size_t index) const noexcept {
    return data[index];
  }
  block_type data[rounds + 1];
};
static_assert(alignof(cipher::round_keys_type) == alignof(cipher::block_type));

constexpr auto cipher::random_key(auto&& rng) noexcept -> key_type {
  key_type result;
  result.data[0] = (rng() << 32) | rng();
  result.data[1] = (rng() << 32) | rng();
  return result;
}

constexpr auto cipher::random_block(auto&& rng) noexcept -> block_type {
  block_type result;
  result.data[0] = (rng() << 32) | rng();
  result.data[1] = (rng() << 32) | rng();
  return result;
}

constexpr cipher::round_keys_type::round_keys_type(
    const key_type& key) noexcept {
  expand_key_128((const uint8_t*)key.data, (uint8_t*)data);
};

constexpr auto cipher::expansion(const key_type& key) noexcept
    -> round_keys_type {
  return {key};
}

inline void cipher::encrypt(const round_keys_type& round_keys,
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

inline void cipher::encrypt(const round_keys_type& round_keys,
                            block_type& block) noexcept {
  encrypt(round_keys, block, block);
}

inline auto cipher::encryption(const round_keys_type& round_keys,
                               const block_type& block) noexcept -> block_type {
  block_type result{};
  encrypt(round_keys, block, result);
  return result;
}

inline void cipher::decrypt(const round_keys_type& round_keys,  //
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

inline void cipher::decrypt(const round_keys_type& round_keys,
                            block_type& block) noexcept {
  decrypt(round_keys, block, block);
}

inline auto cipher::decryption(const round_keys_type& round_keys,
                               const block_type& block) noexcept -> block_type {
  block_type result{};
  decrypt(round_keys, block, result);
  return result;
}

inline void cipher::add_round_key(const block_type& round_key,
                                  block_type& block) noexcept {
  add_round_key_128(reinterpret_cast<const uint64_t*>(round_key.data),
                    reinterpret_cast<uint64_t*>(block.data));
}

inline void cipher::sub_bytes(cipher::block_type& block) noexcept {
  sub_bytes_128(reinterpret_cast<uint8_t*>(block.data));
}

inline void cipher::inv_sub_bytes(cipher::block_type& block) noexcept {
  inv_sub_bytes_128(reinterpret_cast<uint8_t*>(block.data));
}

inline void cipher::shift_rows(const block_type& src,
                               block_type& dst) noexcept {
  shift_rows_128(reinterpret_cast<const uint8_t*>(src.data),
                 reinterpret_cast<uint8_t*>(dst.data));
}

inline void cipher::inv_shift_rows(const block_type& src,
                                   block_type& dst) noexcept {
  inv_shift_rows_128(reinterpret_cast<const uint8_t*>(src.data),
                     reinterpret_cast<uint8_t*>(dst.data));
}

inline void cipher::mix_columns(const block_type& src,
                                block_type& dst) noexcept {
  mix_columns_128(reinterpret_cast<const uint64_t*>(src.data),
                  reinterpret_cast<uint64_t*>(dst.data));
}

inline void cipher::inv_mix_columns(const block_type& src,
                                    block_type& dst) noexcept {
  inv_mix_columns_128(reinterpret_cast<const uint64_t*>(src.data),
                      reinterpret_cast<uint64_t*>(dst.data));
}

}  // namespace aes

}  // namespace lyrahgames::cipher
