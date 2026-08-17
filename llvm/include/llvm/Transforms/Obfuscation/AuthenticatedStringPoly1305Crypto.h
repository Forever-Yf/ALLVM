#ifndef LLVM_TRANSFORMS_OBFUSCATION_AUTHENTICATEDSTRINGPOLY1305CRYPTO_H
#define LLVM_TRANSFORMS_OBFUSCATION_AUTHENTICATEDSTRINGPOLY1305CRYPTO_H

// Keep the v1 primitives available for compiler-side record fingerprints, but
// hide the legacy record seal/open entrypoints. The production aliases below
// use RFC 8439 ChaCha20-Poly1305 semantics and record version 2.
#define allvm_str_seal_record allvm_str_legacy_seal_record
#define allvm_str_open_record allvm_str_legacy_open_record
#define allvm_str_open_record_split allvm_str_legacy_open_record_split
#include "llvm/Transforms/Obfuscation/AuthenticatedStringCrypto.h"
#undef allvm_str_seal_record
#undef allvm_str_open_record
#undef allvm_str_open_record_split

#undef ALLVM_STR_VERSION
#define ALLVM_STR_VERSION 2U
#define ALLVM_STR_TAG_OFFSET 32U
#define ALLVM_STR_ROOT_KEY_SIZE 64U
#define ALLVM_STR_AEAD_KEY_SIZE 32U
#define ALLVM_STR_TAG_SIZE 16U

ALLVM_STR_INLINE void allvm_str_derive_aead_key(
    allvm_str_u8 out[ALLVM_STR_AEAD_KEY_SIZE],
    const allvm_str_u8 root[ALLVM_STR_ROOT_KEY_SIZE]) {
  unsigned i;
  for (i = 0; i < ALLVM_STR_AEAD_KEY_SIZE; ++i)
    out[i] = (allvm_str_u8)(root[i] ^ root[ALLVM_STR_AEAD_KEY_SIZE + i]);
}

ALLVM_STR_INLINE void allvm_str_derive_aead_key_split(
    allvm_str_u8 out[ALLVM_STR_AEAD_KEY_SIZE],
    const allvm_str_u8 share_a[ALLVM_STR_ROOT_KEY_SIZE],
    const allvm_str_u8 share_b[ALLVM_STR_ROOT_KEY_SIZE]) {
  unsigned i;
  for (i = 0; i < ALLVM_STR_AEAD_KEY_SIZE; ++i) {
    out[i] = (allvm_str_u8)(
        share_a[i] ^ share_b[i] ^
        share_a[ALLVM_STR_AEAD_KEY_SIZE + i] ^
        share_b[ALLVM_STR_AEAD_KEY_SIZE + i]);
  }
}

typedef struct allvm_str_poly1305_state {
  allvm_str_u32 r0, r1, r2, r3, r4;
  allvm_str_u32 s1, s2, s3, s4;
  allvm_str_u32 h0, h1, h2, h3, h4;
  allvm_str_u32 pad0, pad1, pad2, pad3;
  allvm_str_u8 buffer[16];
  unsigned leftover;
  allvm_str_u8 final;
} allvm_str_poly1305_state;

ALLVM_STR_INLINE void allvm_str_poly1305_blocks(
    allvm_str_poly1305_state *state, const allvm_str_u8 *message,
    allvm_str_u64 bytes) {
  const allvm_str_u32 hibit = state->final ? 0U : (1U << 24);
  allvm_str_u32 r0 = state->r0;
  allvm_str_u32 r1 = state->r1;
  allvm_str_u32 r2 = state->r2;
  allvm_str_u32 r3 = state->r3;
  allvm_str_u32 r4 = state->r4;
  allvm_str_u32 s1 = state->s1;
  allvm_str_u32 s2 = state->s2;
  allvm_str_u32 s3 = state->s3;
  allvm_str_u32 s4 = state->s4;
  allvm_str_u32 h0 = state->h0;
  allvm_str_u32 h1 = state->h1;
  allvm_str_u32 h2 = state->h2;
  allvm_str_u32 h3 = state->h3;
  allvm_str_u32 h4 = state->h4;

  while (bytes >= 16U) {
    allvm_str_u64 d0, d1, d2, d3, d4;
    allvm_str_u32 carry;

    h0 += allvm_str_load32_le(message + 0U) & 0x3ffffffU;
    h1 += (allvm_str_load32_le(message + 3U) >> 2) & 0x3ffffffU;
    h2 += (allvm_str_load32_le(message + 6U) >> 4) & 0x3ffffffU;
    h3 += (allvm_str_load32_le(message + 9U) >> 6) & 0x3ffffffU;
    h4 += (allvm_str_load32_le(message + 12U) >> 8) | hibit;

    d0 = (allvm_str_u64)h0 * r0 + (allvm_str_u64)h1 * s4 +
         (allvm_str_u64)h2 * s3 + (allvm_str_u64)h3 * s2 +
         (allvm_str_u64)h4 * s1;
    d1 = (allvm_str_u64)h0 * r1 + (allvm_str_u64)h1 * r0 +
         (allvm_str_u64)h2 * s4 + (allvm_str_u64)h3 * s3 +
         (allvm_str_u64)h4 * s2;
    d2 = (allvm_str_u64)h0 * r2 + (allvm_str_u64)h1 * r1 +
         (allvm_str_u64)h2 * r0 + (allvm_str_u64)h3 * s4 +
         (allvm_str_u64)h4 * s3;
    d3 = (allvm_str_u64)h0 * r3 + (allvm_str_u64)h1 * r2 +
         (allvm_str_u64)h2 * r1 + (allvm_str_u64)h3 * r0 +
         (allvm_str_u64)h4 * s4;
    d4 = (allvm_str_u64)h0 * r4 + (allvm_str_u64)h1 * r3 +
         (allvm_str_u64)h2 * r2 + (allvm_str_u64)h3 * r1 +
         (allvm_str_u64)h4 * r0;

    carry = (allvm_str_u32)(d0 >> 26);
    h0 = (allvm_str_u32)d0 & 0x3ffffffU;
    d1 += carry;
    carry = (allvm_str_u32)(d1 >> 26);
    h1 = (allvm_str_u32)d1 & 0x3ffffffU;
    d2 += carry;
    carry = (allvm_str_u32)(d2 >> 26);
    h2 = (allvm_str_u32)d2 & 0x3ffffffU;
    d3 += carry;
    carry = (allvm_str_u32)(d3 >> 26);
    h3 = (allvm_str_u32)d3 & 0x3ffffffU;
    d4 += carry;
    carry = (allvm_str_u32)(d4 >> 26);
    h4 = (allvm_str_u32)d4 & 0x3ffffffU;
    h0 += carry * 5U;
    carry = h0 >> 26;
    h0 &= 0x3ffffffU;
    h1 += carry;

    message += 16U;
    bytes -= 16U;
  }

  state->h0 = h0;
  state->h1 = h1;
  state->h2 = h2;
  state->h3 = h3;
  state->h4 = h4;
}

ALLVM_STR_INLINE void allvm_str_poly1305_init(
    allvm_str_poly1305_state *state, const allvm_str_u8 key[32]) {
  state->r0 = allvm_str_load32_le(key + 0U) & 0x3ffffffU;
  state->r1 = (allvm_str_load32_le(key + 3U) >> 2) & 0x3ffff03U;
  state->r2 = (allvm_str_load32_le(key + 6U) >> 4) & 0x3ffc0ffU;
  state->r3 = (allvm_str_load32_le(key + 9U) >> 6) & 0x3f03fffU;
  state->r4 = (allvm_str_load32_le(key + 12U) >> 8) & 0x00fffffU;
  state->s1 = state->r1 * 5U;
  state->s2 = state->r2 * 5U;
  state->s3 = state->r3 * 5U;
  state->s4 = state->r4 * 5U;
  state->h0 = 0U;
  state->h1 = 0U;
  state->h2 = 0U;
  state->h3 = 0U;
  state->h4 = 0U;
  state->pad0 = allvm_str_load32_le(key + 16U);
  state->pad1 = allvm_str_load32_le(key + 20U);
  state->pad2 = allvm_str_load32_le(key + 24U);
  state->pad3 = allvm_str_load32_le(key + 28U);
  state->leftover = 0U;
  state->final = 0U;
}

ALLVM_STR_INLINE void allvm_str_poly1305_update(
    allvm_str_poly1305_state *state, const allvm_str_u8 *message,
    allvm_str_u64 bytes) {
  unsigned i;
  if (state->leftover != 0U) {
    unsigned wanted = 16U - state->leftover;
    if ((allvm_str_u64)wanted > bytes)
      wanted = (unsigned)bytes;
    for (i = 0; i < wanted; ++i)
      state->buffer[state->leftover + i] = message[i];
    bytes -= wanted;
    message += wanted;
    state->leftover += wanted;
    if (state->leftover < 16U)
      return;
    allvm_str_poly1305_blocks(state, state->buffer, 16U);
    state->leftover = 0U;
  }

  if (bytes >= 16U) {
    const allvm_str_u64 wanted = bytes & ~15ULL;
    allvm_str_poly1305_blocks(state, message, wanted);
    message += wanted;
    bytes -= wanted;
  }

  if (bytes != 0U) {
    for (i = 0; i < (unsigned)bytes; ++i)
      state->buffer[i] = message[i];
    state->leftover = (unsigned)bytes;
  }
}

ALLVM_STR_INLINE void allvm_str_poly1305_finish(
    allvm_str_poly1305_state *state, allvm_str_u8 tag[16]) {
  allvm_str_u32 h0 = state->h0;
  allvm_str_u32 h1 = state->h1;
  allvm_str_u32 h2 = state->h2;
  allvm_str_u32 h3 = state->h3;
  allvm_str_u32 h4 = state->h4;
  allvm_str_u32 carry, g0, g1, g2, g3, g4, mask;
  allvm_str_u64 f;
  unsigned i;

  if (state->leftover != 0U) {
    state->buffer[state->leftover] = 1U;
    for (i = state->leftover + 1U; i < 16U; ++i)
      state->buffer[i] = 0U;
    state->final = 1U;
    allvm_str_poly1305_blocks(state, state->buffer, 16U);
    h0 = state->h0;
    h1 = state->h1;
    h2 = state->h2;
    h3 = state->h3;
    h4 = state->h4;
  }

  carry = h1 >> 26;
  h1 &= 0x3ffffffU;
  h2 += carry;
  carry = h2 >> 26;
  h2 &= 0x3ffffffU;
  h3 += carry;
  carry = h3 >> 26;
  h3 &= 0x3ffffffU;
  h4 += carry;
  carry = h4 >> 26;
  h4 &= 0x3ffffffU;
  h0 += carry * 5U;
  carry = h0 >> 26;
  h0 &= 0x3ffffffU;
  h1 += carry;

  g0 = h0 + 5U;
  carry = g0 >> 26;
  g0 &= 0x3ffffffU;
  g1 = h1 + carry;
  carry = g1 >> 26;
  g1 &= 0x3ffffffU;
  g2 = h2 + carry;
  carry = g2 >> 26;
  g2 &= 0x3ffffffU;
  g3 = h3 + carry;
  carry = g3 >> 26;
  g3 &= 0x3ffffffU;
  g4 = h4 + carry - (1U << 26);

  mask = (g4 >> 31) - 1U;
  g0 &= mask;
  g1 &= mask;
  g2 &= mask;
  g3 &= mask;
  g4 &= mask;
  mask = ~mask;
  h0 = (h0 & mask) | g0;
  h1 = (h1 & mask) | g1;
  h2 = (h2 & mask) | g2;
  h3 = (h3 & mask) | g3;
  h4 = (h4 & mask) | g4;

  {
    allvm_str_u32 w0 = h0 | (h1 << 26);
    allvm_str_u32 w1 = (h1 >> 6) | (h2 << 20);
    allvm_str_u32 w2 = (h2 >> 12) | (h3 << 14);
    allvm_str_u32 w3 = (h3 >> 18) | (h4 << 8);
    f = (allvm_str_u64)w0 + state->pad0;
    w0 = (allvm_str_u32)f;
    f = (allvm_str_u64)w1 + state->pad1 + (f >> 32);
    w1 = (allvm_str_u32)f;
    f = (allvm_str_u64)w2 + state->pad2 + (f >> 32);
    w2 = (allvm_str_u32)f;
    f = (allvm_str_u64)w3 + state->pad3 + (f >> 32);
    w3 = (allvm_str_u32)f;
    allvm_str_store32_le(tag + 0U, w0);
    allvm_str_store32_le(tag + 4U, w1);
    allvm_str_store32_le(tag + 8U, w2);
    allvm_str_store32_le(tag + 12U, w3);
  }
  allvm_str_zero(state->buffer, 16U);
}

ALLVM_STR_INLINE void allvm_str_poly1305_auth(
    allvm_str_u8 tag[16], const allvm_str_u8 *message,
    allvm_str_u64 message_size, const allvm_str_u8 key[32]) {
  allvm_str_poly1305_state state;
  allvm_str_poly1305_init(&state, key);
  allvm_str_poly1305_update(&state, message, message_size);
  allvm_str_poly1305_finish(&state, tag);
}

ALLVM_STR_INLINE int allvm_str_poly1305_tag_equal(
    const allvm_str_u8 left[16], const allvm_str_u8 right[16]) {
  allvm_str_u32 difference = 0U;
  unsigned i;
  for (i = 0; i < 16U; ++i)
    difference |= (allvm_str_u32)(left[i] ^ right[i]);
  return (int)((((difference | (0U - difference)) >> 31) ^ 1U) & 1U);
}

ALLVM_STR_INLINE void allvm_str_record_poly1305_tag(
    allvm_str_u8 tag[16], const allvm_str_u8 *record,
    allvm_str_u32 plaintext_size, const allvm_str_u8 poly1305_key[32]) {
  static const allvm_str_u8 zero_padding[16] = {0};
  allvm_str_u8 lengths[16];
  allvm_str_poly1305_state state;
  const allvm_str_u32 remainder = plaintext_size & 15U;

  allvm_str_poly1305_init(&state, poly1305_key);
  allvm_str_poly1305_update(&state, record, ALLVM_STR_AAD_SIZE);
  allvm_str_poly1305_update(
      &state, record + ALLVM_STR_CIPHERTEXT_OFFSET, plaintext_size);
  if (remainder != 0U)
    allvm_str_poly1305_update(&state, zero_padding, 16U - remainder);
  allvm_str_store64_le(lengths + 0U, ALLVM_STR_AAD_SIZE);
  allvm_str_store64_le(lengths + 8U, plaintext_size);
  allvm_str_poly1305_update(&state, lengths, 16U);
  allvm_str_poly1305_finish(&state, tag);
  allvm_str_zero(lengths, 16U);
}

ALLVM_STR_INLINE int allvm_str_open_record_split(
    allvm_str_u8 *out, const allvm_str_u8 *record,
    allvm_str_u64 record_size,
    const allvm_str_u8 share_a[ALLVM_STR_ROOT_KEY_SIZE],
    const allvm_str_u8 share_b[ALLVM_STR_ROOT_KEY_SIZE],
    allvm_str_u32 expected_id, allvm_str_u32 expected_offset,
    allvm_str_u32 expected_flags, allvm_str_u32 expected_size);

ALLVM_STR_INLINE int allvm_str_seal_record(
    allvm_str_u8 *record, allvm_str_u64 record_capacity,
    const allvm_str_u8 *plaintext, allvm_str_u32 plaintext_size,
    const allvm_str_u8 root_key[ALLVM_STR_ROOT_KEY_SIZE],
    const allvm_str_u8 nonce[12], allvm_str_u32 record_id,
    allvm_str_u32 record_offset, allvm_str_u32 flags) {
  const allvm_str_u64 required =
      (allvm_str_u64)ALLVM_STR_HEADER_SIZE + plaintext_size;
  allvm_str_u8 key[ALLVM_STR_AEAD_KEY_SIZE];
  allvm_str_u8 block_zero[64];
  allvm_str_u8 tag[ALLVM_STR_TAG_SIZE];
  unsigned i;

  if (record_capacity < required)
    return 0;
  for (i = 0; i < ALLVM_STR_HEADER_SIZE; ++i)
    record[i] = 0;
  allvm_str_store32_le(record + 0U, ALLVM_STR_MAGIC);
  allvm_str_store32_le(
      record + 4U,
      (ALLVM_STR_VERSION & 0xffffU) | ((flags & 0xffffU) << 16));
  allvm_str_store32_le(record + 8U, record_id);
  allvm_str_store32_le(record + 12U, plaintext_size);
  for (i = 0; i < 12U; ++i)
    record[ALLVM_STR_NONCE_OFFSET + i] = nonce[i];
  allvm_str_store32_le(record + 28U, record_offset);

  allvm_str_derive_aead_key(key, root_key);
  if (!allvm_str_chacha_xor(
          record + ALLVM_STR_CIPHERTEXT_OFFSET, plaintext, plaintext_size,
          key, nonce)) {
    allvm_str_zero(key, ALLVM_STR_AEAD_KEY_SIZE);
    return 0;
  }
  allvm_str_chacha_block(block_zero, key, nonce, 0U);
  allvm_str_record_poly1305_tag(tag, record, plaintext_size, block_zero);
  for (i = 0; i < ALLVM_STR_TAG_SIZE; ++i)
    record[ALLVM_STR_TAG_OFFSET + i] = tag[i];

  allvm_str_zero(key, ALLVM_STR_AEAD_KEY_SIZE);
  allvm_str_zero(block_zero, 64U);
  allvm_str_zero(tag, ALLVM_STR_TAG_SIZE);
  return 1;
}

ALLVM_STR_INLINE int allvm_str_open_record(
    allvm_str_u8 *out, const allvm_str_u8 *record,
    allvm_str_u64 record_size,
    const allvm_str_u8 root_key[ALLVM_STR_ROOT_KEY_SIZE],
    allvm_str_u32 expected_id, allvm_str_u32 expected_offset,
    allvm_str_u32 expected_flags, allvm_str_u32 expected_size) {
  allvm_str_u8 share_a[ALLVM_STR_ROOT_KEY_SIZE];
  allvm_str_u8 share_b[ALLVM_STR_ROOT_KEY_SIZE];
  unsigned i;
  int result;
  for (i = 0; i < ALLVM_STR_ROOT_KEY_SIZE; ++i) {
    share_a[i] = 0U;
    share_b[i] = root_key[i];
  }
  result = allvm_str_open_record_split(
      out, record, record_size, share_a, share_b, expected_id,
      expected_offset, expected_flags, expected_size);
  allvm_str_zero(share_a, ALLVM_STR_ROOT_KEY_SIZE);
  allvm_str_zero(share_b, ALLVM_STR_ROOT_KEY_SIZE);
  return result;
}

ALLVM_STR_INLINE int allvm_str_open_record_split(
    allvm_str_u8 *out, const allvm_str_u8 *record,
    allvm_str_u64 record_size,
    const allvm_str_u8 share_a[ALLVM_STR_ROOT_KEY_SIZE],
    const allvm_str_u8 share_b[ALLVM_STR_ROOT_KEY_SIZE],
    allvm_str_u32 expected_id, allvm_str_u32 expected_offset,
    allvm_str_u32 expected_flags, allvm_str_u32 expected_size) {
  allvm_str_u32 version_flags;
  allvm_str_u8 key[ALLVM_STR_AEAD_KEY_SIZE];
  allvm_str_u8 block_zero[64];
  allvm_str_u8 computed[ALLVM_STR_TAG_SIZE];
  allvm_str_u8 stored[ALLVM_STR_TAG_SIZE];
  unsigned i;

  if (record_size !=
          (allvm_str_u64)ALLVM_STR_HEADER_SIZE + expected_size ||
      allvm_str_load32_le(record + 0U) != ALLVM_STR_MAGIC ||
      allvm_str_load32_le(record + 8U) != expected_id ||
      allvm_str_load32_le(record + 12U) != expected_size ||
      allvm_str_load32_le(record + 28U) != expected_offset) {
    allvm_str_zero(out, expected_size);
    return 0;
  }

  version_flags = allvm_str_load32_le(record + 4U);
  if ((version_flags & 0xffffU) != ALLVM_STR_VERSION ||
      ((version_flags >> 16) & 0xffffU) !=
          (expected_flags & 0xffffU)) {
    allvm_str_zero(out, expected_size);
    return 0;
  }

  allvm_str_derive_aead_key_split(key, share_a, share_b);
  allvm_str_chacha_block(
      block_zero, key, record + ALLVM_STR_NONCE_OFFSET, 0U);
  allvm_str_record_poly1305_tag(
      computed, record, expected_size, block_zero);
  for (i = 0; i < ALLVM_STR_TAG_SIZE; ++i)
    stored[i] = record[ALLVM_STR_TAG_OFFSET + i];

  if (!allvm_str_poly1305_tag_equal(computed, stored)) {
    allvm_str_zero(out, expected_size);
    allvm_str_zero(key, ALLVM_STR_AEAD_KEY_SIZE);
    allvm_str_zero(block_zero, 64U);
    allvm_str_zero(computed, ALLVM_STR_TAG_SIZE);
    allvm_str_zero(stored, ALLVM_STR_TAG_SIZE);
    return 0;
  }

  if (!allvm_str_chacha_xor(
          out, record + ALLVM_STR_CIPHERTEXT_OFFSET, expected_size, key,
          record + ALLVM_STR_NONCE_OFFSET)) {
    allvm_str_zero(out, expected_size);
    allvm_str_zero(key, ALLVM_STR_AEAD_KEY_SIZE);
    allvm_str_zero(block_zero, 64U);
    allvm_str_zero(computed, ALLVM_STR_TAG_SIZE);
    allvm_str_zero(stored, ALLVM_STR_TAG_SIZE);
    return 0;
  }

  allvm_str_zero(key, ALLVM_STR_AEAD_KEY_SIZE);
  allvm_str_zero(block_zero, 64U);
  allvm_str_zero(computed, ALLVM_STR_TAG_SIZE);
  allvm_str_zero(stored, ALLVM_STR_TAG_SIZE);
  return 1;
}

#endif // LLVM_TRANSFORMS_OBFUSCATION_AUTHENTICATEDSTRINGPOLY1305CRYPTO_H
