#ifndef LLVM_TRANSFORMS_OBFUSCATION_AUTHENTICATEDSTRINGCRYPTO_H
#define LLVM_TRANSFORMS_OBFUSCATION_AUTHENTICATEDSTRINGCRYPTO_H

typedef unsigned char allvm_str_u8;
typedef unsigned int allvm_str_u32;
typedef unsigned long long allvm_str_u64;

#define ALLVM_STR_MAGIC 0x31525453U
#define ALLVM_STR_VERSION 1U
#define ALLVM_STR_FLAG_UTF16 1U
#define ALLVM_STR_HEADER_SIZE 48U
#define ALLVM_STR_AAD_SIZE 32U
#define ALLVM_STR_NONCE_OFFSET 16U
#define ALLVM_STR_TAG0_OFFSET 32U
#define ALLVM_STR_TAG1_OFFSET 40U
#define ALLVM_STR_CIPHERTEXT_OFFSET 48U

#if defined(_MSC_VER)
#define ALLVM_STR_INLINE static __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define ALLVM_STR_INLINE static __inline__ __attribute__((always_inline))
#else
#define ALLVM_STR_INLINE static inline
#endif

ALLVM_STR_INLINE allvm_str_u32 allvm_str_load32_le(const allvm_str_u8 *p) {
  return ((allvm_str_u32)p[0]) | ((allvm_str_u32)p[1] << 8) |
         ((allvm_str_u32)p[2] << 16) | ((allvm_str_u32)p[3] << 24);
}

ALLVM_STR_INLINE allvm_str_u64 allvm_str_load64_le(const allvm_str_u8 *p) {
  allvm_str_u64 v = 0;
  unsigned i;
  for (i = 0; i < 8U; ++i)
    v |= (allvm_str_u64)p[i] << (8U * i);
  return v;
}

ALLVM_STR_INLINE allvm_str_u32 allvm_str_load_split32_le(
    const allvm_str_u8 *a, const allvm_str_u8 *b, unsigned offset) {
  return allvm_str_load32_le(a + offset) ^ allvm_str_load32_le(b + offset);
}

ALLVM_STR_INLINE allvm_str_u64 allvm_str_load_split64_le(
    const allvm_str_u8 *a, const allvm_str_u8 *b, unsigned offset) {
  return allvm_str_load64_le(a + offset) ^ allvm_str_load64_le(b + offset);
}

ALLVM_STR_INLINE void allvm_str_store32_le(allvm_str_u8 *p, allvm_str_u32 v) {
  p[0] = (allvm_str_u8)(v & 0xffU);
  p[1] = (allvm_str_u8)((v >> 8) & 0xffU);
  p[2] = (allvm_str_u8)((v >> 16) & 0xffU);
  p[3] = (allvm_str_u8)((v >> 24) & 0xffU);
}

ALLVM_STR_INLINE void allvm_str_store64_le(allvm_str_u8 *p, allvm_str_u64 v) {
  unsigned i;
  for (i = 0; i < 8U; ++i) {
    p[i] = (allvm_str_u8)(v & 0xffU);
    v >>= 8;
  }
}

ALLVM_STR_INLINE allvm_str_u32 allvm_str_rotl32(allvm_str_u32 v, unsigned n) {
  return (v << n) | (v >> (32U - n));
}

ALLVM_STR_INLINE allvm_str_u64 allvm_str_rotl64(allvm_str_u64 v, unsigned n) {
  return (v << n) | (v >> (64U - n));
}

ALLVM_STR_INLINE void allvm_str_qr(allvm_str_u32 *a, allvm_str_u32 *b,
                                    allvm_str_u32 *c, allvm_str_u32 *d) {
  *a += *b;
  *d ^= *a;
  *d = allvm_str_rotl32(*d, 16U);
  *c += *d;
  *b ^= *c;
  *b = allvm_str_rotl32(*b, 12U);
  *a += *b;
  *d ^= *a;
  *d = allvm_str_rotl32(*d, 8U);
  *c += *d;
  *b ^= *c;
  *b = allvm_str_rotl32(*b, 7U);
}

ALLVM_STR_INLINE void allvm_str_chacha_block(allvm_str_u8 out[64],
                                              const allvm_str_u8 key[32],
                                              const allvm_str_u8 nonce[12],
                                              allvm_str_u32 counter) {
  allvm_str_u32 x[16];
  allvm_str_u32 initial[16];
  unsigned i;
  initial[0] = 0x61707865U;
  initial[1] = 0x3320646eU;
  initial[2] = 0x79622d32U;
  initial[3] = 0x6b206574U;
  for (i = 0; i < 8U; ++i)
    initial[4U + i] = allvm_str_load32_le(key + 4U * i);
  initial[12] = counter;
  initial[13] = allvm_str_load32_le(nonce + 0U);
  initial[14] = allvm_str_load32_le(nonce + 4U);
  initial[15] = allvm_str_load32_le(nonce + 8U);
  for (i = 0; i < 16U; ++i)
    x[i] = initial[i];
  for (i = 0; i < 10U; ++i) {
    allvm_str_qr(&x[0], &x[4], &x[8], &x[12]);
    allvm_str_qr(&x[1], &x[5], &x[9], &x[13]);
    allvm_str_qr(&x[2], &x[6], &x[10], &x[14]);
    allvm_str_qr(&x[3], &x[7], &x[11], &x[15]);
    allvm_str_qr(&x[0], &x[5], &x[10], &x[15]);
    allvm_str_qr(&x[1], &x[6], &x[11], &x[12]);
    allvm_str_qr(&x[2], &x[7], &x[8], &x[13]);
    allvm_str_qr(&x[3], &x[4], &x[9], &x[14]);
  }
  for (i = 0; i < 16U; ++i)
    allvm_str_store32_le(out + 4U * i, x[i] + initial[i]);
}

ALLVM_STR_INLINE int allvm_str_chacha_xor(allvm_str_u8 *out,
                                           const allvm_str_u8 *in,
                                           allvm_str_u32 size,
                                           const allvm_str_u8 key[32],
                                           const allvm_str_u8 nonce[12]) {
  allvm_str_u8 block[64];
  allvm_str_u32 counter = 1U;
  allvm_str_u32 offset = 0U;
  while (offset < size) {
    allvm_str_u32 count = size - offset;
    unsigned i;
    if (count > 64U)
      count = 64U;
    if (counter == 0U)
      return 0;
    allvm_str_chacha_block(block, key, nonce, counter++);
    for (i = 0; i < count; ++i)
      out[offset + i] = in[offset + i] ^ block[i];
    offset += count;
  }
  {
    volatile allvm_str_u8 *p = (volatile allvm_str_u8 *)block;
    unsigned i;
    for (i = 0; i < 64U; ++i)
      p[i] = 0;
  }
  return 1;
}

ALLVM_STR_INLINE void allvm_str_chacha_block_split(
    allvm_str_u8 out[64], const allvm_str_u8 key_a[64],
    const allvm_str_u8 key_b[64], const allvm_str_u8 nonce[12],
    allvm_str_u32 counter) {
  allvm_str_u32 x[16];
  allvm_str_u32 initial[16];
  unsigned i;
  initial[0] = 0x61707865U;
  initial[1] = 0x3320646eU;
  initial[2] = 0x79622d32U;
  initial[3] = 0x6b206574U;
  for (i = 0; i < 8U; ++i)
    initial[4U + i] = allvm_str_load_split32_le(key_a, key_b, 4U * i);
  initial[12] = counter;
  initial[13] = allvm_str_load32_le(nonce + 0U);
  initial[14] = allvm_str_load32_le(nonce + 4U);
  initial[15] = allvm_str_load32_le(nonce + 8U);
  for (i = 0; i < 16U; ++i)
    x[i] = initial[i];
  for (i = 0; i < 10U; ++i) {
    allvm_str_qr(&x[0], &x[4], &x[8], &x[12]);
    allvm_str_qr(&x[1], &x[5], &x[9], &x[13]);
    allvm_str_qr(&x[2], &x[6], &x[10], &x[14]);
    allvm_str_qr(&x[3], &x[7], &x[11], &x[15]);
    allvm_str_qr(&x[0], &x[5], &x[10], &x[15]);
    allvm_str_qr(&x[1], &x[6], &x[11], &x[12]);
    allvm_str_qr(&x[2], &x[7], &x[8], &x[13]);
    allvm_str_qr(&x[3], &x[4], &x[9], &x[14]);
  }
  for (i = 0; i < 16U; ++i)
    allvm_str_store32_le(out + 4U * i, x[i] + initial[i]);
}

ALLVM_STR_INLINE int allvm_str_chacha_xor_split(
    allvm_str_u8 *out, const allvm_str_u8 *in, allvm_str_u32 size,
    const allvm_str_u8 key_a[64], const allvm_str_u8 key_b[64],
    const allvm_str_u8 nonce[12]) {
  allvm_str_u8 block[64];
  allvm_str_u32 counter = 1U;
  allvm_str_u32 offset = 0U;
  while (offset < size) {
    allvm_str_u32 count = size - offset;
    unsigned i;
    if (count > 64U)
      count = 64U;
    if (counter == 0U)
      return 0;
    allvm_str_chacha_block_split(block, key_a, key_b, nonce, counter++);
    for (i = 0; i < count; ++i)
      out[offset + i] = in[offset + i] ^ block[i];
    offset += count;
  }
  {
    volatile allvm_str_u8 *p = (volatile allvm_str_u8 *)block;
    unsigned i;
    for (i = 0; i < 64U; ++i)
      p[i] = 0;
  }
  return 1;
}

typedef struct allvm_str_sip_state {
  allvm_str_u64 v0;
  allvm_str_u64 v1;
  allvm_str_u64 v2;
  allvm_str_u64 v3;
  allvm_str_u64 total;
  allvm_str_u64 tail;
  unsigned tail_length;
} allvm_str_sip_state;

ALLVM_STR_INLINE void allvm_str_sip_round(allvm_str_sip_state *s) {
  s->v0 += s->v1;
  s->v1 = allvm_str_rotl64(s->v1, 13U);
  s->v1 ^= s->v0;
  s->v0 = allvm_str_rotl64(s->v0, 32U);
  s->v2 += s->v3;
  s->v3 = allvm_str_rotl64(s->v3, 16U);
  s->v3 ^= s->v2;
  s->v0 += s->v3;
  s->v3 = allvm_str_rotl64(s->v3, 21U);
  s->v3 ^= s->v0;
  s->v2 += s->v1;
  s->v1 = allvm_str_rotl64(s->v1, 17U);
  s->v1 ^= s->v2;
  s->v2 = allvm_str_rotl64(s->v2, 32U);
}

ALLVM_STR_INLINE void allvm_str_sip_init(allvm_str_sip_state *s,
                                          allvm_str_u64 k0,
                                          allvm_str_u64 k1) {
  s->v0 = 0x736f6d6570736575ULL ^ k0;
  s->v1 = 0x646f72616e646f6dULL ^ k1;
  s->v2 = 0x6c7967656e657261ULL ^ k0;
  s->v3 = 0x7465646279746573ULL ^ k1;
  s->total = 0;
  s->tail = 0;
  s->tail_length = 0;
}

ALLVM_STR_INLINE void allvm_str_sip_compress(allvm_str_sip_state *s,
                                              allvm_str_u64 word) {
  s->v3 ^= word;
  allvm_str_sip_round(s);
  allvm_str_sip_round(s);
  s->v0 ^= word;
}

ALLVM_STR_INLINE void allvm_str_sip_update(allvm_str_sip_state *s,
                                            const allvm_str_u8 *data,
                                            allvm_str_u64 size) {
  allvm_str_u64 i = 0;
  s->total += size;
  while (i < size && s->tail_length != 0U) {
    s->tail |= (allvm_str_u64)data[i] << (8U * s->tail_length);
    ++s->tail_length;
    ++i;
    if (s->tail_length == 8U) {
      allvm_str_sip_compress(s, s->tail);
      s->tail = 0;
      s->tail_length = 0;
    }
  }
  while (size - i >= 8U) {
    allvm_str_sip_compress(s, allvm_str_load64_le(data + i));
    i += 8U;
  }
  while (i < size) {
    s->tail |= (allvm_str_u64)data[i] << (8U * s->tail_length);
    ++s->tail_length;
    ++i;
  }
}

ALLVM_STR_INLINE allvm_str_u64 allvm_str_sip_final(allvm_str_sip_state *s) {
  allvm_str_u64 b = ((s->total & 0xffULL) << 56) | s->tail;
  unsigned i;
  allvm_str_sip_compress(s, b);
  s->v2 ^= 0xffULL;
  for (i = 0; i < 4U; ++i)
    allvm_str_sip_round(s);
  return s->v0 ^ s->v1 ^ s->v2 ^ s->v3;
}

ALLVM_STR_INLINE allvm_str_u64 allvm_str_tag(const allvm_str_u8 *record,
                                              allvm_str_u32 plain_size,
                                              allvm_str_u64 k0,
                                              allvm_str_u64 k1,
                                              allvm_str_u64 domain) {
  allvm_str_sip_state s;
  allvm_str_u8 domain_bytes[8];
  allvm_str_store64_le(domain_bytes, domain);
  allvm_str_sip_init(&s, k0, k1);
  allvm_str_sip_update(&s, domain_bytes, 8U);
  allvm_str_sip_update(&s, record, ALLVM_STR_AAD_SIZE);
  if (plain_size != 0U)
    allvm_str_sip_update(&s, record + ALLVM_STR_CIPHERTEXT_OFFSET,
                         plain_size);
  return allvm_str_sip_final(&s);
}

ALLVM_STR_INLINE int allvm_str_tag_equal(allvm_str_u64 a, allvm_str_u64 b) {
  allvm_str_u64 difference = a ^ b;
  return (int)((((difference | (0ULL - difference)) >> 63) ^ 1ULL) & 1ULL);
}

ALLVM_STR_INLINE void allvm_str_zero(allvm_str_u8 *out, allvm_str_u32 size) {
  volatile allvm_str_u8 *p = (volatile allvm_str_u8 *)out;
  allvm_str_u32 i;
  for (i = 0; i < size; ++i)
    p[i] = 0;
}

ALLVM_STR_INLINE int allvm_str_seal_record(
    allvm_str_u8 *record, allvm_str_u64 record_capacity,
    const allvm_str_u8 *plain, allvm_str_u32 plain_size,
    const allvm_str_u8 key[64], const allvm_str_u8 nonce[12],
    allvm_str_u32 record_id, allvm_str_u32 record_offset,
    allvm_str_u32 flags) {
  allvm_str_u64 required = (allvm_str_u64)ALLVM_STR_HEADER_SIZE + plain_size;
  allvm_str_u64 tag0;
  allvm_str_u64 tag1;
  unsigned i;
  if (record_capacity < required)
    return 0;
  for (i = 0; i < ALLVM_STR_HEADER_SIZE; ++i)
    record[i] = 0;
  allvm_str_store32_le(record + 0U, ALLVM_STR_MAGIC);
  allvm_str_store32_le(record + 4U,
                       (ALLVM_STR_VERSION & 0xffffU) | ((flags & 0xffffU) << 16));
  allvm_str_store32_le(record + 8U, record_id);
  allvm_str_store32_le(record + 12U, plain_size);
  for (i = 0; i < 12U; ++i)
    record[ALLVM_STR_NONCE_OFFSET + i] = nonce[i];
  allvm_str_store32_le(record + 28U, record_offset);
  if (!allvm_str_chacha_xor(record + ALLVM_STR_CIPHERTEXT_OFFSET, plain,
                            plain_size, key, nonce))
    return 0;
  tag0 = allvm_str_tag(record, plain_size, allvm_str_load64_le(key + 32U),
                       allvm_str_load64_le(key + 40U),
                       0x305254534d564c41ULL);
  tag1 = allvm_str_tag(record, plain_size, allvm_str_load64_le(key + 48U),
                       allvm_str_load64_le(key + 56U),
                       0x315254534d564c41ULL);
  allvm_str_store64_le(record + ALLVM_STR_TAG0_OFFSET, tag0);
  allvm_str_store64_le(record + ALLVM_STR_TAG1_OFFSET, tag1);
  return 1;
}

ALLVM_STR_INLINE int allvm_str_open_record(
    allvm_str_u8 *out, const allvm_str_u8 *record,
    allvm_str_u64 record_size, const allvm_str_u8 key[64],
    allvm_str_u32 expected_id, allvm_str_u32 expected_offset,
    allvm_str_u32 expected_flags, allvm_str_u32 expected_size) {
  allvm_str_u32 version_flags;
  allvm_str_u64 tag0;
  allvm_str_u64 tag1;
  allvm_str_u64 computed0;
  allvm_str_u64 computed1;
  if (record_size != (allvm_str_u64)ALLVM_STR_HEADER_SIZE + expected_size ||
      allvm_str_load32_le(record + 0U) != ALLVM_STR_MAGIC ||
      allvm_str_load32_le(record + 8U) != expected_id ||
      allvm_str_load32_le(record + 12U) != expected_size ||
      allvm_str_load32_le(record + 28U) != expected_offset) {
    allvm_str_zero(out, expected_size);
    return 0;
  }
  version_flags = allvm_str_load32_le(record + 4U);
  if ((version_flags & 0xffffU) != ALLVM_STR_VERSION ||
      ((version_flags >> 16) & 0xffffU) != (expected_flags & 0xffffU)) {
    allvm_str_zero(out, expected_size);
    return 0;
  }
  tag0 = allvm_str_load64_le(record + ALLVM_STR_TAG0_OFFSET);
  tag1 = allvm_str_load64_le(record + ALLVM_STR_TAG1_OFFSET);
  computed0 = allvm_str_tag(record, expected_size,
                            allvm_str_load64_le(key + 32U),
                            allvm_str_load64_le(key + 40U),
                            0x305254534d564c41ULL);
  computed1 = allvm_str_tag(record, expected_size,
                            allvm_str_load64_le(key + 48U),
                            allvm_str_load64_le(key + 56U),
                            0x315254534d564c41ULL);
  if (!(allvm_str_tag_equal(tag0, computed0) &
        allvm_str_tag_equal(tag1, computed1))) {
    allvm_str_zero(out, expected_size);
    return 0;
  }
  if (!allvm_str_chacha_xor(out, record + ALLVM_STR_CIPHERTEXT_OFFSET,
                            expected_size, key,
                            record + ALLVM_STR_NONCE_OFFSET)) {
    allvm_str_zero(out, expected_size);
    return 0;
  }
  return 1;
}

ALLVM_STR_INLINE int allvm_str_open_record_split(
    allvm_str_u8 *out, const allvm_str_u8 *record,
    allvm_str_u64 record_size, const allvm_str_u8 key_a[64],
    const allvm_str_u8 key_b[64], allvm_str_u32 expected_id,
    allvm_str_u32 expected_offset, allvm_str_u32 expected_flags,
    allvm_str_u32 expected_size) {
  allvm_str_u32 version_flags;
  allvm_str_u64 tag0;
  allvm_str_u64 tag1;
  allvm_str_u64 computed0;
  allvm_str_u64 computed1;
  if (record_size != (allvm_str_u64)ALLVM_STR_HEADER_SIZE + expected_size ||
      allvm_str_load32_le(record + 0U) != ALLVM_STR_MAGIC ||
      allvm_str_load32_le(record + 8U) != expected_id ||
      allvm_str_load32_le(record + 12U) != expected_size ||
      allvm_str_load32_le(record + 28U) != expected_offset) {
    allvm_str_zero(out, expected_size);
    return 0;
  }
  version_flags = allvm_str_load32_le(record + 4U);
  if ((version_flags & 0xffffU) != ALLVM_STR_VERSION ||
      ((version_flags >> 16) & 0xffffU) != (expected_flags & 0xffffU)) {
    allvm_str_zero(out, expected_size);
    return 0;
  }
  tag0 = allvm_str_load64_le(record + ALLVM_STR_TAG0_OFFSET);
  tag1 = allvm_str_load64_le(record + ALLVM_STR_TAG1_OFFSET);
  computed0 = allvm_str_tag(
      record, expected_size, allvm_str_load_split64_le(key_a, key_b, 32U),
      allvm_str_load_split64_le(key_a, key_b, 40U),
      0x305254534d564c41ULL);
  computed1 = allvm_str_tag(
      record, expected_size, allvm_str_load_split64_le(key_a, key_b, 48U),
      allvm_str_load_split64_le(key_a, key_b, 56U),
      0x315254534d564c41ULL);
  if (!(allvm_str_tag_equal(tag0, computed0) &
        allvm_str_tag_equal(tag1, computed1))) {
    allvm_str_zero(out, expected_size);
    return 0;
  }
  if (!allvm_str_chacha_xor_split(
          out, record + ALLVM_STR_CIPHERTEXT_OFFSET, expected_size, key_a,
          key_b, record + ALLVM_STR_NONCE_OFFSET)) {
    allvm_str_zero(out, expected_size);
    return 0;
  }
  return 1;
}

#endif
