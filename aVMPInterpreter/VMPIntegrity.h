//===- VMPIntegrity.h - authenticated legacy VMP block format -----------===//
//
// A compact C/C++ compatible SipHash-2-4 implementation shared by the
// translator and the embedded interpreter.  Each VMP basic block carries two
// independently domain-separated 64-bit tags over its metadata and encrypted
// body.  The key remains inside the protected client binary; these tags detect
// accidental or unauthorised modification before execution, but they do not
// make an embedded client key impossible to extract.
//
//===----------------------------------------------------------------------===//

#ifndef ALLVM_VMP_INTEGRITY_H
#define ALLVM_VMP_INTEGRITY_H

typedef unsigned char vmp_u8;
typedef unsigned int vmp_u32;
typedef unsigned long long vmp_u64;

#define VMP_BLOCK_OPCODE_SEED_OFFSET 0U
#define VMP_BLOCK_CODE_SEED_OFFSET   4U
#define VMP_BLOCK_BODY_SIZE_OFFSET   8U
#define VMP_BLOCK_MAGIC_OFFSET      12U
#define VMP_BLOCK_TAG0_OFFSET       16U
#define VMP_BLOCK_TAG1_OFFSET       24U
#define VMP_BLOCK_HEADER_SIZE       32U

#define VMP_BLOCK_MAGIC   0x314B4C42U /* "BLK1" in little endian */
#define VMP_BLOCK_VERSION 1U
#define VMP_BLOCK_DOMAIN  0x504D5641U /* "AVMP" in little endian */

#define VMP_INTEGRITY_TAG_BYTES 16U

#if defined(_MSC_VER)
#define VMP_INTEGRITY_INLINE static __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define VMP_INTEGRITY_INLINE static __inline__ __attribute__((always_inline))
#else
#define VMP_INTEGRITY_INLINE static inline
#endif

VMP_INTEGRITY_INLINE vmp_u32
vmp_integrity_load32_le(const vmp_u8 *bytes) {
    return ((vmp_u32)bytes[0]) |
           ((vmp_u32)bytes[1] << 8) |
           ((vmp_u32)bytes[2] << 16) |
           ((vmp_u32)bytes[3] << 24);
}

VMP_INTEGRITY_INLINE vmp_u64
vmp_integrity_load64_le(const vmp_u8 *bytes) {
    vmp_u64 value = 0;
    unsigned index;
    for (index = 0; index < 8U; ++index)
        value |= (vmp_u64)bytes[index] << (8U * index);
    return value;
}

VMP_INTEGRITY_INLINE void
vmp_integrity_store32_le(vmp_u8 *bytes, vmp_u32 value) {
    bytes[0] = (vmp_u8)(value & 0xFFU);
    bytes[1] = (vmp_u8)((value >> 8) & 0xFFU);
    bytes[2] = (vmp_u8)((value >> 16) & 0xFFU);
    bytes[3] = (vmp_u8)((value >> 24) & 0xFFU);
}

VMP_INTEGRITY_INLINE void
vmp_integrity_store64_le(vmp_u8 *bytes, vmp_u64 value) {
    unsigned index;
    for (index = 0; index < 8U; ++index) {
        bytes[index] = (vmp_u8)(value & 0xFFU);
        value >>= 8;
    }
}

VMP_INTEGRITY_INLINE vmp_u64
vmp_integrity_rotl64(vmp_u64 value, unsigned shift) {
    return (value << shift) | (value >> (64U - shift));
}

typedef struct vmp_integrity_sip_state {
    vmp_u64 v0;
    vmp_u64 v1;
    vmp_u64 v2;
    vmp_u64 v3;
    vmp_u64 total;
    vmp_u64 tail;
    unsigned tail_length;
} vmp_integrity_sip_state;

VMP_INTEGRITY_INLINE void
vmp_integrity_sip_round(vmp_integrity_sip_state *state) {
    state->v0 += state->v1;
    state->v1 = vmp_integrity_rotl64(state->v1, 13U);
    state->v1 ^= state->v0;
    state->v0 = vmp_integrity_rotl64(state->v0, 32U);

    state->v2 += state->v3;
    state->v3 = vmp_integrity_rotl64(state->v3, 16U);
    state->v3 ^= state->v2;

    state->v0 += state->v3;
    state->v3 = vmp_integrity_rotl64(state->v3, 21U);
    state->v3 ^= state->v0;

    state->v2 += state->v1;
    state->v1 = vmp_integrity_rotl64(state->v1, 17U);
    state->v1 ^= state->v2;
    state->v2 = vmp_integrity_rotl64(state->v2, 32U);
}

VMP_INTEGRITY_INLINE void
vmp_integrity_sip_init(vmp_integrity_sip_state *state,
                       vmp_u64 key0, vmp_u64 key1) {
    state->v0 = 0x736F6D6570736575ULL ^ key0;
    state->v1 = 0x646F72616E646F6DULL ^ key1;
    state->v2 = 0x6C7967656E657261ULL ^ key0;
    state->v3 = 0x7465646279746573ULL ^ key1;
    state->total = 0;
    state->tail = 0;
    state->tail_length = 0;
}

VMP_INTEGRITY_INLINE void
vmp_integrity_sip_compress(vmp_integrity_sip_state *state, vmp_u64 word) {
    state->v3 ^= word;
    vmp_integrity_sip_round(state);
    vmp_integrity_sip_round(state);
    state->v0 ^= word;
}

VMP_INTEGRITY_INLINE void
vmp_integrity_sip_update(vmp_integrity_sip_state *state,
                         const vmp_u8 *bytes, vmp_u64 size) {
    vmp_u64 index = 0;
    state->total += size;

    while (index < size && state->tail_length != 0U) {
        state->tail |= (vmp_u64)bytes[index]
                       << (8U * state->tail_length);
        ++state->tail_length;
        ++index;
        if (state->tail_length == 8U) {
            vmp_integrity_sip_compress(state, state->tail);
            state->tail = 0;
            state->tail_length = 0;
        }
    }

    while (size - index >= 8U) {
        vmp_integrity_sip_compress(
            state, vmp_integrity_load64_le(bytes + index));
        index += 8U;
    }

    while (index < size) {
        state->tail |= (vmp_u64)bytes[index]
                       << (8U * state->tail_length);
        ++state->tail_length;
        ++index;
    }
}

VMP_INTEGRITY_INLINE vmp_u64
vmp_integrity_sip_final(vmp_integrity_sip_state *state) {
    const vmp_u64 final_word =
        ((state->total & 0xFFULL) << 56) | state->tail;
    unsigned round;

    vmp_integrity_sip_compress(state, final_word);
    state->v2 ^= 0xFFULL;
    for (round = 0; round < 4U; ++round)
        vmp_integrity_sip_round(state);
    return state->v0 ^ state->v1 ^ state->v2 ^ state->v3;
}

VMP_INTEGRITY_INLINE void
vmp_integrity_block_tags(const vmp_u8 *ciphertext,
                         vmp_u32 body_size,
                         vmp_u64 key0,
                         vmp_u64 key1,
                         vmp_u64 block_offset,
                         vmp_u32 opcode_seed,
                         vmp_u32 code_seed,
                         vmp_u64 *tag0,
                         vmp_u64 *tag1) {
    vmp_u8 metadata[32];
    vmp_integrity_sip_state first;
    vmp_integrity_sip_state second;

    vmp_integrity_store32_le(metadata + 0U, VMP_BLOCK_MAGIC);
    vmp_integrity_store32_le(metadata + 4U, VMP_BLOCK_VERSION);
    vmp_integrity_store64_le(metadata + 8U, block_offset);
    vmp_integrity_store32_le(metadata + 16U, opcode_seed);
    vmp_integrity_store32_le(metadata + 20U, code_seed);
    vmp_integrity_store32_le(metadata + 24U, body_size);
    vmp_integrity_store32_le(metadata + 28U, VMP_BLOCK_DOMAIN);

    vmp_integrity_sip_init(&first, key0, key1);
    vmp_integrity_sip_update(&first, metadata, (vmp_u64)sizeof(metadata));
    if (body_size != 0U)
        vmp_integrity_sip_update(&first, ciphertext, body_size);
    *tag0 = vmp_integrity_sip_final(&first);

    vmp_integrity_sip_init(
        &second,
        key0 ^ 0xA5A5A5A5A5A5A5A5ULL,
        key1 ^ 0x5A5A5A5A5A5A5A5AULL);
    vmp_integrity_sip_update(&second, metadata, (vmp_u64)sizeof(metadata));
    if (body_size != 0U)
        vmp_integrity_sip_update(&second, ciphertext, body_size);
    *tag1 = vmp_integrity_sip_final(&second);
}

VMP_INTEGRITY_INLINE int
vmp_integrity_tag_equal(vmp_u64 left, vmp_u64 right) {
    const vmp_u64 difference = left ^ right;
    return (int)((((difference | (0ULL - difference)) >> 63) ^ 1ULL) & 1ULL);
}

#endif // ALLVM_VMP_INTEGRITY_H
