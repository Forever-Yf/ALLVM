#!/usr/bin/env python3
"""One-time, fail-fast migration for authenticated VMP blocks and budgets."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one occurrence, found {count}: {old[:100]!r}")
    write(path, text.replace(old, new, 1))


def replace_all(path: str, old: str, new: str, minimum: int = 1) -> None:
    text = read(path)
    count = text.count(old)
    if count < minimum:
        raise SystemExit(f"{path}: expected at least {minimum}, found {count}: {old[:100]!r}")
    write(path, text.replace(old, new))


def replace_region(path: str, start: str, end: str, replacement: str) -> None:
    text = read(path)
    start_index = text.find(start)
    if start_index < 0:
        raise SystemExit(f"{path}: missing start marker {start!r}")
    if text.find(start, start_index + 1) >= 0:
        raise SystemExit(f"{path}: start marker is not unique {start!r}")
    end_index = text.find(end, start_index)
    if end_index < 0:
        raise SystemExit(f"{path}: missing end marker {end!r}")
    write(path, text[:start_index] + replacement + text[end_index:])


INTERPRETER_HEADER = r'''#ifndef ALLVM_AVMP_INTERPRETER_H
#define ALLVM_AVMP_INTERPRETER_H

// The embedded interpreter intentionally avoids libc headers so it can be
// compiled directly to LLVM bitcode for the target ABI.
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef long long int64_t;
typedef unsigned long long uintptr_t;

// Opcode
#define NOP_OP              0x00
#define ALLOCA_OP           0x01
#define LOAD_OP             0x02
#define STORE_OP            0x03
#define BinaryOperator_OP   0x04
#define GEP_OP              0x05
#define CMP_OP              0x06
#define CAST_OP             0x07
#define BR_OP               0x08
#define Call_OP             0x09
#define Ret_OP              0x0A
#define SWITCH_OP           0x0B
#define INSERTVALUE_OP      0x0C
#define EXTRACTVALUE_OP     0x0D

#define OP_TOTAL            0x0D

// Runtime fault codes. The first fault is preserved in vm_fault.
#define VM_FAULT_NONE           0U
#define VM_FAULT_CODE_RANGE     1U
#define VM_FAULT_DATA_RANGE     2U
#define VM_FAULT_NULL_ADDRESS   3U
#define VM_FAULT_INVALID_SIZE   4U
#define VM_FAULT_INVALID_OPCODE 5U
#define VM_FAULT_ARITHMETIC     6U
#define VM_FAULT_BAD_STATE      7U
#define VM_FAULT_INTEGRITY      8U
#define VM_FAULT_STEP_LIMIT     9U
#define VM_FAULT_CALL_LIMIT    10U
#define VM_FAULT_CALL_DEPTH    11U
#define VM_FAULT_REENTRANT     12U
#define VM_FAULT_BLOCK_RANGE   13U

// Per-function VM state. aVMP.cpp replaces these declarations with globals
// derived from the translated function before cloning the interpreter.
extern uintptr_t data_seg_addr;
extern uintptr_t code_seg_addr;
extern int ip;
extern unsigned pointer_size;
extern uint32_t opcode_xorshift32_state;
extern uint32_t vm_code_state;
extern uint64_t code_seg_size;
extern uint64_t data_seg_size;
extern uint32_t vm_fault;

// Authenticated-block metadata and execution budgets.
extern uint64_t vm_integrity_key0;
extern uint64_t vm_integrity_key1;
extern uint64_t vm_block_end;
extern uint64_t vm_step_limit;
extern uint64_t vm_call_limit;
extern uint64_t vm_call_depth_limit;
extern uint64_t vm_steps_remaining;
extern uint64_t vm_calls_remaining;
extern uint64_t vm_call_depth;
extern uint32_t vm_frame_active;

// BinaryOperator codes
#define BINOP_ADD       13
#define BINOP_FADD      14
#define BINOP_SUB       15
#define BINOP_FSUB      16
#define BINOP_MUL       17
#define BINOP_FMUL      18
#define BINOP_UDIV      19
#define BINOP_SDIV      20
#define BINOP_FDIV      21
#define BINOP_UREM      22
#define BINOP_SREM      23
#define BINOP_FREM      24
#define BINOP_SHL       25
#define BINOP_LSHR      26
#define BINOP_ASHR      27
#define BINOP_AND       28
#define BINOP_OR        29
#define BINOP_XOR       30

// Integer comparison predicates
#define ICMP_EQ     32
#define ICMP_NE     33
#define ICMP_UGT    34
#define ICMP_UGE    35
#define ICMP_ULT    36
#define ICMP_ULE    37
#define ICMP_SGT    38
#define ICMP_SGE    39
#define ICMP_SLT    40
#define ICMP_SLE    41

uint32_t xorshift32(uint32_t *state);
int vm_enter_block(uint64_t block_offset);
uint8_t get_byte_code(void);
uint32_t get_xorshift_seed(void);
uint8_t get_opcode(void);
uint64_t unpack_code(int size);
uint64_t unpack_data(uint64_t offset, int size);
uint64_t unpack_addr(uint64_t address, int size);
void pack_data(uint64_t offset, uint64_t value, int size);
void pack_store_addr(uint64_t address, uint64_t value, int size);
uint64_t get_value_with_size(uint8_t value_size, uint8_t value_type);
uint64_t get_value(void);
void alloca_handler(void);
void load_handler(void);
void store_handler(void);
void binaryOperator_handler(void);
void gep_handler(void);
void cmp_handler(void);
void cast_handler(void);
void br_handler(void);
void return_handler(void);
void switch_handler(void);
void data_seg_clean(int return_value_off);
extern void call_handler(uint64_t targetfunc_id);
void vm_interpreter(void);

#endif // ALLVM_AVMP_INTERPRETER_H
'''


INTERPRETER_TEST = r'''//===- vmp-interpreter-bounds-smoke.c - native authenticated runtime test ===//
//
// Compiles the interpreter directly into this translation unit. The suite
// covers authenticated block entry, ciphertext/header tampering, block-local
// bounds, opcode collision handling, execution budgets, depth and re-entry.
// VMP_TEST_NO_TRAP keeps fail-closed faults observable instead of trapping.
//
//===----------------------------------------------------------------------===//

#include "../aVMPInterpreter/aVMPInterpreter.h"

uintptr_t data_seg_addr = 0;
uintptr_t code_seg_addr = 0;
int ip = 0;
unsigned pointer_size = 8;
uint32_t opcode_xorshift32_state = 1;
uint32_t vm_code_state = 1;
uint64_t code_seg_size = 0;
uint64_t data_seg_size = 0;
uint32_t vm_fault = VM_FAULT_NONE;
uint64_t vm_integrity_key0 = 0x0706050403020100ULL;
uint64_t vm_integrity_key1 = 0x0F0E0D0C0B0A0908ULL;
uint64_t vm_block_end = 0;
uint64_t vm_step_limit = 0;
uint64_t vm_call_limit = 0;
uint64_t vm_call_depth_limit = 64;
uint64_t vm_steps_remaining = 0;
uint64_t vm_calls_remaining = 0;
uint64_t vm_call_depth = 0;
uint32_t vm_frame_active = 0;

static unsigned call_handler_count = 0;
void call_handler(uint64_t targetfunc_id) {
    (void)targetfunc_id;
    ++call_handler_count;
}

#define VMP_TEST_NO_TRAP
#include "../aVMPInterpreter/aVMPInterpreter.c"

static void fill_bytes(uint8_t *buffer, uint64_t size, uint8_t value) {
    for (uint64_t i = 0; i < size; ++i)
        buffer[i] = value;
}

static void reset_data(uint8_t *buffer, uint64_t size) {
    fill_bytes(buffer, size, 0);
    data_seg_addr = (uintptr_t)buffer;
    data_seg_size = size;
    vm_fault = VM_FAULT_NONE;
}

static void reset_code(uint8_t *buffer, uint64_t size) {
    code_seg_addr = (uintptr_t)buffer;
    code_seg_size = size;
    ip = 0;
    vm_block_end = size;
    vm_code_state = 0;
    opcode_xorshift32_state = 0;
    vm_step_limit = 0;
    vm_call_limit = 0;
    vm_call_depth_limit = 64;
    vm_steps_remaining = 0;
    vm_calls_remaining = 0;
    vm_call_depth = 0;
    vm_frame_active = 0;
    call_handler_count = 0;
    vm_fault = VM_FAULT_NONE;
}

static void write_le(uint8_t *buffer, uint64_t value, unsigned size) {
    for (unsigned i = 0; i < size; ++i) {
        buffer[i] = (uint8_t)(value & 0xFFU);
        value >>= 8;
    }
}

static unsigned encode_const_u64(uint8_t *buffer, uint64_t value) {
    buffer[0] = 8;
    buffer[1] = 1;
    write_le(buffer + 2, value, 8);
    return 10;
}

static uint8_t encode_opcode(uint32_t *state, uint8_t opcode) {
    uint8_t seen[256] = {0};
    unsigned unique_count = 0;
    unsigned attempts = 0;
    uint8_t result = 0;

    if (opcode == NOP_OP)
        return 0;
    while (unique_count < opcode) {
        if (++attempts > 4096U)
            return 0;
        const uint8_t candidate =
            (uint8_t)(xorshift32(state) & 0xFFU);
        if (candidate == 0 || seen[candidate] != 0)
            continue;
        seen[candidate] = 1;
        result = candidate;
        ++unique_count;
    }
    return result;
}

static unsigned build_authenticated_block(uint8_t *buffer,
                                          unsigned capacity,
                                          const uint8_t *plain_body,
                                          unsigned body_size,
                                          uint32_t opcode_seed,
                                          uint32_t code_seed,
                                          uint64_t block_offset) {
    uint32_t cipher_state = code_seed;
    vmp_u64 tag0 = 0;
    vmp_u64 tag1 = 0;
    const unsigned total = VMP_BLOCK_HEADER_SIZE + body_size;
    if (capacity < total)
        return 0;

    fill_bytes(buffer, total, 0);
    vmp_integrity_store32_le(
        buffer + VMP_BLOCK_OPCODE_SEED_OFFSET, opcode_seed);
    vmp_integrity_store32_le(
        buffer + VMP_BLOCK_CODE_SEED_OFFSET, code_seed);
    vmp_integrity_store32_le(
        buffer + VMP_BLOCK_BODY_SIZE_OFFSET, body_size);
    vmp_integrity_store32_le(
        buffer + VMP_BLOCK_MAGIC_OFFSET, VMP_BLOCK_MAGIC);

    for (unsigned i = 0; i < body_size; ++i) {
        buffer[VMP_BLOCK_HEADER_SIZE + i] =
            plain_body[i] ^ (uint8_t)(xorshift32(&cipher_state) & 0xFFU);
    }

    vmp_integrity_block_tags(
        buffer + VMP_BLOCK_HEADER_SIZE, body_size,
        vm_integrity_key0, vm_integrity_key1,
        block_offset, opcode_seed, code_seed, &tag0, &tag1);
    vmp_integrity_store64_le(buffer + VMP_BLOCK_TAG0_OFFSET, tag0);
    vmp_integrity_store64_le(buffer + VMP_BLOCK_TAG1_OFFSET, tag1);
    return total;
}

static unsigned build_return_block(uint8_t *buffer, unsigned capacity,
                                   uint32_t opcode_seed,
                                   uint32_t code_seed) {
    uint8_t body[11] = {0};
    uint32_t opcode_state = opcode_seed;
    body[0] = encode_opcode(&opcode_state, Ret_OP);
    return build_authenticated_block(
        buffer, capacity, body, sizeof(body), opcode_seed, code_seed, 0);
}

static unsigned build_binary_code(uint8_t *code, uint8_t opcode,
                                  uint64_t left, uint64_t right) {
    code[0] = opcode;
    code[1] = 8;
    code[2] = 0;
    write_le(code + 3, 0, 8);
    unsigned offset = 11;
    offset += encode_const_u64(code + offset, left);
    offset += encode_const_u64(code + offset, right);
    return offset;
}

static int test_integrity_known_vector(void) {
    uint8_t body[16];
    vmp_u64 tag0 = 0;
    vmp_u64 tag1 = 0;
    for (unsigned i = 0; i < sizeof(body); ++i)
        body[i] = (uint8_t)i;
    vmp_integrity_block_tags(
        body, sizeof(body),
        0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL,
        0x1122334455667788ULL, 0x01020304U, 0x05060708U,
        &tag0, &tag1);
    if (tag0 != 0x1BEC6648F7191DF7ULL)
        return 1;
    if (tag1 != 0x61FE8F113EA25735ULL)
        return 2;
    return 0;
}

static int test_authenticated_block_entry(void) {
    uint8_t code[64];
    const uint8_t body[1] = {0};
    const unsigned size = build_authenticated_block(
        code, sizeof(code), body, sizeof(body), 8U, 9U, 0);
    reset_code(code, size);
    vm_block_end = 0;
    if (!vm_enter_block(0))
        return 1;
    if (vm_fault != VM_FAULT_NONE || ip != (int)VMP_BLOCK_HEADER_SIZE)
        return 2;
    if (vm_block_end != size)
        return 3;
    if (get_opcode() != NOP_OP || vm_fault != VM_FAULT_NONE)
        return 4;
    return 0;
}

static int test_authenticated_block_tamper(void) {
    uint8_t code[64];
    const uint8_t body[2] = {0, 0};
    unsigned size = build_authenticated_block(
        code, sizeof(code), body, sizeof(body), 11U, 13U, 0);

    code[VMP_BLOCK_HEADER_SIZE] ^= 1U;
    reset_code(code, size);
    vm_block_end = 0;
    (void)vm_enter_block(0);
    if (vm_fault != VM_FAULT_INTEGRITY)
        return 1;

    size = build_authenticated_block(
        code, sizeof(code), body, sizeof(body), 11U, 13U, 0);
    code[VMP_BLOCK_TAG0_OFFSET] ^= 1U;
    reset_code(code, size);
    vm_block_end = 0;
    (void)vm_enter_block(0);
    if (vm_fault != VM_FAULT_INTEGRITY)
        return 2;

    size = build_authenticated_block(
        code, sizeof(code), body, sizeof(body), 11U, 13U, 0);
    vmp_integrity_store32_le(
        code + VMP_BLOCK_BODY_SIZE_OFFSET, 0xFFFFFFFFU);
    reset_code(code, size);
    vm_block_end = 0;
    (void)vm_enter_block(0);
    if (vm_fault != VM_FAULT_BLOCK_RANGE)
        return 3;
    return 0;
}

static int test_block_local_boundary(void) {
    uint8_t code[64];
    const uint8_t body[1] = {0xA5U};
    const unsigned size = build_authenticated_block(
        code, sizeof(code), body, sizeof(body), 17U, 19U, 0);
    reset_code(code, size);
    vm_block_end = 0;
    if (!vm_enter_block(0))
        return 1;
    (void)get_byte_code();
    if (vm_fault != VM_FAULT_NONE)
        return 2;
    (void)get_byte_code();
    return vm_fault == VM_FAULT_BLOCK_RANGE ? 0 : 3;
}

static int test_valid_data_access(void) {
    uint8_t data[16];
    reset_data(data, sizeof(data));
    pack_data(4, 0x11223344U, 4);
    if (vm_fault != VM_FAULT_NONE)
        return 1;
    if (unpack_data(4, 4) != 0x11223344U)
        return 2;
    return vm_fault == VM_FAULT_NONE ? 0 : 3;
}

static int test_data_out_of_bounds(void) {
    uint8_t data[16];
    reset_data(data, sizeof(data));
    fill_bytes(data, sizeof(data), 0xA5U);
    pack_data(14, 0x11223344U, 4);
    if (vm_fault != VM_FAULT_DATA_RANGE)
        return 1;
    if (data[14] != 0xA5U || data[15] != 0xA5U)
        return 2;
    reset_data(data, sizeof(data));
    (void)unpack_addr((uint64_t)(data_seg_addr + 15U), 2);
    return vm_fault == VM_FAULT_DATA_RANGE ? 0 : 3;
}

static int test_code_out_of_bounds(void) {
    uint8_t code[4] = {0};
    reset_code(code, sizeof(code));
    ip = 3;
    (void)unpack_code(2);
    return vm_fault == VM_FAULT_CODE_RANGE ? 0 : 1;
}

static int test_invalid_width_and_null(void) {
    uint8_t data[8];
    reset_data(data, sizeof(data));
    (void)unpack_data(0, 9);
    if (vm_fault != VM_FAULT_INVALID_SIZE)
        return 1;
    reset_data(data, sizeof(data));
    (void)unpack_addr(0, 1);
    return vm_fault == VM_FAULT_NULL_ADDRESS ? 0 : 2;
}

static int test_tampered_switch_case_count(void) {
    uint8_t code[19] = {0};
    code[0] = 1;
    code[1] = 1;
    code[2] = 0;
    write_le(code + 3, 0xFFFFFFFFU, 4);
    write_le(code + 7, 1, 4);
    write_le(code + 11, 0, 8);
    reset_code(code, sizeof(code));
    switch_handler();
    return vm_fault == VM_FAULT_BLOCK_RANGE ? 0 : 1;
}

static int test_invalid_branch_target(void) {
    uint8_t code[9] = {0};
    code[0] = 0;
    write_le(code + 1, 999, 8);
    reset_code(code, sizeof(code));
    br_handler();
    return vm_fault == VM_FAULT_BLOCK_RANGE ? 0 : 1;
}

static int test_arithmetic_faults(void) {
    uint8_t data[16];
    uint8_t code[31];
    reset_data(data, sizeof(data));
    fill_bytes(code, sizeof(code), 0);
    unsigned size = build_binary_code(code, BINOP_UDIV, 10, 0);
    reset_code(code, size);
    binaryOperator_handler();
    if (vm_fault != VM_FAULT_ARITHMETIC)
        return 1;
    reset_data(data, sizeof(data));
    fill_bytes(code, sizeof(code), 0);
    size = build_binary_code(code, BINOP_SHL, 1, 64);
    reset_code(code, size);
    binaryOperator_handler();
    return vm_fault == VM_FAULT_ARITHMETIC ? 0 : 2;
}

static int test_opcode_collision_sequence(void) {
    uint8_t code[1] = {41};
    reset_code(code, sizeof(code));
    opcode_xorshift32_state = 8;
    if (get_opcode() != 2)
        return 1;
    if (vm_fault != VM_FAULT_NONE || ip != 1)
        return 2;
    code[0] = 0;
    reset_code(code, sizeof(code));
    opcode_xorshift32_state = 8;
    if (get_opcode() != NOP_OP)
        return 3;
    return opcode_xorshift32_state == 8 && vm_fault == VM_FAULT_NONE ? 0 : 4;
}

static int test_step_budget(void) {
    uint8_t data[8];
    uint8_t code[64];
    const uint8_t body[2] = {0, 0};
    const unsigned size = build_authenticated_block(
        code, sizeof(code), body, sizeof(body), 23U, 29U, 0);
    reset_data(data, sizeof(data));
    reset_code(code, size);
    vm_step_limit = 1;
    vm_call_depth_limit = 8;
    vm_interpreter();
    if (vm_fault != VM_FAULT_STEP_LIMIT)
        return 1;
    return vm_frame_active == 0 && vm_call_depth == 0 ? 0 : 2;
}

static int test_call_budget(void) {
    uint8_t data[8];
    uint8_t code[96];
    uint8_t body[32] = {0};
    uint32_t opcode_state = 31U;
    unsigned offset = 0;
    body[offset++] = encode_opcode(&opcode_state, Call_OP);
    write_le(body + offset, 1, 8);
    offset += 8;
    body[offset++] = encode_opcode(&opcode_state, Call_OP);
    write_le(body + offset, 2, 8);
    offset += 8;
    const unsigned size = build_authenticated_block(
        code, sizeof(code), body, offset, 31U, 37U, 0);
    reset_data(data, sizeof(data));
    reset_code(code, size);
    vm_step_limit = 10;
    vm_call_limit = 1;
    vm_call_depth_limit = 8;
    vm_interpreter();
    if (vm_fault != VM_FAULT_CALL_LIMIT)
        return 1;
    return call_handler_count == 1 ? 0 : 2;
}

static int test_call_depth_limit(void) {
    uint8_t data[8];
    uint8_t code[64];
    const unsigned size = build_return_block(code, sizeof(code), 41U, 43U);
    reset_data(data, sizeof(data));
    reset_code(code, size);
    vm_call_depth_limit = 3;
    vm_call_depth = 3;
    vm_interpreter();
    if (vm_fault != VM_FAULT_CALL_DEPTH)
        return 1;
    return vm_call_depth == 3 && vm_frame_active == 0 ? 0 : 2;
}

static int test_reentrant_guard(void) {
    uint8_t data[8];
    uint8_t code[64];
    const unsigned size = build_return_block(code, sizeof(code), 47U, 53U);
    reset_data(data, sizeof(data));
    reset_code(code, size);
    vm_frame_active = 1;
    vm_interpreter();
    if (vm_fault != VM_FAULT_REENTRANT)
        return 1;
    const int ok = vm_frame_active == 1 && vm_call_depth == 0;
    vm_frame_active = 0;
    return ok ? 0 : 2;
}

static int test_valid_interpreter_return(void) {
    uint8_t data[8];
    uint8_t code[64];
    const unsigned size = build_return_block(code, sizeof(code), 59U, 61U);
    reset_data(data, sizeof(data));
    fill_bytes(data, sizeof(data), 0xCCU);
    reset_code(code, size);
    vm_step_limit = 10;
    vm_call_limit = 10;
    vm_call_depth_limit = 8;
    vm_interpreter();
    if (vm_fault != VM_FAULT_NONE)
        return 1;
    if (vm_frame_active != 0 || vm_call_depth != 0)
        return 2;
    for (unsigned i = 0; i < sizeof(data); ++i)
        if (data[i] != 0)
            return 3;
    return 0;
}

static int test_return_clears_transient_data(void) {
    uint8_t data[8];
    uint8_t code[3] = {1, 1, 0x7AU};
    reset_data(data, sizeof(data));
    fill_bytes(data, sizeof(data), 0xCCU);
    reset_code(code, sizeof(code));
    return_handler();
    if (vm_fault != VM_FAULT_NONE || data[0] != 0x7AU)
        return 1;
    for (unsigned i = 1; i < sizeof(data); ++i)
        if (data[i] != 0)
            return 2;
    return 0;
}

static int test_bad_interpreter_state(void) {
    uint8_t data[8] = {0};
    data_seg_addr = (uintptr_t)data;
    data_seg_size = sizeof(data);
    code_seg_addr = 0;
    code_seg_size = 0;
    vm_frame_active = 0;
    vm_call_depth = 0;
    vm_fault = VM_FAULT_NONE;
    vm_interpreter();
    return vm_fault == VM_FAULT_BAD_STATE ? 0 : 1;
}

#define RUN_TEST(function_name, base) do { \
    const int result = function_name(); \
    if (result != 0) return (base) + result; \
} while (0)

int main(void) {
    RUN_TEST(test_integrity_known_vector, 10);
    RUN_TEST(test_authenticated_block_entry, 20);
    RUN_TEST(test_authenticated_block_tamper, 30);
    RUN_TEST(test_block_local_boundary, 40);
    RUN_TEST(test_valid_data_access, 50);
    RUN_TEST(test_data_out_of_bounds, 60);
    RUN_TEST(test_code_out_of_bounds, 70);
    RUN_TEST(test_invalid_width_and_null, 80);
    RUN_TEST(test_tampered_switch_case_count, 90);
    RUN_TEST(test_invalid_branch_target, 100);
    RUN_TEST(test_arithmetic_faults, 110);
    RUN_TEST(test_opcode_collision_sequence, 120);
    RUN_TEST(test_step_budget, 130);
    RUN_TEST(test_call_budget, 140);
    RUN_TEST(test_call_depth_limit, 150);
    RUN_TEST(test_reentrant_guard, 160);
    RUN_TEST(test_valid_interpreter_return, 170);
    RUN_TEST(test_return_clears_transient_data, 180);
    RUN_TEST(test_bad_interpreter_state, 190);
    return 0;
}
'''


def patch_interpreter() -> None:
    write("aVMPInterpreter/aVMPInterpreter.h", INTERPRETER_HEADER)
    write("tools/vmp-interpreter-bounds-smoke.c", INTERPRETER_TEST)

    source = "aVMPInterpreter/aVMPInterpreter.c"
    replace_once(
        source,
        '#include "aVMPInterpreter.h"\n',
        '#include "aVMPInterpreter.h"\n#include "VMPIntegrity.h"\n',
    )

    runtime_helpers = r'''VM_FORCE_INLINE uint32_t vm_read_u32_raw(uint64_t offset) {
    if (code_seg_addr == 0 || !vm_range_valid(offset, 4U, code_seg_size)) {
        vm_set_fault(VM_FAULT_CODE_RANGE);
        return 0;
    }
    return (uint32_t)vmp_integrity_load32_le(
        (const vmp_u8 *)(uintptr_t)(code_seg_addr + offset));
}

VM_FORCE_INLINE uint64_t vm_read_u64_raw(uint64_t offset) {
    if (code_seg_addr == 0 || !vm_range_valid(offset, 8U, code_seg_size)) {
        vm_set_fault(VM_FAULT_CODE_RANGE);
        return 0;
    }
    return (uint64_t)vmp_integrity_load64_le(
        (const vmp_u8 *)(uintptr_t)(code_seg_addr + offset));
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
int vm_enter_block(uint64_t block_offset) {
    uint32_t opcode_seed;
    uint32_t code_seed;
    uint32_t body_size;
    uint32_t magic;
    uint64_t expected_tag0;
    uint64_t expected_tag1;
    uint64_t computed_tag0 = 0;
    uint64_t computed_tag1 = 0;
    uint64_t body_start;
    uint64_t body_end;
    const vmp_u8 *ciphertext;

    if (vm_fault != VM_FAULT_NONE)
        return 0;
    if (block_offset > 0x7FFFFFFFULL ||
        !vm_range_valid(block_offset, VMP_BLOCK_HEADER_SIZE, code_seg_size)) {
        vm_set_fault(VM_FAULT_BLOCK_RANGE);
        return 0;
    }

    opcode_seed = vm_read_u32_raw(
        block_offset + VMP_BLOCK_OPCODE_SEED_OFFSET);
    code_seed = vm_read_u32_raw(
        block_offset + VMP_BLOCK_CODE_SEED_OFFSET);
    body_size = vm_read_u32_raw(
        block_offset + VMP_BLOCK_BODY_SIZE_OFFSET);
    magic = vm_read_u32_raw(block_offset + VMP_BLOCK_MAGIC_OFFSET);
    expected_tag0 = vm_read_u64_raw(block_offset + VMP_BLOCK_TAG0_OFFSET);
    expected_tag1 = vm_read_u64_raw(block_offset + VMP_BLOCK_TAG1_OFFSET);
    if (vm_fault != VM_FAULT_NONE)
        return 0;
    if (magic != VMP_BLOCK_MAGIC || opcode_seed == 0U || code_seed == 0U) {
        vm_set_fault(VM_FAULT_INTEGRITY);
        return 0;
    }

    body_start = block_offset + VMP_BLOCK_HEADER_SIZE;
    body_end = body_start + (uint64_t)body_size;
    if (body_end < body_start || body_end > 0x7FFFFFFFULL ||
        !vm_range_valid(body_start, body_size, code_seg_size)) {
        vm_set_fault(VM_FAULT_BLOCK_RANGE);
        return 0;
    }

    ciphertext = (const vmp_u8 *)(uintptr_t)(code_seg_addr + body_start);
    vmp_integrity_block_tags(
        ciphertext, body_size, vm_integrity_key0, vm_integrity_key1,
        block_offset, opcode_seed, code_seed,
        &computed_tag0, &computed_tag1);
    if (!(vmp_integrity_tag_equal(expected_tag0, computed_tag0) &
          vmp_integrity_tag_equal(expected_tag1, computed_tag1))) {
        vm_set_fault(VM_FAULT_INTEGRITY);
        return 0;
    }

    opcode_xorshift32_state = opcode_seed;
    vm_code_state = code_seed;
    ip = (int)body_start;
    vm_block_end = body_end;
    return 1;
}

VM_FORCE_INLINE int vm_consume_budget(uint64_t *remaining,
                                      uint32_t fault_code) {
    if (*remaining == 0) {
        vm_set_fault(fault_code);
        return 0;
    }
    --*remaining;
    return 1;
}

VM_FORCE_INLINE int vm_set_ip(uint64_t target) {
    if (target > 0x7FFFFFFFULL ||
        !vm_range_valid(target, VMP_BLOCK_HEADER_SIZE, code_seg_size)) {
        vm_set_fault(VM_FAULT_BLOCK_RANGE);
        return 0;
    }
    ip = (int)target;
    return 1;
}
'''
    replace_region(
        source,
        "VM_FORCE_INLINE int vm_set_ip(uint64_t target) {",
        "\n\n#ifdef IS_INLINE_FUNC\n    __inline__ __attribute__((always_inline))\n#endif\nuint8_t get_byte_code()",
        runtime_helpers,
    )

    get_byte_code = r'''uint8_t get_byte_code() {
    if (vm_fault != VM_FAULT_NONE)
        return 0;
    if (code_seg_addr == 0 || ip < 0 ||
        !vm_range_valid((uint64_t)ip, 1U, code_seg_size)) {
        vm_set_fault(VM_FAULT_CODE_RANGE);
        return 0;
    }
    if (vm_block_end == 0 ||
        !vm_range_valid((uint64_t)ip, 1U, vm_block_end)) {
        vm_set_fault(VM_FAULT_BLOCK_RANGE);
        return 0;
    }

    uint8_t tmp = ((uint8_t *)code_seg_addr)[ip++];
    tmp ^= (uint8_t)(xorshift32(&vm_code_state) & 0xFFU);
    return tmp;
}
'''
    replace_region(
        source,
        "uint8_t get_byte_code() {",
        "\n\n#ifdef IS_INLINE_FUNC\n    __inline__ __attribute__((always_inline))\n#endif\nuint32_t get_xorshift_seed()",
        get_byte_code,
    )

    unpack_code = r'''uint64_t unpack_code(int size) {
    uint64_t res = 0;
    if (!vm_width_valid(size)) {
        vm_set_fault(VM_FAULT_INVALID_SIZE);
        return 0;
    }
    if (vm_fault != VM_FAULT_NONE)
        return 0;
    if (code_seg_addr == 0 || ip < 0 ||
        !vm_range_valid((uint64_t)ip, (uint64_t)size, code_seg_size)) {
        vm_set_fault(VM_FAULT_CODE_RANGE);
        return 0;
    }
    if (vm_block_end == 0 ||
        !vm_range_valid((uint64_t)ip, (uint64_t)size, vm_block_end)) {
        vm_set_fault(VM_FAULT_BLOCK_RANGE);
        return 0;
    }

    for (int i = 0; i < size; ++i)
        res |= (uint64_t)get_byte_code() << (8 * i);
    return res;
}
'''
    replace_region(
        source,
        "uint64_t unpack_code(int size) {",
        "\n\n#ifdef IS_INLINE_FUNC\n    __inline__ __attribute__((always_inline))\n#endif\nuint64_t unpack_data",
        unpack_code,
    )

    replace_once(
        source,
        "    if (ip < 0 || (uint64_t)ip > code_seg_size) {\n"
        "        vm_set_fault(VM_FAULT_CODE_RANGE);\n"
        "        return;\n"
        "    }\n"
        "    const uint64_t remaining_code = code_seg_size - (uint64_t)ip;\n"
        "    if ((uint64_t)num_cases > remaining_code / bytes_per_case) {\n"
        "        vm_set_fault(VM_FAULT_CODE_RANGE);\n",
        "    if (vm_block_end == 0 || ip < 0 || (uint64_t)ip > vm_block_end) {\n"
        "        vm_set_fault(VM_FAULT_BLOCK_RANGE);\n"
        "        return;\n"
        "    }\n"
        "    const uint64_t remaining_code = vm_block_end - (uint64_t)ip;\n"
        "    if ((uint64_t)num_cases > remaining_code / bytes_per_case) {\n"
        "        vm_set_fault(VM_FAULT_BLOCK_RANGE);\n",
    )

    interpreter = r'''void vm_interpreter() {
    int entered_frame = 0;
    uint64_t next_block = 0;

    pointer_size = sizeof(void *);
    vm_fault = VM_FAULT_NONE;
    ip = 0;
    vm_block_end = 0;
    vm_steps_remaining =
        vm_step_limit == 0 ? ~(uint64_t)0 : vm_step_limit;
    vm_calls_remaining =
        vm_call_limit == 0 ? ~(uint64_t)0 : vm_call_limit;

    if (pointer_size != 8 || code_seg_addr == 0 || data_seg_addr == 0 ||
        code_seg_size < VMP_BLOCK_HEADER_SIZE || data_seg_size == 0) {
        vm_set_fault(VM_FAULT_BAD_STATE);
        goto cleanup;
    }
    if (vm_frame_active != 0U) {
        vm_set_fault(VM_FAULT_REENTRANT);
        goto cleanup;
    }
    if (vm_call_depth_limit != 0 &&
        vm_call_depth >= vm_call_depth_limit) {
        vm_set_fault(VM_FAULT_CALL_DEPTH);
        goto cleanup;
    }

    vm_frame_active = 1U;
    ++vm_call_depth;
    entered_frame = 1;

    if (!vm_enter_block(0))
        goto cleanup;

    while (vm_fault == VM_FAULT_NONE) {
        if (!vm_consume_budget(
                &vm_steps_remaining, VM_FAULT_STEP_LIMIT))
            break;

        const uint8_t opcode = get_opcode();
        if (vm_fault != VM_FAULT_NONE)
            break;

        switch (opcode) {
            case NOP_OP:
                break;
            case ALLOCA_OP:
                alloca_handler();
                break;
            case LOAD_OP:
                load_handler();
                break;
            case STORE_OP:
                store_handler();
                break;
            case BinaryOperator_OP:
                binaryOperator_handler();
                break;
            case GEP_OP:
                gep_handler();
                break;
            case CMP_OP:
                cmp_handler();
                break;
            case CAST_OP:
                cast_handler();
                break;
            case BR_OP:
                br_handler();
                if (vm_fault == VM_FAULT_NONE) {
                    next_block = (uint64_t)ip;
                    (void)vm_enter_block(next_block);
                }
                break;
            case SWITCH_OP:
                switch_handler();
                if (vm_fault == VM_FAULT_NONE) {
                    next_block = (uint64_t)ip;
                    (void)vm_enter_block(next_block);
                }
                break;
            case INSERTVALUE_OP:
            case EXTRACTVALUE_OP:
                vm_set_fault(VM_FAULT_INVALID_OPCODE);
                break;
            case Ret_OP:
                return_handler();
                goto cleanup;
            case Call_OP: {
                const uint64_t target_function_id = unpack_code(pointer_size);
                if (vm_fault == VM_FAULT_NONE &&
                    vm_consume_budget(
                        &vm_calls_remaining, VM_FAULT_CALL_LIMIT))
                    call_handler(target_function_id);
                break;
            }
            default:
                vm_set_fault(VM_FAULT_INVALID_OPCODE);
                break;
        }
    }

cleanup:
    if (entered_frame) {
        vm_frame_active = 0U;
        if (vm_call_depth != 0)
            --vm_call_depth;
    }
    if (vm_fault != VM_FAULT_NONE)
        vm_fail_closed();
}
'''
    replace_region(
        source,
        "void vm_interpreter() {",
        "\n\n// Main function removed",
        interpreter,
    )


def patch_translator() -> None:
    path = "llvm/lib/Transforms/Obfuscation/aVMP.cpp"
    replace_once(
        path,
        '#include "llvm/Transforms/Obfuscation/vm.h"\n#include <assert.h>',
        '#include "llvm/Transforms/Obfuscation/vm.h"\n'
        '#include "../../../../aVMPInterpreter/VMPIntegrity.h"\n'
        '#include <assert.h>',
    )

    replace_once(
        path,
        'static cl::opt<bool> VMPStrictCompatibility(\n'
        '    "irobf-vmp-strict", cl::init(false),\n'
        '    cl::desc("Fail compilation instead of skipping an incompatible VMP function"));\n',
        'static cl::opt<bool> VMPStrictCompatibility(\n'
        '    "irobf-vmp-strict", cl::init(false),\n'
        '    cl::desc("Fail compilation instead of skipping an incompatible VMP function"));\n'
        'static cl::opt<uint64_t> VMPMaxRuntimeSteps(\n'
        '    "irobf-vmp-max-runtime-steps", cl::init(10000000ULL),\n'
        '    cl::desc("Maximum VM opcodes per invocation; 0 disables the limit"));\n'
        'static cl::opt<uint64_t> VMPMaxRuntimeCalls(\n'
        '    "irobf-vmp-max-runtime-calls", cl::init(65536ULL),\n'
        '    cl::desc("Maximum VM call opcodes per invocation; 0 disables the limit"));\n'
        'static cl::opt<uint64_t> VMPMaxCallDepth(\n'
        '    "irobf-vmp-max-call-depth", cl::init(64ULL),\n'
        '    cl::desc("Maximum nested VMP wrapper depth per thread; 0 disables the limit"));\n',
    )

    old_domain = '''            std::string RandomDomain = "legacy-vmp|";
            RandomDomain += this->Mod->getModuleIdentifier();
            RandomDomain += '|';
            RandomDomain += this->F->getName().str();
            allvm::seedCryptoUtils(RandomEngine, RandomDomain.c_str());
'''
    new_domain = '''            std::string DomainSuffix = this->Mod->getModuleIdentifier();
            DomainSuffix += '|';
            DomainSuffix += this->F->getName().str();

            std::string LayoutDomain = "legacy-vmp-layout|" + DomainSuffix;
            allvm::seedCryptoUtils(RandomEngine, LayoutDomain.c_str());

            std::string IntegrityDomain =
                "legacy-vmp-integrity|" + DomainSuffix;
            allvm::seedCryptoUtils(IntegrityEngine, IntegrityDomain.c_str());
            do {
                IntegrityKey0 = IntegrityEngine.get_uint64_t();
                IntegrityKey1 = IntegrityEngine.get_uint64_t();
            } while ((IntegrityKey0 | IntegrityKey1) == 0);
'''
    replace_once(path, old_domain, new_domain)

    replace_once(
        path,
        "        CryptoUtils RandomEngine;\n"
        "        allvm::VMPResourceLimits ResourceLimits;",
        "        CryptoUtils RandomEngine;\n"
        "        CryptoUtils IntegrityEngine;\n"
        "        uint64_t IntegrityKey0 = 0;\n"
        "        uint64_t IntegrityKey1 = 0;\n"
        "        allvm::VMPResourceLimits ResourceLimits;",
    )

    replace_once(
        path,
        '''        uint64_t getDataSegmentSize() const {
            return curr_data_offset < 0
                       ? 0
                       : static_cast<uint64_t>(curr_data_offset);
        }
''',
        '''        uint64_t getDataSegmentSize() const {
            return curr_data_offset < 0
                       ? 0
                       : static_cast<uint64_t>(curr_data_offset);
        }

        uint64_t getIntegrityKey0() const { return IntegrityKey0; }
        uint64_t getIntegrityKey1() const { return IntegrityKey1; }
''',
    )

    replace_once(
        path,
        '''        /* encrypt vm_code */
        // mark seed for each basicblock
        std::vector<std::tuple<uint32_t, uint32_t, uint32_t>>
            vm_code_seed_ranges;
''',
        '''        struct VMPBlockRecord {
            uint32_t HeaderOffset;
            uint32_t BodyBegin;
            uint32_t BodyEnd;
            uint32_t OpcodeSeed;
            uint32_t CodeSeed;
        };
        std::vector<VMPBlockRecord> vm_blocks;
''',
    )

    old_encrypt = '''        void encrypt_vm_code() {
            for (const auto &Range : vm_code_seed_ranges) {
                uint32_t vm_code_seed = std::get<0>(Range);
                const uint32_t Begin = std::get<1>(Range);
                const uint32_t End = std::get<2>(Range);
                for (uint32_t addr = Begin; addr < End; ++addr)
                    vm_code[addr] ^= (xorshift32(&vm_code_seed) & 0xFF);
            }
        }
'''
    new_encrypt = '''        void encrypt_vm_code() {
            for (const VMPBlockRecord &Block : vm_blocks) {
                uint32_t vm_code_seed = Block.CodeSeed;
                for (uint32_t addr = Block.BodyBegin;
                     addr < Block.BodyEnd; ++addr)
                    vm_code[addr] ^= (xorshift32(&vm_code_seed) & 0xFF);
            }
        }

        bool seal_vm_blocks() {
            for (const VMPBlockRecord &Block : vm_blocks) {
                if (Block.BodyEnd < Block.BodyBegin ||
                    static_cast<size_t>(Block.HeaderOffset) +
                            VMP_BLOCK_HEADER_SIZE >
                        vm_code.size() ||
                    Block.BodyEnd > vm_code.size()) {
                    failTranslation("VMP authenticated block range is invalid");
                    return false;
                }

                const uint64_t BodySize64 =
                    static_cast<uint64_t>(Block.BodyEnd - Block.BodyBegin);
                if (BodySize64 > std::numeric_limits<uint32_t>::max()) {
                    failTranslation("VMP authenticated block body exceeds 32-bit size");
                    return false;
                }

                uint8_t *Header = vm_code.data() + Block.HeaderOffset;
                vmp_integrity_store32_le(
                    Header + VMP_BLOCK_BODY_SIZE_OFFSET,
                    static_cast<vmp_u32>(BodySize64));
                vmp_integrity_store32_le(
                    Header + VMP_BLOCK_MAGIC_OFFSET, VMP_BLOCK_MAGIC);

                vmp_u64 Tag0 = 0;
                vmp_u64 Tag1 = 0;
                vmp_integrity_block_tags(
                    vm_code.data() + Block.BodyBegin,
                    static_cast<vmp_u32>(BodySize64),
                    IntegrityKey0, IntegrityKey1,
                    Block.HeaderOffset, Block.OpcodeSeed, Block.CodeSeed,
                    &Tag0, &Tag1);
                vmp_integrity_store64_le(
                    Header + VMP_BLOCK_TAG0_OFFSET, Tag0);
                vmp_integrity_store64_le(
                    Header + VMP_BLOCK_TAG1_OFFSET, Tag1);
            }
            return true;
        }
'''
    replace_once(path, old_encrypt, new_encrypt)

    replace_once(
        path,
        '''        basicblock_map.emplace(bb, static_cast<int>(vm_code.size()));

        opcode_seed_setup();
        const uint32_t vm_code_seed = vm_code_seed_setup();
        const uint32_t currbb_begin = static_cast<uint32_t>(vm_code.size());
''',
        '''        const uint32_t block_header =
            static_cast<uint32_t>(vm_code.size());
        basicblock_map.emplace(bb, static_cast<int>(block_header));

        const uint32_t opcode_seed = opcode_seed_setup();
        const uint32_t vm_code_seed = vm_code_seed_setup();
        vm_code.resize(
            vm_code.size() + VMP_BLOCK_HEADER_SIZE - 8U, 0);
        const uint32_t currbb_begin =
            static_cast<uint32_t>(vm_code.size());
''',
    )

    replace_once(
        path,
        "        vm_code_seed_ranges.emplace_back(vm_code_seed, currbb_begin, currbb_end);",
        "        vm_blocks.push_back({block_header, currbb_begin, currbb_end,\n"
        "                             opcode_seed, vm_code_seed});",
    )

    replace_once(
        path,
        "    encrypt_vm_code();\n    construct_gv();",
        "    encrypt_vm_code();\n"
        "    if (!seal_vm_blocks())\n"
        "        return false;\n"
        "    construct_gv();",
    )

    constructor = '''        GOVMInterpreter(Function *F, Function *callinst_handler,
                        uint64_t CodeSegmentSize,
                        uint64_t DataSegmentSize,
                        uint64_t IntegrityKey0,
                        uint64_t IntegrityKey1,
                        uint64_t RuntimeStepLimit,
                        uint64_t RuntimeCallLimit,
                        uint64_t RuntimeCallDepthLimit) {
            this->Mod = F->getParent();
            this->F = F;
            this->modDataLayout =
                const_cast<DataLayout *>(&this->Mod->getDataLayout());
            this->callinst_handler = callinst_handler;
            this->CodeSegmentSize = CodeSegmentSize;
            this->DataSegmentSize = DataSegmentSize;
            this->IntegrityKey0 = IntegrityKey0;
            this->IntegrityKey1 = IntegrityKey1;
            this->RuntimeStepLimit = RuntimeStepLimit;
            this->RuntimeCallLimit = RuntimeCallLimit;
            this->RuntimeCallDepthLimit = RuntimeCallDepthLimit;

            construct_gv();
        }
'''
    replace_region(
        path,
        "        GOVMInterpreter(Function *F, Function *callinst_handler,",
        "\n\n        Module * Mod;",
        constructor,
    )

    old_fields = '''        Function *callinst_handler;
        uint64_t CodeSegmentSize = 0;
        uint64_t DataSegmentSize = 0;

        GlobalVariable *pointer_size_gv;
        GlobalVariable *opcode_xorshift32_state;
        GlobalVariable *vm_code_state;
        GlobalVariable *code_seg_size_gv;
        GlobalVariable *data_seg_size_gv;
        GlobalVariable *vm_fault_gv;
'''
    new_fields = '''        Function *callinst_handler;
        uint64_t CodeSegmentSize = 0;
        uint64_t DataSegmentSize = 0;
        uint64_t IntegrityKey0 = 0;
        uint64_t IntegrityKey1 = 0;
        uint64_t RuntimeStepLimit = 0;
        uint64_t RuntimeCallLimit = 0;
        uint64_t RuntimeCallDepthLimit = 0;

        GlobalVariable *pointer_size_gv;
        GlobalVariable *opcode_xorshift32_state;
        GlobalVariable *vm_code_state;
        GlobalVariable *code_seg_size_gv;
        GlobalVariable *data_seg_size_gv;
        GlobalVariable *vm_fault_gv;
        GlobalVariable *integrity_key0_gv;
        GlobalVariable *integrity_key1_gv;
        GlobalVariable *block_end_gv;
        GlobalVariable *step_limit_gv;
        GlobalVariable *call_limit_gv;
        GlobalVariable *call_depth_limit_gv;
        GlobalVariable *steps_remaining_gv;
        GlobalVariable *calls_remaining_gv;
        GlobalVariable *call_depth_gv;
        GlobalVariable *frame_active_gv;
'''
    replace_once(path, old_fields, new_fields)

    fault_block = '''    Constant *fault_init = ConstantInt::get(
        Type::getInt32Ty(Mod->getContext()), 0);
    vm_fault_gv = new GlobalVariable(
        *Mod, Type::getInt32Ty(Mod->getContext()), false,
        GlobalValue::InternalLinkage, fault_init,
        "vm_fault_" + F->getName());
    vm_fault_gv->setThreadLocal(true);
'''
    runtime_globals = fault_block + '''

    Constant *key0_init = ConstantInt::get(
        Type::getInt64Ty(Mod->getContext()), IntegrityKey0);
    integrity_key0_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), true,
        GlobalValue::InternalLinkage, key0_init,
        "vm_integrity_key0_" + F->getName());

    Constant *key1_init = ConstantInt::get(
        Type::getInt64Ty(Mod->getContext()), IntegrityKey1);
    integrity_key1_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), true,
        GlobalValue::InternalLinkage, key1_init,
        "vm_integrity_key1_" + F->getName());

    Constant *zero64 = ConstantInt::get(
        Type::getInt64Ty(Mod->getContext()), 0);
    block_end_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), false,
        GlobalValue::InternalLinkage, zero64,
        "vm_block_end_" + F->getName());
    block_end_gv->setThreadLocal(true);

    step_limit_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), true,
        GlobalValue::InternalLinkage,
        ConstantInt::get(Type::getInt64Ty(Mod->getContext()), RuntimeStepLimit),
        "vm_step_limit_" + F->getName());
    call_limit_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), true,
        GlobalValue::InternalLinkage,
        ConstantInt::get(Type::getInt64Ty(Mod->getContext()), RuntimeCallLimit),
        "vm_call_limit_" + F->getName());
    call_depth_limit_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), true,
        GlobalValue::InternalLinkage,
        ConstantInt::get(Type::getInt64Ty(Mod->getContext()),
                         RuntimeCallDepthLimit),
        "vm_call_depth_limit_" + F->getName());

    steps_remaining_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), false,
        GlobalValue::InternalLinkage, zero64,
        "vm_steps_remaining_" + F->getName());
    steps_remaining_gv->setThreadLocal(true);
    calls_remaining_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), false,
        GlobalValue::InternalLinkage, zero64,
        "vm_calls_remaining_" + F->getName());
    calls_remaining_gv->setThreadLocal(true);

    call_depth_gv =
        Mod->getGlobalVariable("__allvm_vmp_call_depth", true);
    if (call_depth_gv == nullptr) {
        call_depth_gv = new GlobalVariable(
            *Mod, Type::getInt64Ty(Mod->getContext()), false,
            GlobalValue::InternalLinkage, zero64,
            "__allvm_vmp_call_depth");
        call_depth_gv->setThreadLocal(true);
    } else if (call_depth_gv->getValueType() !=
               Type::getInt64Ty(Mod->getContext())) {
        report_fatal_error("ALLVM VMP call-depth TLS has an invalid type");
    }

    frame_active_gv = new GlobalVariable(
        *Mod, Type::getInt32Ty(Mod->getContext()), false,
        GlobalValue::InternalLinkage, fault_init,
        "vm_frame_active_" + F->getName());
    frame_active_gv->setThreadLocal(true);
'''
    replace_once(path, fault_block, runtime_globals)

    mapping = '''    std::vector<std::string> gv_list = {
        "ip", "data_seg_addr", "code_seg_addr", "pointer_size",
        "opcode_xorshift32_state", "vm_code_state",
        "code_seg_size", "data_seg_size", "vm_fault",
        "vm_integrity_key0", "vm_integrity_key1", "vm_block_end",
        "vm_step_limit", "vm_call_limit", "vm_call_depth_limit",
        "vm_steps_remaining", "vm_calls_remaining", "vm_call_depth",
        "vm_frame_active"};
    std::vector<GlobalVariable *> new_gv_list = {
        ip, data_seg_addr, code_seg_addr, pointer_size_gv,
        opcode_xorshift32_state, vm_code_state, code_seg_size_gv,
        data_seg_size_gv, vm_fault_gv, integrity_key0_gv,
        integrity_key1_gv, block_end_gv, step_limit_gv, call_limit_gv,
        call_depth_limit_gv, steps_remaining_gv, calls_remaining_gv,
        call_depth_gv, frame_active_gv};
'''
    replace_region(
        path,
        "    std::vector<std::string> gv_list = {",
        "    for (unsigned i = 0; i < gv_list.size(); i++) {",
        mapping,
    )

    replace_once(
        path,
        '''        eraseUnusedGlobal(Interpreter->vm_fault_gv);
''',
        '''        eraseUnusedGlobal(Interpreter->vm_fault_gv);
        eraseUnusedGlobal(Interpreter->integrity_key0_gv);
        eraseUnusedGlobal(Interpreter->integrity_key1_gv);
        eraseUnusedGlobal(Interpreter->block_end_gv);
        eraseUnusedGlobal(Interpreter->step_limit_gv);
        eraseUnusedGlobal(Interpreter->call_limit_gv);
        eraseUnusedGlobal(Interpreter->call_depth_limit_gv);
        eraseUnusedGlobal(Interpreter->steps_remaining_gv);
        eraseUnusedGlobal(Interpreter->calls_remaining_gv);
        eraseUnusedGlobal(Interpreter->call_depth_gv);
        eraseUnusedGlobal(Interpreter->frame_active_gv);
''',
    )

    replace_once(
        path,
        '''    GOVMInterpreter Interpreter(
        &F, Translator.get_callinst_handler(),
        Translator.getCodeSegmentSize(), Translator.getDataSegmentSize());
''',
        '''    GOVMInterpreter Interpreter(
        &F, Translator.get_callinst_handler(),
        Translator.getCodeSegmentSize(), Translator.getDataSegmentSize(),
        Translator.getIntegrityKey0(), Translator.getIntegrityKey1(),
        static_cast<uint64_t>(VMPMaxRuntimeSteps),
        static_cast<uint64_t>(VMPMaxRuntimeCalls),
        static_cast<uint64_t>(VMPMaxCallDepth));
''',
    )


def patch_preflight() -> None:
    path = "llvm/lib/Transforms/Obfuscation/VMPCompatibility.cpp"
    replace_once(
        path,
        '#include "llvm/Transforms/Obfuscation/VMPCompatibility.h"\n',
        '#include "llvm/Transforms/Obfuscation/VMPCompatibility.h"\n'
        '#include "../../../../aVMPInterpreter/VMPIntegrity.h"\n',
    )
    replace_once(
        path,
        '''    if (!checkedAdd(Result.EstimatedCodeBytes, 8))
      reject(Result, "基本块随机种子导致代码大小溢出");
''',
        '''    if (!checkedAdd(Result.EstimatedCodeBytes,
                    VMP_BLOCK_HEADER_SIZE))
      reject(Result, "基本块认证头导致代码大小溢出");
''',
    )


def patch_hardening_checker() -> None:
    path = "tools/check-hardening.py"
    replace_once(
        path,
        '    interpreter_header = read("aVMPInterpreter/aVMPInterpreter.h")\n',
        '    interpreter_header = read("aVMPInterpreter/aVMPInterpreter.h")\n'
        '    integrity_header = read("aVMPInterpreter/VMPIntegrity.h")\n',
    )
    replace_once(
        path,
        '''    required_vmp = (
        "legacy-vmp|",
        "getModuleIdentifier()",
        "getName().str()",
        "seedCryptoUtils(RandomEngine, RandomDomain.c_str())",
        "while (Seed == 0)",
    )
''',
        '''    required_vmp = (
        "legacy-vmp-layout|",
        "legacy-vmp-integrity|",
        "getModuleIdentifier()",
        "getName().str()",
        "seedCryptoUtils(RandomEngine, LayoutDomain.c_str())",
        "seedCryptoUtils(IntegrityEngine, IntegrityDomain.c_str())",
        "while (Seed == 0)",
    )
''',
    )
    replace_once(
        path,
        '''        "irobf-vmp-max-data-bytes",
        "irobf-vmp-strict",
        "analyzeVMPFunction",
''',
        '''        "irobf-vmp-max-data-bytes",
        "irobf-vmp-max-runtime-steps",
        "irobf-vmp-max-runtime-calls",
        "irobf-vmp-max-call-depth",
        "irobf-vmp-strict",
        "analyzeVMPFunction",
        "seal_vm_blocks",
        "VMP_BLOCK_HEADER_SIZE",
''',
    )
    replace_once(
        path,
        '''        "VM_FAULT_INVALID_OPCODE",
        "VM_FAULT_BAD_STATE",
        "extern uint64_t code_seg_size",
''',
        '''        "VM_FAULT_INVALID_OPCODE",
        "VM_FAULT_BAD_STATE",
        "VM_FAULT_INTEGRITY",
        "VM_FAULT_STEP_LIMIT",
        "VM_FAULT_CALL_LIMIT",
        "VM_FAULT_CALL_DEPTH",
        "VM_FAULT_REENTRANT",
        "VM_FAULT_BLOCK_RANGE",
        "extern uint64_t code_seg_size",
''',
    )
    replace_once(
        path,
        '''        "extern uint32_t vm_fault",
    )
''',
        '''        "extern uint32_t vm_fault",
        "extern uint64_t vm_integrity_key0",
        "extern uint64_t vm_steps_remaining",
        "extern uint64_t vm_call_depth",
        "extern uint32_t vm_frame_active",
    )
''',
    )
    replace_once(
        path,
        '''    interpreter_source_markers = (
        "VM_FORCE_INLINE static __inline__",
        "vm_range_valid",
        "vm_fail_closed",
        "vm_set_ip",
        "remaining_code / bytes_per_case",
        "VM_FAULT_ARITHMETIC",
        "data_seg_clean((int)var_size)",
        "code_seg_size < 8",
        "pointer_size != 8",
    )
''',
        '''    interpreter_source_markers = (
        "VM_FORCE_INLINE static __inline__",
        "vm_range_valid",
        "vm_fail_closed",
        "vm_set_ip",
        "vm_enter_block",
        "vmp_integrity_block_tags",
        "vm_consume_budget",
        "remaining_code / bytes_per_case",
        "VM_FAULT_ARITHMETIC",
        "VM_FAULT_INTEGRITY",
        "VM_FAULT_STEP_LIMIT",
        "VM_FAULT_CALL_LIMIT",
        "data_seg_clean((int)var_size)",
        "code_seg_size < VMP_BLOCK_HEADER_SIZE",
        "pointer_size != 8",
    )
''',
    )
    replace_once(
        path,
        '''        '"code_seg_size", "data_seg_size", "vm_fault"',
        "vm_fault_gv->setThreadLocal(true)",
''',
        '''        '"code_seg_size", "data_seg_size", "vm_fault"',
        '"vm_integrity_key0", "vm_integrity_key1", "vm_block_end"',
        '"vm_steps_remaining", "vm_calls_remaining", "vm_call_depth"',
        "vm_fault_gv->setThreadLocal(true)",
        "frame_active_gv->setThreadLocal(true)",
''',
    )
    replace_once(
        path,
        '''        "test_valid_data_access",
''',
        '''        "test_integrity_known_vector",
        "test_authenticated_block_entry",
        "test_authenticated_block_tamper",
        "test_block_local_boundary",
        "test_step_budget",
        "test_call_budget",
        "test_call_depth_limit",
        "test_reentrant_guard",
        "test_valid_data_access",
''',
    )
    replace_once(
        path,
        '''    embed_checker_markers = (
''',
        '''    integrity_markers = (
        "VMP_BLOCK_HEADER_SIZE",
        "VMP_BLOCK_MAGIC",
        "vmp_integrity_block_tags",
        "vmp_integrity_sip_round",
        "vmp_integrity_tag_equal",
    )
    ok, missing = contains_all(integrity_header, integrity_markers)
    add(
        results,
        "VMP 分块认证原语",
        ok,
        "共享双标签 SipHash 块格式存在"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    embed_checker_markers = (
''',
    )
    replace_once(
        path,
        '''        "-irobf-vmp-max-code-bytes",
        "运行时段边界与 fail-closed",
''',
        '''        "-irobf-vmp-max-code-bytes",
        "-irobf-vmp-max-runtime-steps",
        "分块认证",
        "运行时段边界与 fail-closed",
''',
    )
    replace_once(
        path,
        '''        "运行时段边界与 fail-closed",
        "VM_FAULT_CODE_RANGE",
''',
        '''        "运行时段边界与 fail-closed",
        "分块认证",
        "VM_FAULT_CODE_RANGE",
        "VM_FAULT_INTEGRITY",
''',
    )


def patch_workflow() -> None:
    path = ".github/workflows/hardening-smoke.yml"
    replace_all(
        path,
        '      - "aVMPInterpreter/aVMPInterpreter.h"\n',
        '      - "aVMPInterpreter/aVMPInterpreter.h"\n'
        '      - "aVMPInterpreter/VMPIntegrity.h"\n',
        minimum=2,
    )
    replace_all(
        path,
        "            aVMPInterpreter/aVMPInterpreter.h\n",
        "            aVMPInterpreter/aVMPInterpreter.h\n"
        "            aVMPInterpreter/VMPIntegrity.h\n",
        minimum=2,
    )
    replace_all(
        path,
        "          grep -q '@vm_fault' /tmp/aVMPInterpreter.ll\n",
        "          grep -q '@vm_fault' /tmp/aVMPInterpreter.ll\n"
        "          grep -q '@vm_integrity_key0' /tmp/aVMPInterpreter.ll\n"
        "          grep -q '@vm_block_end' /tmp/aVMPInterpreter.ll\n"
        "          grep -q '@vm_steps_remaining' /tmp/aVMPInterpreter.ll\n"
        "          grep -q '@vm_call_depth' /tmp/aVMPInterpreter.ll\n"
        "          grep -q '@vm_frame_active' /tmp/aVMPInterpreter.ll\n",
        minimum=1,
    )
    replace_all(
        path,
        "          grep -q '@vm_fault' /tmp/checked-aVMPInterpreter.ll\n",
        "          grep -q '@vm_fault' /tmp/checked-aVMPInterpreter.ll\n"
        "          grep -q '@vm_integrity_key0' /tmp/checked-aVMPInterpreter.ll\n"
        "          grep -q '@vm_block_end' /tmp/checked-aVMPInterpreter.ll\n"
        "          grep -q '@vm_steps_remaining' /tmp/checked-aVMPInterpreter.ll\n"
        "          grep -q '@vm_call_depth' /tmp/checked-aVMPInterpreter.ll\n"
        "          grep -q '@vm_frame_active' /tmp/checked-aVMPInterpreter.ll\n",
        minimum=1,
    )
    replace_all(
        path,
        "vm_set_ip|vm_fail_closed)'",
        "vm_set_ip|vm_fail_closed|vm_enter_block|vm_consume_budget)'",
        minimum=2,
    )


def patch_docs() -> None:
    readme = "README.md"
    replace_once(
        readme,
        "- VMP 解释器加入 code/data 段长度、TLS fault 状态、跳转/switch 边界、fail-closed 和返回后临时数据清理；\n",
        "- VMP 解释器加入 code/data 段长度、TLS fault 状态、跳转/switch 边界、fail-closed 和返回后临时数据清理；\n"
        "- VMP 每个基本块采用 32 字节认证头和双 64 位 SipHash 标签，执行前认证块元数据与加密正文；\n"
        "- VMP 增加每次调用的 opcode 步数、Call opcode 次数、线程共享调用深度和同函数重入限制；\n",
    )
    replace_once(
        readme,
        "| 旧版 VMP | 按模块和函数派生种子；转换前检查 IR/ABI/资源；运行时检查 code/data 段与跳转边界；TLS fault fail-closed；转换后运行 IR verifier | 当前嵌入解释器仅支持 64 位目标；外部原始指针仍无法获知对象长度；字节码仍使用 xorshift 且没有认证标签 |",
        "| 旧版 VMP | 布局与认证密钥按函数分域；转换前检查 IR/ABI/资源；每块执行前验证双 SipHash 标签；运行时限制步数、调用数、线程调用深度和重入；TLS fault fail-closed；转换后运行 IR verifier | 当前嵌入解释器仅支持 64 位目标；外部原始指针仍无法获知对象长度；认证密钥位于客户端，标签不是 AEAD，也不提供密钥不可提取保证 |",
    )
    replace_all(
        readme,
        "└── legacy-vmp | ModuleIdentifier | FunctionName",
        "├── legacy-vmp-layout | ModuleIdentifier | FunctionName\n"
        "└── legacy-vmp-integrity | ModuleIdentifier | FunctionName",
        minimum=1,
    )
    replace_once(
        readme,
        "LOCAL_CFLAGS += -mllvm -irobf-vmp-strict\nLOCAL_CFLAGS += -frtti -fno-exceptions",
        "LOCAL_CFLAGS += -mllvm -irobf-vmp-strict\n"
        "LOCAL_CFLAGS += -mllvm -irobf-vmp-max-runtime-steps=10000000\n"
        "LOCAL_CFLAGS += -mllvm -irobf-vmp-max-runtime-calls=65536\n"
        "LOCAL_CFLAGS += -mllvm -irobf-vmp-max-call-depth=64\n"
        "LOCAL_CFLAGS += -frtti -fno-exceptions",
    )
    replace_all(
        readme,
        "| `-mllvm -irobf-vmp-max-data-bytes=N` | `16777216` | 估算和实际 VM 数据区上限，16 MiB |\n",
        "| `-mllvm -irobf-vmp-max-data-bytes=N` | `16777216` | 估算和实际 VM 数据区上限，16 MiB |\n"
        "| `-mllvm -irobf-vmp-max-runtime-steps=N` | `10000000` | 单次解释调用允许的最大 opcode 步数，0 表示不限 |\n"
        "| `-mllvm -irobf-vmp-max-runtime-calls=N` | `65536` | 单次解释调用允许的最大 Call opcode 次数，0 表示不限 |\n"
        "| `-mllvm -irobf-vmp-max-call-depth=N` | `64` | 同一线程允许的嵌套 VMP wrapper 深度，0 表示不限 |\n",
        minimum=1,
    )
    replace_once(
        readme,
        "每个受保护函数的可变运行状态被放入线程局部存储，改善不同线程同时调用的隔离性。**直接递归会被拒绝**；互递归和间接递归仍无法完全静态识别，应避免用于 VMP 函数。VM 内部栈和调用栈的完整动态预算仍属于后续工作。",
        "每个受保护函数的可变运行状态被放入线程局部存储。直接递归仍在预检阶段拒绝；运行时另用模块级 TLS 记录跨 VMP 函数调用深度，并用每函数 `vm_frame_active` 拒绝同函数重入，因此互递归或间接递归即使逃过静态分析也会 fail-closed。旧版解释器没有独立操作数栈，值槽已按实际数据区动态创建；新增的步数、Call 次数和调用深度预算用于限制循环和嵌套执行资源。",
    )
    replace_once(
        readme,
        "#### 运行时段边界与 fail-closed",
        "#### 分块认证\n\n"
        "每个 VM 基本块现在使用固定 32 字节头：两个非零随机种子、密文正文长度、格式 magic 和两个 64 位认证标签。标签使用按函数独立派生的 128 位密钥，对块偏移、版本、正文长度、两个种子和**加密后的正文**计算。branch/switch 只能跳到完整块头，解释器在设置 opcode/代码流状态前先认证目标块，任意正文、长度、种子、标签或块位置变更都会设置 `VM_FAULT_INTEGRITY` 或 `VM_FAULT_BLOCK_RANGE`。\n\n"
        "这是客户端内嵌密钥的分块 MAC，不是 AEAD：xorshift 仍只负责混淆，标签不提供额外保密性；有能力提取并复用客户端密钥的攻击者仍可重签名补丁。它解决的是未授权修改在执行前可检测，以及普通二进制补丁不能再静默改变 VM 语义。\n\n"
        "#### 运行时段边界与 fail-closed",
    )
    replace_once(
        readme,
        "VM_FAULT_BAD_STATE\n```",
        "VM_FAULT_BAD_STATE\n"
        "VM_FAULT_INTEGRITY\n"
        "VM_FAULT_STEP_LIMIT\n"
        "VM_FAULT_CALL_LIMIT\n"
        "VM_FAULT_CALL_DEPTH\n"
        "VM_FAULT_REENTRANT\n"
        "VM_FAULT_BLOCK_RANGE\n```",
    )
    replace_once(
        readme,
        "- opcode、种子、立即数和 switch 表不能越过 code 段；\n",
        "- 块头和密文正文必须通过双标签认证，且读取不能越过当前认证块；\n"
        "- opcode、立即数和 switch 表不能越过当前块或 code 段；\n",
    )
    replace_once(
        readme,
        "- 返回时保留返回值槽，并清零其余 VM data 段；\n",
        "- 每次解释调用限制 opcode 步数和 Call opcode 次数；跨函数共享 TLS 调用深度，并拒绝同函数重入；\n"
        "- 返回时保留返回值槽，并清零其余 VM data 段；\n",
    )
    replace_once(
        readme,
        "需要明确：xorshift 字节流仍只是可逆混淆，不是 AEAD，修改 VM 字节码也尚无统一认证标签。预检和运行时边界解决的是语义兼容性、资源失控、越界和静默错误，不等于密码学完整性保护。",
        "需要明确：xorshift 字节流仍只是可逆混淆，不是 AEAD。新增双 SipHash 标签提供执行前的分块完整性验证，但认证密钥也存在于客户端，因此不能替代服务端信任、硬件密钥或不可导出的长期秘密。",
    )
    replace_all(
        readme,
        "| `-mllvm -irobf-vmp-max-data-bytes=N` | VMP 数据预算；默认 16 MiB，0 表示关闭 |\n",
        "| `-mllvm -irobf-vmp-max-data-bytes=N` | VMP 数据预算；默认 16 MiB，0 表示关闭 |\n"
        "| `-mllvm -irobf-vmp-max-runtime-steps=N` | 单次 VM opcode 步数预算；默认 10000000 |\n"
        "| `-mllvm -irobf-vmp-max-runtime-calls=N` | 单次 Call opcode 预算；默认 65536 |\n"
        "| `-mllvm -irobf-vmp-max-call-depth=N` | 每线程嵌套 VMP wrapper 深度；默认 64 |\n",
        minimum=1,
    )
    replace_once(
        readme,
        "| `aVMPInterpreter/aVMPInterpreter.c` | 带 code/data 边界和 fail-closed fault 的嵌入解释器源码 |",
        "| `aVMPInterpreter/VMPIntegrity.h` | 翻译器与解释器共享的认证块格式和双 SipHash 标签实现 |\n"
        "| `aVMPInterpreter/aVMPInterpreter.c` | 带分块认证、执行预算、code/data 边界和 fail-closed fault 的嵌入解释器源码 |",
    )

    doc = "docs/ALLVM_HARDENING.md"
    replace_once(
        doc,
        "- 字符串和 VMP 字节码的认证加密；",
        "- 字符串记录的标准 AEAD，以及客户端认证密钥不可提取；",
    )
    replace_all(
        doc,
        "└── legacy-vmp | ModuleIdentifier | FunctionName",
        "├── legacy-vmp-layout | ModuleIdentifier | FunctionName\n"
        "└── legacy-vmp-integrity | ModuleIdentifier | FunctionName",
        minimum=1,
    )
    replace_once(
        doc,
        "legacy-vmp | ModuleIdentifier | FunctionName",
        "legacy-vmp-layout | ModuleIdentifier | FunctionName\n"
        "legacy-vmp-integrity | ModuleIdentifier | FunctionName",
    )
    replace_once(
        doc,
        "该改动只改善种子质量和隔离；xorshift 仍是可逆混淆，不是 AEAD。",
        "布局随机流与认证密钥使用不同域。xorshift 仍是可逆混淆，不是 AEAD；完整性由后述分块标签单独负责。",
    )
    replace_once(
        doc,
        "- VM 内部栈和调用栈的完整动态预算仍是后续工作。",
        "- 旧版解释器没有独立操作数栈；数据值槽继续按实际结果动态创建；\n"
        "- 运行时限制 opcode 步数、Call opcode 次数和线程共享调用深度，并用每函数活动标志拒绝同函数重入。",
    )
    replace_once(
        doc,
        "### 5.5 运行时段边界与 fail-closed",
        "### 5.5 分块认证与执行预算\n\n"
        "每个基本块格式由原来的 8 字节种子头升级为固定 32 字节认证头：\n\n"
        "```text\n"
        "opcode_seed : u32\n"
        "code_seed   : u32\n"
        "body_size   : u32\n"
        "magic       : u32\n"
        "tag0        : u64\n"
        "tag1        : u64\n"
        "ciphertext  : body_size bytes\n"
        "```\n\n"
        "翻译器使用独立的 `legacy-vmp-integrity` 域派生 128 位函数密钥。两个域分离的 SipHash-2-4 标签覆盖版本、块偏移、正文长度、两个种子及加密正文。解释器先验证范围、magic 和两个标签，再设置流状态和 IP。branch/switch 目标必须指向完整块头，读取也不能跨过当前认证块。\n\n"
        "新增运行时参数：\n\n"
        "```text\n"
        "-irobf-vmp-max-runtime-steps=10000000\n"
        "-irobf-vmp-max-runtime-calls=65536\n"
        "-irobf-vmp-max-call-depth=64\n"
        "```\n\n"
        "0 表示关闭对应限制。步数预算限制循环，调用预算限制单次解释中的 Call opcode，模块级 TLS 深度限制跨 VMP 函数嵌套；每函数 TLS 活动标志拒绝同函数重入。密钥位于客户端，所以标签不是不可伪造的远程信任根，也不提供 xorshift 之外的保密性。\n\n"
        "### 5.6 运行时段边界与 fail-closed",
    )
    replace_once(doc, "### 5.6 嵌入产物与可执行测试", "### 5.7 嵌入产物与可执行测试")
    replace_once(
        doc,
        "VM_FAULT_BAD_STATE\n```",
        "VM_FAULT_BAD_STATE\n"
        "VM_FAULT_INTEGRITY\n"
        "VM_FAULT_STEP_LIMIT\n"
        "VM_FAULT_CALL_LIMIT\n"
        "VM_FAULT_CALL_DEPTH\n"
        "VM_FAULT_REENTRANT\n"
        "VM_FAULT_BLOCK_RANGE\n```",
    )
    replace_once(
        doc,
        "- 所有 code 字节读取在推进 IP 前验证剩余长度；\n",
        "- 每次进入基本块先验证双标签，所有 code 字节读取同时受当前块和总 code 段边界约束；\n",
    )
    replace_once(
        doc,
        "- 返回后保留返回值槽并清零其余 data 段；\n",
        "- opcode 步数、Call 次数、调用深度和重入超过预算时设置独立 fault；\n"
        "- 返回后保留返回值槽并清零其余 data 段；\n",
    )
    replace_once(
        doc,
        "- 解释器坏状态。\n",
        "- 解释器坏状态；\n"
        "- 固定 SipHash 向量、合法认证块、密文/标签/长度篡改和块内越界；\n"
        "- opcode 步数、Call 次数、调用深度和重入预算。\n",
    )
    replace_once(
        doc,
        "需要明确：运行时边界和兼容性预检不能替代 VMP 字节码认证。现有字节流仍无密码学篡改标签。",
        "需要明确：双 SipHash 标签会在执行前检测块篡改，但密钥和验证器同驻客户端，不能提供服务端级不可伪造信任；xorshift 也仍不是 AEAD。",
    )
    replace_once(
        doc,
        "1. 字符串记录改为标准 AEAD，并定义缓存、TLS 和调用期明文生命周期；\n"
        "2. VMP 字节码增加分块完整性标签；\n"
        "3. 在已动态化 code/data 缓冲并加入资源预检的基础上，继续动态化 VM 内部栈和调用栈；\n"
        "4. 扩展 capability analysis 覆盖面、互递归检测和机器可读跳过报告；",
        "1. 字符串记录改为标准 AEAD，并定义缓存、TLS 和调用期明文生命周期；\n"
        "2. 扩展 capability analysis 覆盖面、互递归静态检测和机器可读跳过报告；\n"
        "3. 为分块认证增加可选设备/服务端派生因子，降低纯离线重签名能力；\n"
        "4. 增加真实 Android 递归、并发和长循环的预算回归矩阵；",
    )


def main() -> int:
    integrity = read("aVMPInterpreter/VMPIntegrity.h")
    for marker in (
        "VMP_BLOCK_HEADER_SIZE",
        "vmp_integrity_block_tags",
        "vmp_integrity_tag_equal",
    ):
        if marker not in integrity:
            raise SystemExit(f"missing VMP integrity primitive: {marker}")

    patch_interpreter()
    patch_translator()
    patch_preflight()
    patch_hardening_checker()
    patch_workflow()
    patch_docs()
    print("authenticated VMP block and runtime budget migration applied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
