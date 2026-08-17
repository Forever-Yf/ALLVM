//===- vmp-interpreter-bounds-smoke.c - native authenticated runtime test ===//
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
    uint8_t code[128];
    const uint8_t first_body[1] = {0xA5U};
    const uint8_t second_body[1] = {0};
    const unsigned first_size = build_authenticated_block(
        code, sizeof(code), first_body, sizeof(first_body), 17U, 19U, 0);
    const unsigned second_size = build_authenticated_block(
        code + first_size, sizeof(code) - first_size,
        second_body, sizeof(second_body), 23U, 29U, first_size);
    const unsigned total_size = first_size + second_size;
    if (first_size == 0 || second_size == 0)
        return 1;

    reset_code(code, total_size);
    vm_block_end = 0;
    if (!vm_enter_block(0))
        return 2;
    (void)get_byte_code();
    if (vm_fault != VM_FAULT_NONE)
        return 3;
    (void)get_byte_code();
    return vm_fault == VM_FAULT_BLOCK_RANGE ? 0 : 4;
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
