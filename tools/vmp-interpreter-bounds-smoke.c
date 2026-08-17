//===- vmp-interpreter-bounds-smoke.c - native runtime bounds test -------===//
//
// Compiles the interpreter directly into this translation unit so the tests
// exercise the same helpers that are emitted into the embedded bitcode.
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

void call_handler(uint64_t targetfunc_id) {
    (void)targetfunc_id;
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
    vm_code_state = 0;
    opcode_xorshift32_state = 0;
    vm_fault = VM_FAULT_NONE;
}

static void write_le(uint8_t *buffer, uint64_t value, unsigned size) {
    for (unsigned i = 0; i < size; ++i) {
        buffer[i] = (uint8_t)(value & 0xFFU);
        value >>= 8;
    }
}

static unsigned encode_const_u64(uint8_t *buffer, uint64_t value) {
    buffer[0] = 8; // value size
    buffer[1] = 1; // non-zero value type means an inline constant
    write_le(buffer + 2, value, 8);
    return 10;
}

static unsigned build_binary_code(uint8_t *code, uint8_t opcode,
                                  uint64_t left, uint64_t right) {
    write_le(code, 0, 8); // result offset
    code[8] = 8;         // result width
    code[9] = 0;         // result type is currently unused by the handler
    code[10] = opcode;

    unsigned offset = 11;
    offset += encode_const_u64(code + offset, left);
    offset += encode_const_u64(code + offset, right);
    return offset;
}

static int test_valid_data_access(void) {
    uint8_t data[16];
    reset_data(data, sizeof(data));

    pack_data(4, 0x11223344U, 4);
    if (vm_fault != VM_FAULT_NONE)
        return 1;
    if (unpack_data(4, 4) != 0x11223344U)
        return 2;
    if (vm_fault != VM_FAULT_NONE)
        return 3;
    return 0;
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
    if (vm_fault != VM_FAULT_DATA_RANGE)
        return 3;
    return 0;
}

static int test_code_out_of_bounds(void) {
    uint8_t code[4] = {0, 0, 0, 0};
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
    if (vm_fault != VM_FAULT_NULL_ADDRESS)
        return 2;
    return 0;
}

static int test_tampered_switch_case_count(void) {
    // get_value(const i8 0), num_cases=UINT32_MAX, case_size=1,
    // default_target=0. No case table bytes remain.
    uint8_t code[19] = {0};
    code[0] = 1; // condition size
    code[1] = 1; // constant
    code[2] = 0; // condition value
    write_le(code + 3, 0xFFFFFFFFU, 4);
    write_le(code + 7, 1, 4);
    write_le(code + 11, 0, 8);
    reset_code(code, sizeof(code));

    switch_handler();
    if (vm_fault != VM_FAULT_CODE_RANGE)
        return 1;
    if (ip != (int)sizeof(code))
        return 2;
    return 0;
}

static int test_invalid_branch_target(void) {
    uint8_t code[9] = {0};
    code[0] = 0; // unconditional branch
    write_le(code + 1, 999, 8);
    reset_code(code, sizeof(code));

    br_handler();
    return vm_fault == VM_FAULT_CODE_RANGE ? 0 : 1;
}

static int test_arithmetic_faults(void) {
    uint8_t data[16];
    uint8_t code[31];
    unsigned code_size = 0;

    reset_data(data, sizeof(data));
    fill_bytes(code, sizeof(code), 0);
    code_size = build_binary_code(code, BINOP_UDIV, 10, 0);
    reset_code(code, code_size);
    binaryOperator_handler();
    if (vm_fault != VM_FAULT_ARITHMETIC)
        return 1;

    reset_data(data, sizeof(data));
    fill_bytes(code, sizeof(code), 0);
    code_size = build_binary_code(code, BINOP_SHL, 1, 64);
    reset_code(code, code_size);
    binaryOperator_handler();
    if (vm_fault != VM_FAULT_ARITHMETIC)
        return 2;

    return 0;
}

static int test_return_clears_transient_data(void) {
    uint8_t data[8];
    uint8_t code[3] = {1, 1, 0x7AU}; // return const i8 0x7a
    reset_data(data, sizeof(data));
    fill_bytes(data, sizeof(data), 0xCCU);
    reset_code(code, sizeof(code));

    return_handler();
    if (vm_fault != VM_FAULT_NONE)
        return 1;
    if (data[0] != 0x7AU)
        return 2;
    for (unsigned i = 1; i < sizeof(data); ++i)
        if (data[i] != 0)
            return 3;
    return 0;
}

static int test_bad_interpreter_state(void) {
    uint8_t data[8] = {0};
    data_seg_addr = (uintptr_t)data;
    data_seg_size = sizeof(data);
    code_seg_addr = 0;
    code_seg_size = 0;
    vm_fault = VM_FAULT_NONE;

    vm_interpreter();
    return vm_fault == VM_FAULT_BAD_STATE ? 0 : 1;
}

int main(void) {
    int result = 0;

    result = test_valid_data_access();
    if (result != 0)
        return 10 + result;

    result = test_data_out_of_bounds();
    if (result != 0)
        return 20 + result;

    result = test_code_out_of_bounds();
    if (result != 0)
        return 30 + result;

    result = test_invalid_width_and_null();
    if (result != 0)
        return 40 + result;

    result = test_tampered_switch_case_count();
    if (result != 0)
        return 50 + result;

    result = test_invalid_branch_target();
    if (result != 0)
        return 60 + result;

    result = test_arithmetic_faults();
    if (result != 0)
        return 70 + result;

    result = test_return_clears_transient_data();
    if (result != 0)
        return 80 + result;

    result = test_bad_interpreter_state();
    if (result != 0)
        return 90 + result;

    return 0;
}
