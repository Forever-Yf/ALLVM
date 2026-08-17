#include "aVMPInterpreter.h"

// #define GOVM_CPP_DEBUG

#define IS_INLINE_FUNC

#ifdef IS_INLINE_FUNC
#define VM_FORCE_INLINE static __inline__ __attribute__((always_inline))
#else
#define VM_FORCE_INLINE static
#endif

//
extern uintptr_t data_seg_addr;
extern uintptr_t code_seg_addr;

extern int ip;

extern unsigned pointer_size;

// Opcode encrypt by xorshift32
extern uint32_t opcode_xorshift32_state;
extern uint32_t vm_code_state;

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
/* The state word must be initialized to non-zero */
uint32_t xorshift32(uint32_t *state)
{
    /* Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs" */
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return *state = x;
}

VM_FORCE_INLINE void vm_set_fault(uint32_t fault_code) {
    if (vm_fault == VM_FAULT_NONE)
        vm_fault = fault_code;
}

VM_FORCE_INLINE int vm_width_valid(int size) {
    return size >= 0 && size <= 8;
}

VM_FORCE_INLINE int vm_range_valid(uint64_t offset, uint64_t size, uint64_t limit) {
    return offset <= limit && size <= limit - offset;
}

VM_FORCE_INLINE int vm_address_is_data_related(uint64_t address) {
    if (data_seg_addr == 0 || address < data_seg_addr)
        return 0;
    return address - data_seg_addr <= data_seg_size;
}

VM_FORCE_INLINE void vm_fail_closed(void) {
#ifndef VMP_TEST_NO_TRAP
    __builtin_trap();
#endif
}

VM_FORCE_INLINE int vm_set_ip(uint64_t target) {
    if (target >= code_seg_size || target > 0x7fffffffULL) {
        vm_set_fault(VM_FAULT_CODE_RANGE);
        return 0;
    }
    ip = (int)target;
    return 1;
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
uint8_t get_byte_code() {
    if (vm_fault != VM_FAULT_NONE)
        return 0;
    if (code_seg_addr == 0 || ip < 0 ||
        !vm_range_valid((uint64_t)ip, 1, code_seg_size)) {
        vm_set_fault(VM_FAULT_CODE_RANGE);
        return 0;
    }

    uint8_t tmp = ((uint8_t *)code_seg_addr)[ip++];
    tmp ^= (uint8_t)(xorshift32(&vm_code_state) & 0xFFU);
    return tmp;
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
uint32_t get_xorshift_seed() {
    uint32_t res = 0;
    if (vm_fault != VM_FAULT_NONE)
        return 0;
    if (code_seg_addr == 0 || ip < 0 ||
        !vm_range_valid((uint64_t)ip, 4, code_seg_size)) {
        vm_set_fault(VM_FAULT_CODE_RANGE);
        return 0;
    }

    for (int i = 0; i < 4; ++i)
        res |= (uint32_t)((uint8_t *)code_seg_addr)[ip++] << (8 * i);
    return res;
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
uint64_t unpack_code(int size) {
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

    for (int i = 0; i < size; ++i)
        res |= (uint64_t)get_byte_code() << (8 * i);
    return res;
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
uint64_t unpack_data(uint64_t offset, int size) {
    uint64_t res = 0;
    if (!vm_width_valid(size)) {
        vm_set_fault(VM_FAULT_INVALID_SIZE);
        return 0;
    }
    if (vm_fault != VM_FAULT_NONE)
        return 0;
    if (data_seg_addr == 0 ||
        !vm_range_valid(offset, (uint64_t)size, data_seg_size)) {
        vm_set_fault(VM_FAULT_DATA_RANGE);
        return 0;
    }

    for (int i = 0; i < size; ++i)
        res |= (uint64_t)((uint8_t *)data_seg_addr)[offset + (uint64_t)i]
               << (8 * i);
    return res;
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
void pack_data(uint64_t offset, uint64_t value, int size) {
    if (!vm_width_valid(size)) {
        vm_set_fault(VM_FAULT_INVALID_SIZE);
        return;
    }
    if (vm_fault != VM_FAULT_NONE)
        return;
    if (data_seg_addr == 0 ||
        !vm_range_valid(offset, (uint64_t)size, data_seg_size)) {
        vm_set_fault(VM_FAULT_DATA_RANGE);
        return;
    }

    for (int i = 0; i < size; ++i) {
        ((uint8_t *)data_seg_addr)[offset + (uint64_t)i] =
            (uint8_t)(value & 0xFFU);
        value >>= 8;
    }
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
uint64_t unpack_addr(uint64_t address, int size) {
    uint64_t res = 0;
    if (!vm_width_valid(size)) {
        vm_set_fault(VM_FAULT_INVALID_SIZE);
        return 0;
    }
    if (vm_fault != VM_FAULT_NONE)
        return 0;
    if (address == 0) {
        vm_set_fault(VM_FAULT_NULL_ADDRESS);
        return 0;
    }
    if (vm_address_is_data_related(address))
        return unpack_data(address - data_seg_addr, size);

    const uint8_t *ptr = (const uint8_t *)(uintptr_t)address;
    for (int i = 0; i < size; ++i)
        res |= (uint64_t)ptr[i] << (8 * i);
    return res;
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
void pack_store_addr(uint64_t address, uint64_t value, int size) {
    if (!vm_width_valid(size)) {
        vm_set_fault(VM_FAULT_INVALID_SIZE);
        return;
    }
    if (vm_fault != VM_FAULT_NONE)
        return;
    if (address == 0) {
        vm_set_fault(VM_FAULT_NULL_ADDRESS);
        return;
    }
    if (vm_address_is_data_related(address)) {
        pack_data(address - data_seg_addr, value, size);
        return;
    }

    uint8_t *ptr = (uint8_t *)(uintptr_t)address;
    for (int i = 0; i < size; ++i) {
        ptr[i] = (uint8_t)(value & 0xFFU);
        value >>= 8;
    }
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
// get a var or const directly 
uint64_t get_value_with_size(uint8_t value_size, uint8_t value_type) {

    uint64_t res = 0;
    if (value_type == 0) {
        // is a var

        // get var_offset of data_seg
        uint64_t var_offset = unpack_code(pointer_size);

        // fetch data from data_seg
        res = unpack_data(var_offset, value_size);
    }
    else {
        // const

        // unpack const from code
        res = unpack_code(value_size);
    }

    return res;
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
uint64_t get_value() {

    uint8_t value_size = get_byte_code();
    uint8_t value_type = get_byte_code();

    uint64_t res = 0;
    if (value_type == 0) {
        // is a var

        // get var_offset of data_seg
        uint64_t var_offset = unpack_code(pointer_size);

        // fetch data from data_seg
        res = unpack_data(var_offset, value_size);
    }
    else {
        // const

        // unpack const from code
        res = unpack_code(value_size);
    }

    return res;
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
void alloca_handler() {
    // size and type of pointer is useless
    uint8_t var_size = get_byte_code();
    uint8_t var_type = get_byte_code();

    // get pointer var offset
    uint64_t var_offset = unpack_code(pointer_size);

    // get alloca area offset
    uint64_t area_offset = unpack_code(pointer_size);

    // Store the alloca-area virtual address in the pointer slot.
    if (area_offset >= data_seg_size) {
        vm_set_fault(VM_FAULT_DATA_RANGE);
        return;
    }
    pack_data(var_offset, data_seg_addr + area_offset, var_size);
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
void load_handler() {
    uint8_t var_size = get_byte_code();
    uint8_t var_type = get_byte_code();
    uint64_t var_offset = unpack_code(pointer_size);


    uint8_t ptr_size = get_byte_code();
    uint8_t ptr_type = get_byte_code();
    uint64_t ptr_offset = unpack_code(pointer_size);

    // load virtual address
    uint64_t ptr = unpack_data(ptr_offset, pointer_size);

    // load value from address
    uint64_t load_value = unpack_addr(ptr, var_size);

    // printf("load  ptr: %lx, load_value: %lx, var_size: %lx\n", ptr, load_value, var_size);
    // store value to var
    pack_data(var_offset, load_value, var_size);
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
void store_handler() {
    uint8_t var_size = get_byte_code();
    uint8_t var_type = get_byte_code();
    uint64_t store_value = get_value_with_size(var_size, var_type);

    uint8_t ptr_size = get_byte_code();
    uint8_t ptr_type = get_byte_code();
    uint64_t ptr_offset = unpack_code(pointer_size);

    uint64_t ptr = unpack_data(ptr_offset, pointer_size);

    // printf("store ptr: %lx, store_value: %lx, var_size: %lx\n", ptr, store_value, var_size);
    pack_store_addr(ptr, store_value, var_size);
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
void binaryOperator_handler() {
    // binary op_code
    uint8_t op_code = get_byte_code();

    uint8_t res_size = get_byte_code();
    uint8_t res_type = get_byte_code();
    uint64_t res_offset = unpack_code(pointer_size);

    // get operands
    uint64_t op1_value = get_value();
    uint64_t op2_value = get_value();
    if (vm_fault != VM_FAULT_NONE)
        return;

    uint64_t res_value = 0;

    switch (op_code)
    {
        case BINOP_ADD:
            res_value = op1_value + op2_value;
            break;
        case BINOP_FADD: {
            if (res_size <= 4) {
                float f1 = *(float*)&op1_value;
                float f2 = *(float*)&op2_value;
                float fr = f1 + f2;
                res_value = (uint64_t)*(uint32_t*)&fr;
            } else {
                double d1 = *(double*)&op1_value;
                double d2 = *(double*)&op2_value;
                double dr = d1 + d2;
                res_value = *(uint64_t*)&dr;
            }
            break;
        }
        case BINOP_SUB:
            res_value = op1_value - op2_value;
            break;
        case BINOP_FSUB: {
            if (res_size <= 4) {
                float f1 = *(float*)&op1_value;
                float f2 = *(float*)&op2_value;
                float fr = f1 - f2;
                res_value = (uint64_t)*(uint32_t*)&fr;
            } else {
                double d1 = *(double*)&op1_value;
                double d2 = *(double*)&op2_value;
                double dr = d1 - d2;
                res_value = *(uint64_t*)&dr;
            }
            break;
        }
        case BINOP_MUL:
            res_value = op1_value * op2_value;
            break;
        case BINOP_FMUL: {
            if (res_size <= 4) {
                float f1 = *(float*)&op1_value;
                float f2 = *(float*)&op2_value;
                float fr = f1 * f2;
                res_value = (uint64_t)*(uint32_t*)&fr;
            } else {
                double d1 = *(double*)&op1_value;
                double d2 = *(double*)&op2_value;
                double dr = d1 * d2;
                res_value = *(uint64_t*)&dr;
            }
            break;
        }
        case BINOP_UDIV:
            if (op2_value == 0)
                vm_set_fault(VM_FAULT_ARITHMETIC);
            else
                res_value = op1_value / op2_value;
            break;
        case BINOP_SDIV:
            vm_set_fault(VM_FAULT_INVALID_OPCODE);
            break;
        case BINOP_FDIV: {
            if (res_size <= 4) {
                float f1 = *(float*)&op1_value;
                float f2 = *(float*)&op2_value;
                float fr = f1 / f2;
                res_value = (uint64_t)*(uint32_t*)&fr;
            } else {
                double d1 = *(double*)&op1_value;
                double d2 = *(double*)&op2_value;
                double dr = d1 / d2;
                res_value = *(uint64_t*)&dr;
            }
            break;
        }
        case BINOP_UREM:
            if (op2_value == 0)
                vm_set_fault(VM_FAULT_ARITHMETIC);
            else
                res_value = op1_value % op2_value;
            break;
        case BINOP_SREM:
            vm_set_fault(VM_FAULT_INVALID_OPCODE);
            break;
        case BINOP_FREM:
            vm_set_fault(VM_FAULT_INVALID_OPCODE);
            break;
        case BINOP_SHL:
            if (res_size == 0 || op2_value >= (uint64_t)res_size * 8U)
                vm_set_fault(VM_FAULT_ARITHMETIC);
            else
                res_value = op1_value << op2_value;
            break;
        case BINOP_LSHR:
            if (res_size == 0 || op2_value >= (uint64_t)res_size * 8U)
                vm_set_fault(VM_FAULT_ARITHMETIC);
            else
                res_value = op1_value >> op2_value;
            break;
        case BINOP_ASHR:
            vm_set_fault(VM_FAULT_INVALID_OPCODE);
            break;
        case BINOP_AND:
            res_value = op1_value & op2_value;
            break;
        case BINOP_OR:
            res_value = op1_value | op2_value;
            break;
        case BINOP_XOR:
            res_value = op1_value ^ op2_value;
            break;
        
        default:
            vm_set_fault(VM_FAULT_INVALID_OPCODE);
            break;
    }

    // printf("bn op1_value: %lx, op2_value: %lx, res_value: %lx\n", op1_value, op2_value, res_value);
    // store to result var
    pack_data(res_offset, res_value, res_size);

}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
void gep_handler() {
    // get gep size and type
    uint8_t gep_size = get_byte_code();
    uint8_t gep_type = get_byte_code();

    // get return value
    uint8_t res_size = get_byte_code();
    uint8_t res_type = get_byte_code();
    uint64_t res_offset = unpack_code(pointer_size);

    uint64_t ptr_value = get_value();

    uint64_t idx_value = get_value();
    if (vm_fault != VM_FAULT_NONE)
        return;

    uint64_t res_value = 0;

    if (gep_size != 0 && gep_type != 0) {
        // array type
        res_value = ptr_value + gep_size * idx_value;
    } 
    else {
        // struct type - idx_value是成员偏移量（常量）
        res_value = ptr_value + idx_value;
    }

    pack_data(res_offset, res_value, res_size);
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
void cmp_handler() {
    // get Predicate
    uint8_t predicate = get_byte_code();

    uint8_t res_size = get_byte_code();
    uint8_t res_type = get_byte_code();
    uint64_t res_offset = unpack_code(pointer_size);

    // get operands
    uint64_t op1_value = get_value();
    uint64_t op2_value = get_value();
    if (vm_fault != VM_FAULT_NONE)
        return;

    uint64_t res_value = 0;
    // printf("op1: 0x%lx, op2: 0x%lx\n", op1_value, op2_value);

    switch (predicate)
    {
        case ICMP_EQ:
            res_value = op1_value == op2_value;
            break;
        case ICMP_NE:
            res_value = op1_value != op2_value;
            break;
        case ICMP_UGT:
            res_value = op1_value >  op2_value;
            break;
        case ICMP_UGE:
            res_value = op1_value >= op2_value;
            break;
        case ICMP_ULT:
            res_value = op1_value <  op2_value;
            break;
        case ICMP_ULE:
            res_value = op1_value <= op2_value;
            break;
        case ICMP_SGT:
        case ICMP_SGE:
        case ICMP_SLT:
        case ICMP_SLE:
            vm_set_fault(VM_FAULT_INVALID_OPCODE);
            break;
        default:
            vm_set_fault(VM_FAULT_INVALID_OPCODE);
            break;
    }

    pack_data(res_offset, res_value, res_size);
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
void cast_handler() {
    uint8_t res_size = get_byte_code();
    uint8_t res_type = get_byte_code();
    uint64_t res_offset = unpack_code(pointer_size);

    uint64_t op_value = get_value();

    pack_data(res_offset, op_value, res_size);
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
void br_handler() {
    // get br type
    uint8_t br_type = get_byte_code();

    uint64_t target_addr = 0;

    if (br_type == 0) {
        // uncondition br
        target_addr = unpack_code(pointer_size);
    }
    else {
        // condition
        uint64_t condition_value = get_value();
        uint64_t true_br = unpack_code(pointer_size);
        uint64_t false_br = unpack_code(pointer_size);
        if (vm_fault != VM_FAULT_NONE)
            return;

        if (condition_value) {
            target_addr = true_br;
        } 
        else {
            target_addr = false_br;
        }
    }

    // Set the next instruction pointer only after validating the target.
    (void)vm_set_ip(target_addr);
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
void switch_handler() {
    // unpack condition value (size+type+offset/value)
    uint64_t condition_value = get_value();

    // number of cases (4 bytes)
    uint32_t num_cases = (uint32_t)unpack_code(4);

    // case value size (4 bytes)
    uint32_t case_val_size = (uint32_t)unpack_code(4);

    // default target
    uint64_t default_target = unpack_code(pointer_size);
    if (vm_fault != VM_FAULT_NONE)
        return;
    if (case_val_size == 0 || case_val_size > 8 || pointer_size != 8) {
        vm_set_fault(VM_FAULT_INVALID_SIZE);
        return;
    }

    const uint64_t bytes_per_case =
        (uint64_t)case_val_size + (uint64_t)pointer_size;
    if (ip < 0 || (uint64_t)ip > code_seg_size) {
        vm_set_fault(VM_FAULT_CODE_RANGE);
        return;
    }
    const uint64_t remaining_code = code_seg_size - (uint64_t)ip;
    if ((uint64_t)num_cases > remaining_code / bytes_per_case) {
        vm_set_fault(VM_FAULT_CODE_RANGE);
        return;
    }

    uint64_t matched_target = default_target;

    for (uint32_t i = 0; i < num_cases; i++) {
        // read case value (raw from code, already encrypted)
        uint64_t case_val = unpack_code(case_val_size);

        // read case target
        uint64_t case_target = unpack_code(pointer_size);

        if (condition_value == case_val) {
            matched_target = case_target;
            // consume remaining cases but don't evaluate
            for (uint32_t j = i + 1; j < num_cases; j++) {
                unpack_code(case_val_size);
                unpack_code(pointer_size);
            }
            break;
        }
    }

    (void)vm_set_ip(matched_target);
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
void insertvalue_handler() {
    // 结果值位置
    uint8_t res_size = get_byte_code();
    uint8_t res_type = get_byte_code();
    uint64_t res_offset = unpack_code(pointer_size);
    
    // 聚合操作数的值（地址）
    uint64_t agg_value = get_value();
    
    // 要插入的值
    uint64_t insert_value = get_value();
    
    // 偏移量
    uint64_t offset = get_value();
    
    // 值大小
    uint32_t value_size = (uint32_t)unpack_code(4);
    
    // 复制聚合值到结果位置
    uint64_t dst_addr = data_seg_addr + res_offset;
    uint64_t src_addr = agg_value;
    
    // 先复制整个聚合值
    for (uint32_t i = 0; i < res_size; i++) {
        ((uint8_t *)dst_addr)[i] = ((uint8_t *)src_addr)[i];
    }
    
    // 然后在指定偏移处插入新值
    for (uint32_t i = 0; i < value_size && i < 8; i++) {
        ((uint8_t *)dst_addr)[offset + i] = (uint8_t)(insert_value >> (i * 8));
    }
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
void extractvalue_handler() {
    // 结果值位置
    uint8_t res_size = get_byte_code();
    uint8_t res_type = get_byte_code();
    uint64_t res_offset = unpack_code(pointer_size);
    
    // 聚合操作数的值（地址）
    uint64_t agg_value = get_value();
    
    // 偏移量
    uint64_t offset = get_value();
    
    // 结果类型大小
    uint32_t value_size = (uint32_t)unpack_code(4);
    
    // 从聚合值地址+offset处读取数据，存储到结果位置
    uint64_t src_addr = agg_value + offset;
    uint64_t result_value = 0;
    
    // 读取value_size字节的数据
    for (uint32_t i = 0; i < value_size && i < 8; i++) {
        result_value |= ((uint64_t)((uint8_t *)src_addr)[i]) << (i * 8);
    }
    
    // 存储到结果位置
    pack_data(res_offset, result_value, res_size);
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
void data_seg_clean(int return_value_off) {
    if (return_value_off < 0 ||
        (uint64_t)return_value_off > data_seg_size) {
        vm_set_fault(VM_FAULT_DATA_RANGE);
        return;
    }
    for (uint64_t i = (uint64_t)return_value_off; i < data_seg_size; ++i)
        ((uint8_t *)data_seg_addr)[i] = 0;
}

#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
void return_handler() {
    uint8_t var_size = get_byte_code();
    uint8_t var_type = get_byte_code();
    uint64_t ret_value = get_value_with_size(var_size, var_type);

    if (var_size != 0 || var_type != 0)
        pack_data(0, ret_value, var_size);
    if (vm_fault == VM_FAULT_NONE)
        data_seg_clean((int)var_size);
}

// call_handler is declared extern in the header and replaced at link time


#ifdef IS_INLINE_FUNC
    __inline__ __attribute__((always_inline))
#endif
/* Get Opcode, Opcode encrypt by xorshift32*/
uint8_t get_opcode() {
    uint8_t cnt = 0;
    uint8_t his[OP_TOTAL+1];

    uint8_t curr_byte = get_byte_code();
    unsigned attempts = 0;
    if (vm_fault != VM_FAULT_NONE)
        return 0xFF;

    for (int i = 0; i < OP_TOTAL+1; i++) {
        if (++attempts > 4096U) {
            vm_set_fault(VM_FAULT_INVALID_OPCODE);
            return 0xFF;
        }
        uint8_t tmp =
            (uint8_t)(xorshift32(&opcode_xorshift32_state) & 0xFFU);
        // printf("curr_byte: %d, tmp: %d\n", curr_byte, tmp);
        if (tmp == curr_byte) {
            // find
            return i+1;
        }
        
        // privent xorshift32&0xFF conflict
        uint8_t flag = 1;
        for (int j=0; j < i; j++) {
            if (his[j] == tmp) {
                flag = 0;
            }
        }

        if (flag == 1) {
            his[i] = tmp;
        }
        else {
            i--;
        }
    }

    vm_set_fault(VM_FAULT_INVALID_OPCODE);
    return 0xFF;
}


void vm_interpreter() {
    pointer_size = sizeof(void *);
    vm_fault = VM_FAULT_NONE;
    ip = 0;

    if (pointer_size != 8 || code_seg_addr == 0 || data_seg_addr == 0 ||
        code_seg_size < 8 || data_seg_size == 0) {
        vm_set_fault(VM_FAULT_BAD_STATE);
        vm_fail_closed();
        return;
    }

    uint8_t is_a_new_bb = 1;
    while (vm_fault == VM_FAULT_NONE) {
        if (is_a_new_bb) {
            opcode_xorshift32_state = get_xorshift_seed();
            vm_code_state = get_xorshift_seed();
            is_a_new_bb = 0;
            if (vm_fault != VM_FAULT_NONE)
                break;
        }

        uint8_t opcode = get_opcode();
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
                if (vm_fault == VM_FAULT_NONE)
                    is_a_new_bb = 1;
                break;
            case SWITCH_OP:
                switch_handler();
                if (vm_fault == VM_FAULT_NONE)
                    is_a_new_bb = 1;
                break;
            case INSERTVALUE_OP:
            case EXTRACTVALUE_OP:
                vm_set_fault(VM_FAULT_INVALID_OPCODE);
                break;
            case Ret_OP:
                return_handler();
                if (vm_fault != VM_FAULT_NONE)
                    vm_fail_closed();
                return;
            case Call_OP: {
                uint64_t target_function_id = unpack_code(pointer_size);
                if (vm_fault == VM_FAULT_NONE)
                    call_handler(target_function_id);
                break;
            }
            default:
                vm_set_fault(VM_FAULT_INVALID_OPCODE);
                break;
        }
    }

    if (vm_fault != VM_FAULT_NONE)
        vm_fail_closed();
}

// Main function removed - VM interpreter should be linked, not executed directly
// int main() {
//     char test[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
//     uint32_t len = 10;
//     setbuf(stdout, 0);
//     setbuf(stderr, 0);
//     ((uintptr_t *)gv_data_seg)[0] = (uintptr_t) test;
//     ((uint32_t *)gv_data_seg)[2] = len;
//     data_seg_addr = (uintptr_t) gv_data_seg;
//     code_seg_addr = (uintptr_t) gv_code_seg;
//     vm_interpreter();
//     for(int i=0; i < len; i++) {
//         printf("%d, ", test[i]);
//     }
//     printf("\n");
// }
