#ifndef ALLVM_AVMP_INTERPRETER_H
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
