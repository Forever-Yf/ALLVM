#!/usr/bin/env python3
from pathlib import Path
import re


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def regex_once(text: str, pattern: str, replacement: str, label: str) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{label}: expected one regex match, found {count}")
    return updated


def replace_function(text: str, name: str, next_name: str, body: str) -> str:
    pattern = (
        rf"void {re.escape(name)}\(\) \{{.*?\n\}}"
        rf"(?=\n\n#ifdef IS_INLINE_FUNC\n"
        rf"    __inline__ __attribute__\(\(always_inline\)\)\n#endif\n"
        rf"void {re.escape(next_name)}\(\))"
    )
    return regex_once(text, pattern, body, name)


# ---------------------------------------------------------------------------
# aVMPInterpreter.c
# ---------------------------------------------------------------------------
interpreter_path = Path("aVMPInterpreter/aVMPInterpreter.c")
interpreter = interpreter_path.read_text(encoding="utf-8")

interpreter = regex_once(
    interpreter,
    r"#define SEG_SIZE 5000\n\n#define IS_INLINE_FUNC\n\n"
    r"// #define TEST_GOVM_C\n\n"
    r"uint8_t gv_code_seg\[SEG_SIZE\] = \{.*?\n\};\n"
    r"uint8_t gv_data_seg\[SEG_SIZE\] = \{\};",
    "#define IS_INLINE_FUNC",
    "remove fixed interpreter arrays",
)

runtime_helpers = r'''static void vm_set_fault(uint32_t fault_code) {
    if (vm_fault == VM_FAULT_NONE)
        vm_fault = fault_code;
}

static int vm_width_valid(int size) {
    return size >= 0 && size <= 8;
}

static int vm_range_valid(uint64_t offset, uint64_t size, uint64_t limit) {
    return offset <= limit && size <= limit - offset;
}

static int vm_address_is_data_related(uint64_t address) {
    if (data_seg_addr == 0 || address < data_seg_addr)
        return 0;
    return address - data_seg_addr <= data_seg_size;
}

static void vm_fail_closed(void) {
#ifndef VMP_TEST_NO_TRAP
    __builtin_trap();
#endif
}

static int vm_set_ip(uint64_t target) {
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

'''

interpreter = regex_once(
    interpreter,
    r"#ifdef IS_INLINE_FUNC\n"
    r"    __inline__ __attribute__\(\(always_inline\)\)\n"
    r"#endif\nuint8_t get_byte_code\(\) \{.*?"
    r"(?=#ifdef IS_INLINE_FUNC\n"
    r"    __inline__ __attribute__\(\(always_inline\)\)\n"
    r"#endif\n// get a var or const directly)",
    runtime_helpers,
    "replace interpreter byte/data helpers",
)

internal_write_pattern = re.compile(
    r"pack_store_addr\(\s*data_seg_addr\s*\+\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*,"
)
interpreter, internal_write_count = internal_write_pattern.subn(
    r"pack_data(\1,", interpreter
)
if internal_write_count < 5:
    raise SystemExit(
        f"expected at least five internal data writes, found {internal_write_count}"
    )

interpreter = replace_once(
    interpreter,
    "pack_store_addr((uint64_t)data_seg_addr, ret_value, var_size);",
    "pack_data(0, ret_value, var_size);",
    "return value data write",
)

interpreter = replace_once(
    interpreter,
    "    // store area virtual address to var\n"
    "    // set_var(var_offset, pointer_size, data_seg_addr+area_offset);\n"
    "    pack_data(var_offset, data_seg_addr+area_offset, var_size);\n",
    "    // Store the alloca-area virtual address in the pointer slot.\n"
    "    if (area_offset >= data_seg_size) {\n"
    "        vm_set_fault(VM_FAULT_DATA_RANGE);\n"
    "        return;\n"
    "    }\n"
    "    pack_data(var_offset, data_seg_addr + area_offset, var_size);\n",
    "alloca area bound",
)

binary_match = re.search(
    r"void binaryOperator_handler\(\) \{.*?\n\}"
    r"(?=\n\n#ifdef IS_INLINE_FUNC\n"
    r"    __inline__ __attribute__\(\(always_inline\)\)\n#endif\n"
    r"void gep_handler\(\))",
    interpreter,
    flags=re.S,
)
if not binary_match:
    raise SystemExit("binaryOperator_handler not found")
binary = binary_match.group(0)
binary = replace_once(
    binary,
    "    uint64_t op2_value = get_value();\n\n"
    "    uint64_t res_value = 0;\n",
    "    uint64_t op2_value = get_value();\n"
    "    if (vm_fault != VM_FAULT_NONE)\n"
    "        return;\n\n"
    "    uint64_t res_value = 0;\n",
    "binary operand fault check",
)
binary = replace_once(
    binary,
    "        case BINOP_UDIV:\n"
    "            res_value = op1_value / op2_value;\n"
    "            break;\n",
    "        case BINOP_UDIV:\n"
    "            if (op2_value == 0)\n"
    "                vm_set_fault(VM_FAULT_ARITHMETIC);\n"
    "            else\n"
    "                res_value = op1_value / op2_value;\n"
    "            break;\n",
    "unsigned division guard",
)
binary = replace_once(
    binary,
    "        case BINOP_SDIV:\n"
    "            res_value = op1_value / op2_value;\n"
    "            break;\n",
    "        case BINOP_SDIV:\n"
    "            vm_set_fault(VM_FAULT_INVALID_OPCODE);\n"
    "            break;\n",
    "signed division rejection",
)
binary = replace_once(
    binary,
    "        case BINOP_UREM:\n"
    "            res_value = op1_value % op2_value;\n"
    "            break;\n",
    "        case BINOP_UREM:\n"
    "            if (op2_value == 0)\n"
    "                vm_set_fault(VM_FAULT_ARITHMETIC);\n"
    "            else\n"
    "                res_value = op1_value % op2_value;\n"
    "            break;\n",
    "unsigned remainder guard",
)
binary = replace_once(
    binary,
    "        case BINOP_SREM:\n"
    "            res_value = op1_value % op2_value;\n"
    "            break;\n",
    "        case BINOP_SREM:\n"
    "            vm_set_fault(VM_FAULT_INVALID_OPCODE);\n"
    "            break;\n",
    "signed remainder rejection",
)
binary = regex_once(
    binary,
    r"        case BINOP_FREM: \{.*?\n        \}\n",
    "        case BINOP_FREM:\n"
    "            vm_set_fault(VM_FAULT_INVALID_OPCODE);\n"
    "            break;\n",
    "floating remainder rejection",
)
binary = replace_once(
    binary,
    "        case BINOP_SHL:\n"
    "            res_value = op1_value << op2_value;\n"
    "            break;\n"
    "        case BINOP_LSHR:\n"
    "            res_value = op1_value >> op2_value;\n"
    "            break;\n"
    "        case BINOP_ASHR:\n"
    "            res_value = op1_value >> op2_value;\n"
    "            break;\n",
    "        case BINOP_SHL:\n"
    "            if (res_size == 0 || op2_value >= (uint64_t)res_size * 8U)\n"
    "                vm_set_fault(VM_FAULT_ARITHMETIC);\n"
    "            else\n"
    "                res_value = op1_value << op2_value;\n"
    "            break;\n"
    "        case BINOP_LSHR:\n"
    "            if (res_size == 0 || op2_value >= (uint64_t)res_size * 8U)\n"
    "                vm_set_fault(VM_FAULT_ARITHMETIC);\n"
    "            else\n"
    "                res_value = op1_value >> op2_value;\n"
    "            break;\n"
    "        case BINOP_ASHR:\n"
    "            vm_set_fault(VM_FAULT_INVALID_OPCODE);\n"
    "            break;\n",
    "shift guards",
)
binary = replace_once(
    binary,
    "        default:\n"
    "            break;\n",
    "        default:\n"
    "            vm_set_fault(VM_FAULT_INVALID_OPCODE);\n"
    "            break;\n",
    "binary default fault",
)
interpreter = (
    interpreter[: binary_match.start()] + binary + interpreter[binary_match.end() :]
)

cmp_match = re.search(
    r"void cmp_handler\(\) \{.*?\n\}"
    r"(?=\n\n#ifdef IS_INLINE_FUNC\n"
    r"    __inline__ __attribute__\(\(always_inline\)\)\n#endif\n"
    r"void cast_handler\(\))",
    interpreter,
    flags=re.S,
)
if not cmp_match:
    raise SystemExit("cmp_handler not found")
cmp_body = cmp_match.group(0)
cmp_body = replace_once(
    cmp_body,
    "    uint64_t op2_value = get_value();\n\n"
    "    uint64_t res_value = 0;\n",
    "    uint64_t op2_value = get_value();\n"
    "    if (vm_fault != VM_FAULT_NONE)\n"
    "        return;\n\n"
    "    uint64_t res_value = 0;\n",
    "cmp operand fault check",
)
cmp_body = regex_once(
    cmp_body,
    r"        case ICMP_SGT:.*?        case ICMP_SLE:\n"
    r"            res_value = op1_value <= op2_value;\n"
    r"            break;\n",
    "        case ICMP_SGT:\n"
    "        case ICMP_SGE:\n"
    "        case ICMP_SLT:\n"
    "        case ICMP_SLE:\n"
    "            vm_set_fault(VM_FAULT_INVALID_OPCODE);\n"
    "            break;\n",
    "signed compare rejection",
)
cmp_body = replace_once(
    cmp_body,
    "        default:\n"
    "            break;\n",
    "        default:\n"
    "            vm_set_fault(VM_FAULT_INVALID_OPCODE);\n"
    "            break;\n",
    "cmp default fault",
)
interpreter = (
    interpreter[: cmp_match.start()] + cmp_body + interpreter[cmp_match.end() :]
)

interpreter = replace_once(
    interpreter,
    "    // set ip\n"
    "    ip = target_addr;\n",
    "    // Set the next instruction pointer only after validating the target.\n"
    "    (void)vm_set_ip(target_addr);\n",
    "branch target validation",
)
interpreter = replace_once(
    interpreter,
    "    ip = matched_target;\n",
    "    (void)vm_set_ip(matched_target);\n",
    "switch target validation",
)

interpreter = regex_once(
    interpreter,
    r"void data_seg_clean\(int return_value_off\) \{.*?\n\}",
    "void data_seg_clean(int return_value_off) {\n"
    "    if (return_value_off < 0 ||\n"
    "        (uint64_t)return_value_off > data_seg_size) {\n"
    "        vm_set_fault(VM_FAULT_DATA_RANGE);\n"
    "        return;\n"
    "    }\n"
    "    for (uint64_t i = (uint64_t)return_value_off; i < data_seg_size; ++i)\n"
    "        ((uint8_t *)data_seg_addr)[i] = 0;\n"
    "}",
    "dynamic data segment cleanup",
)

opcode_match = re.search(
    r"uint8_t get_opcode\(\) \{.*?\n\}"
    r"(?=\n\n\nvoid vm_interpreter\(\))",
    interpreter,
    flags=re.S,
)
if not opcode_match:
    raise SystemExit("get_opcode not found")
opcode = opcode_match.group(0)
opcode = replace_once(
    opcode,
    "    uint8_t curr_byte = get_byte_code();\n\n"
    "    for (int i = 0; i < OP_TOTAL+1; i++) {\n"
    "        uint8_t tmp = xorshift32(&opcode_xorshift32_state);\n",
    "    uint8_t curr_byte = get_byte_code();\n"
    "    unsigned attempts = 0;\n"
    "    if (vm_fault != VM_FAULT_NONE)\n"
    "        return 0xFF;\n\n"
    "    for (int i = 0; i < OP_TOTAL+1; i++) {\n"
    "        if (++attempts > 4096U) {\n"
    "            vm_set_fault(VM_FAULT_INVALID_OPCODE);\n"
    "            return 0xFF;\n"
    "        }\n"
    "        uint8_t tmp =\n"
    "            (uint8_t)(xorshift32(&opcode_xorshift32_state) & 0xFFU);\n",
    "opcode attempt bound",
)
opcode = replace_once(
    opcode,
    "    return 0xFF;\n",
    "    vm_set_fault(VM_FAULT_INVALID_OPCODE);\n"
    "    return 0xFF;\n",
    "opcode terminal fault",
)
interpreter = (
    interpreter[: opcode_match.start()] + opcode + interpreter[opcode_match.end() :]
)

new_vm_interpreter = r'''void vm_interpreter() {
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
'''
interpreter = regex_once(
    interpreter,
    r"void vm_interpreter\(\) \{.*?\n\}"
    r"(?=\n\n// Main function removed)",
    new_vm_interpreter.rstrip(),
    "replace fail-closed interpreter loop",
)

if "SEG_SIZE" in interpreter:
    raise SystemExit("fixed SEG_SIZE remains in interpreter source")
if "pack_store_addr(data_seg_addr" in interpreter:
    raise SystemExit("unchecked internal data write remains")
interpreter_path.write_text(interpreter, encoding="utf-8")


# ---------------------------------------------------------------------------
# VMPCompatibility.cpp: current embedded interpreter ABI is 64-bit only.
# ---------------------------------------------------------------------------
compatibility_path = Path("llvm/lib/Transforms/Obfuscation/VMPCompatibility.cpp")
compatibility = compatibility_path.read_text(encoding="utf-8")
compatibility = replace_once(
    compatibility,
    "  if (PointerSize == 0 || PointerSize > 8)\n"
    "    reject(Result, \"目标指针宽度不适用于 uint64 VMP ABI\");\n",
    "  if (PointerSize != 8)\n"
    "    reject(Result,\n"
    "           \"当前嵌入解释器的 uintptr_t ABI 仅支持 64 位目标\");\n",
    "64-bit interpreter ABI",
)
compatibility_path.write_text(compatibility, encoding="utf-8")


# ---------------------------------------------------------------------------
# aVMP.cpp: expose actual sizes and map runtime metadata globals.
# ---------------------------------------------------------------------------
avmp_path = Path("llvm/lib/Transforms/Obfuscation/aVMP.cpp")
avmp = avmp_path.read_text(encoding="utf-8")

avmp = replace_once(
    avmp,
    "        StringRef getTranslationError() const {\n"
    "            return TranslationError;\n"
    "        }\n\n",
    "        StringRef getTranslationError() const {\n"
    "            return TranslationError;\n"
    "        }\n\n"
    "        uint64_t getCodeSegmentSize() const {\n"
    "            return static_cast<uint64_t>(vm_code.size());\n"
    "        }\n\n"
    "        uint64_t getDataSegmentSize() const {\n"
    "            return curr_data_offset < 0\n"
    "                       ? 0\n"
    "                       : static_cast<uint64_t>(curr_data_offset);\n"
    "        }\n\n",
    "translator segment size getters",
)

avmp = replace_once(
    avmp,
    "        GOVMInterpreter(Function * F, Function * callinst_handler) {\n"
    "            this->Mod = F->getParent();\n"
    "            this->F = F;\n"
    "            this->modDataLayout = const_cast<DataLayout *>(&this->Mod->getDataLayout());\n"
    "            this->callinst_handler = callinst_handler;\n\n"
    "            construct_gv();\n"
    "        }\n",
    "        GOVMInterpreter(Function *F, Function *callinst_handler,\n"
    "                        uint64_t CodeSegmentSize,\n"
    "                        uint64_t DataSegmentSize) {\n"
    "            this->Mod = F->getParent();\n"
    "            this->F = F;\n"
    "            this->modDataLayout =\n"
    "                const_cast<DataLayout *>(&this->Mod->getDataLayout());\n"
    "            this->callinst_handler = callinst_handler;\n"
    "            this->CodeSegmentSize = CodeSegmentSize;\n"
    "            this->DataSegmentSize = DataSegmentSize;\n\n"
    "            construct_gv();\n"
    "        }\n",
    "interpreter constructor sizes",
)

avmp = replace_once(
    avmp,
    "        Function *callinst_handler;\n\n"
    "        GlobalVariable *pointer_size_gv;\n"
    "        GlobalVariable *opcode_xorshift32_state;\n"
    "        GlobalVariable *vm_code_state;\n",
    "        Function *callinst_handler;\n"
    "        uint64_t CodeSegmentSize = 0;\n"
    "        uint64_t DataSegmentSize = 0;\n\n"
    "        GlobalVariable *pointer_size_gv;\n"
    "        GlobalVariable *opcode_xorshift32_state;\n"
    "        GlobalVariable *vm_code_state;\n"
    "        GlobalVariable *code_seg_size_gv;\n"
    "        GlobalVariable *data_seg_size_gv;\n"
    "        GlobalVariable *vm_fault_gv;\n",
    "interpreter metadata fields",
)

avmp = replace_once(
    avmp,
    "    vm_code_state = new GlobalVariable(*Mod, Type::getInt32Ty(Mod->getContext()), \n"
    "                false,  GlobalValue::InternalLinkage, \n"
    "                vm_code_state_initGV, \"vm_code_state_\"+F->getName());\n"
    "    vm_code_state->setThreadLocal(true);\n"
    "}\n",
    "    vm_code_state = new GlobalVariable(*Mod, Type::getInt32Ty(Mod->getContext()), \n"
    "                false,  GlobalValue::InternalLinkage, \n"
    "                vm_code_state_initGV, \"vm_code_state_\"+F->getName());\n"
    "    vm_code_state->setThreadLocal(true);\n\n"
    "    Constant *code_size_init = ConstantInt::get(\n"
    "        Type::getInt64Ty(Mod->getContext()), CodeSegmentSize);\n"
    "    code_seg_size_gv = new GlobalVariable(\n"
    "        *Mod, Type::getInt64Ty(Mod->getContext()), true,\n"
    "        GlobalValue::InternalLinkage, code_size_init,\n"
    "        \"code_seg_size_\" + F->getName());\n\n"
    "    Constant *data_size_init = ConstantInt::get(\n"
    "        Type::getInt64Ty(Mod->getContext()), DataSegmentSize);\n"
    "    data_seg_size_gv = new GlobalVariable(\n"
    "        *Mod, Type::getInt64Ty(Mod->getContext()), true,\n"
    "        GlobalValue::InternalLinkage, data_size_init,\n"
    "        \"data_seg_size_\" + F->getName());\n\n"
    "    Constant *fault_init = ConstantInt::get(\n"
    "        Type::getInt32Ty(Mod->getContext()), 0);\n"
    "    vm_fault_gv = new GlobalVariable(\n"
    "        *Mod, Type::getInt32Ty(Mod->getContext()), false,\n"
    "        GlobalValue::InternalLinkage, fault_init,\n"
    "        \"vm_fault_\" + F->getName());\n"
    "    vm_fault_gv->setThreadLocal(true);\n"
    "}\n",
    "interpreter runtime metadata globals",
)

avmp = replace_once(
    avmp,
    "    std::vector<std::string> gv_list = {\"ip\",  \"data_seg_addr\", \"code_seg_addr\", \"pointer_size\", \"opcode_xorshift32_state\", \"vm_code_state\"};\n"
    "    std::vector<GlobalVariable *> new_gv_list = {ip,  data_seg_addr, code_seg_addr, pointer_size_gv, opcode_xorshift32_state, vm_code_state};\n",
    "    std::vector<std::string> gv_list = {\n"
    "        \"ip\", \"data_seg_addr\", \"code_seg_addr\", \"pointer_size\",\n"
    "        \"opcode_xorshift32_state\", \"vm_code_state\",\n"
    "        \"code_seg_size\", \"data_seg_size\", \"vm_fault\"};\n"
    "    std::vector<GlobalVariable *> new_gv_list = {\n"
    "        ip, data_seg_addr, code_seg_addr, pointer_size_gv,\n"
    "        opcode_xorshift32_state, vm_code_state, code_seg_size_gv,\n"
    "        data_seg_size_gv, vm_fault_gv};\n",
    "interpreter global replacement list",
)

avmp = replace_once(
    avmp,
    "        eraseUnusedGlobal(Interpreter->pointer_size_gv);\n"
    "        eraseUnusedGlobal(Interpreter->opcode_xorshift32_state);\n"
    "        eraseUnusedGlobal(Interpreter->vm_code_state);\n",
    "        eraseUnusedGlobal(Interpreter->pointer_size_gv);\n"
    "        eraseUnusedGlobal(Interpreter->opcode_xorshift32_state);\n"
    "        eraseUnusedGlobal(Interpreter->vm_code_state);\n"
    "        eraseUnusedGlobal(Interpreter->code_seg_size_gv);\n"
    "        eraseUnusedGlobal(Interpreter->data_seg_size_gv);\n"
    "        eraseUnusedGlobal(Interpreter->vm_fault_gv);\n",
    "failed interpreter metadata cleanup",
)

avmp = replace_once(
    avmp,
    "    GOVMInterpreter Interpreter(&F, Translator.get_callinst_handler());\n",
    "    GOVMInterpreter Interpreter(\n"
    "        &F, Translator.get_callinst_handler(),\n"
    "        Translator.getCodeSegmentSize(), Translator.getDataSegmentSize());\n",
    "interpreter construction with sizes",
)

avmp_path.write_text(avmp, encoding="utf-8")
