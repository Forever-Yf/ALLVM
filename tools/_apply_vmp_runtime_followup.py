#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


path = Path("aVMPInterpreter/aVMPInterpreter.c")
text = path.read_text(encoding="utf-8")

text = replace_once(
    text,
    "#define IS_INLINE_FUNC\n\n//\n",
    "#define IS_INLINE_FUNC\n\n"
    "#ifdef IS_INLINE_FUNC\n"
    "#define VM_FORCE_INLINE static __inline__ __attribute__((always_inline))\n"
    "#else\n"
    "#define VM_FORCE_INLINE static\n"
    "#endif\n\n"
    "//\n",
    "force-inline macro",
)

for signature in (
    "static void vm_set_fault(uint32_t fault_code)",
    "static int vm_width_valid(int size)",
    "static int vm_range_valid(uint64_t offset, uint64_t size, uint64_t limit)",
    "static int vm_address_is_data_related(uint64_t address)",
    "static void vm_fail_closed(void)",
    "static int vm_set_ip(uint64_t target)",
):
    replacement = signature.replace("static ", "VM_FORCE_INLINE ", 1)
    text = replace_once(text, signature, replacement, signature)

text = replace_once(
    text,
    "    uint64_t ptr_value = get_value();\n\n"
    "    uint64_t idx_value = get_value();\n\n"
    "    uint64_t res_value = 0;\n",
    "    uint64_t ptr_value = get_value();\n\n"
    "    uint64_t idx_value = get_value();\n"
    "    if (vm_fault != VM_FAULT_NONE)\n"
    "        return;\n\n"
    "    uint64_t res_value = 0;\n",
    "GEP operand fault check",
)

text = replace_once(
    text,
    "        uint64_t condition_value = get_value();\n"
    "        uint64_t true_br = unpack_code(pointer_size);\n"
    "        uint64_t false_br = unpack_code(pointer_size);\n\n"
    "        if (condition_value) {\n",
    "        uint64_t condition_value = get_value();\n"
    "        uint64_t true_br = unpack_code(pointer_size);\n"
    "        uint64_t false_br = unpack_code(pointer_size);\n"
    "        if (vm_fault != VM_FAULT_NONE)\n"
    "            return;\n\n"
    "        if (condition_value) {\n",
    "branch operand fault check",
)

switch_anchor = (
    "    // default target\n"
    "    uint64_t default_target = unpack_code(pointer_size);\n\n"
    "    uint64_t matched_target = default_target;\n\n"
    "    for (uint32_t i = 0; i < num_cases; i++) {\n"
)
switch_replacement = (
    "    // default target\n"
    "    uint64_t default_target = unpack_code(pointer_size);\n"
    "    if (vm_fault != VM_FAULT_NONE)\n"
    "        return;\n"
    "    if (case_val_size == 0 || case_val_size > 8 || pointer_size != 8) {\n"
    "        vm_set_fault(VM_FAULT_INVALID_SIZE);\n"
    "        return;\n"
    "    }\n\n"
    "    const uint64_t bytes_per_case =\n"
    "        (uint64_t)case_val_size + (uint64_t)pointer_size;\n"
    "    if (ip < 0 || (uint64_t)ip > code_seg_size) {\n"
    "        vm_set_fault(VM_FAULT_CODE_RANGE);\n"
    "        return;\n"
    "    }\n"
    "    const uint64_t remaining_code = code_seg_size - (uint64_t)ip;\n"
    "    if ((uint64_t)num_cases > remaining_code / bytes_per_case) {\n"
    "        vm_set_fault(VM_FAULT_CODE_RANGE);\n"
    "        return;\n"
    "    }\n\n"
    "    uint64_t matched_target = default_target;\n\n"
    "    for (uint32_t i = 0; i < num_cases; i++) {\n"
)
text = replace_once(
    text, switch_anchor, switch_replacement, "switch case byte budget"
)

text = replace_once(
    text,
    "    if (var_size != 0 || var_type != 0) {\n"
    "        pack_data(0, ret_value, var_size);\n"
    "    }\n"
    "    // we dont know data_seg size, may segmentfault\n"
    "    // data_seg_clean(var_size);\n"
    "    // for (unsigned i=var_size; i<SEG_SIZE; i++) {\n"
    "    //     ((uint8_t *)data_seg_addr)[i] = 0;\n"
    "    // }\n",
    "    if (var_size != 0 || var_type != 0)\n"
    "        pack_data(0, ret_value, var_size);\n"
    "    if (vm_fault == VM_FAULT_NONE)\n"
    "        data_seg_clean((int)var_size);\n",
    "return-time data clearing",
)

path.write_text(text, encoding="utf-8")
