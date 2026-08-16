#!/usr/bin/env python3
from pathlib import Path

path = Path("tools/_apply_vmp_runtime_bounds.py")
text = path.read_text(encoding="utf-8")
old = '''opcode = replace_once(
    opcode,
    "    return 0xFF;\\n",
    "    vm_set_fault(VM_FAULT_INVALID_OPCODE);\\n"
    "    return 0xFF;\\n",
    "opcode terminal fault",
)
'''
new = '''terminal_return = "    return 0xFF;\\n"
if not opcode.endswith(terminal_return + "}"):
    raise SystemExit("get_opcode terminal return was not found")
opcode = (
    opcode[: -len(terminal_return + "}")]
    + "    vm_set_fault(VM_FAULT_INVALID_OPCODE);\\n"
    + terminal_return
    + "}"
)
'''
count = text.count(old)
if count != 1:
    raise SystemExit(f"terminal opcode helper block: expected 1, found {count}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
