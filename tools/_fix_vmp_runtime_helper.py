#!/usr/bin/env python3
from pathlib import Path

path = Path("tools/_apply_vmp_runtime_bounds.py")
text = path.read_text(encoding="utf-8")

old_terminal = '''opcode = replace_once(
    opcode,
    "    return 0xFF;\\n",
    "    vm_set_fault(VM_FAULT_INVALID_OPCODE);\\n"
    "    return 0xFF;\\n",
    "opcode terminal fault",
)
'''
new_terminal = '''terminal_return = "    return 0xFF;\\n"
if not opcode.endswith(terminal_return + "}"):
    raise SystemExit("get_opcode terminal return was not found")
opcode = (
    opcode[: -len(terminal_return + "}")]
    + "    vm_set_fault(VM_FAULT_INVALID_OPCODE);\\n"
    + terminal_return
    + "}"
)
'''
if text.count(old_terminal) != 1:
    raise SystemExit("terminal opcode helper block is not unique")
text = text.replace(old_terminal, new_terminal, 1)

old_guard = '''if "SEG_SIZE" in interpreter:
    raise SystemExit("fixed SEG_SIZE remains in interpreter source")
'''
new_guard = '''if "#define SEG_SIZE" in interpreter:
    raise SystemExit("fixed SEG_SIZE macro remains in interpreter source")
'''
if text.count(old_guard) != 1:
    raise SystemExit("fixed-size helper guard is not unique")
text = text.replace(old_guard, new_guard, 1)

path.write_text(text, encoding="utf-8")
