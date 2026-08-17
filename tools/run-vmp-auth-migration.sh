#!/usr/bin/env bash
set -euo pipefail

python3 -m py_compile tools/apply-vmp-auth-budgets.py
python3 tools/apply-vmp-auth-budgets.py

# The first block-local boundary test must keep a second authenticated block in
# the total code segment. Otherwise the same read crosses both the block and the
# complete code segment and legitimately reports the broader CODE_RANGE fault.
python3 - <<'PY'
from pathlib import Path

path = Path("tools/vmp-interpreter-bounds-smoke.c")
text = path.read_text(encoding="utf-8")
start = text.index("static int test_block_local_boundary(void) {")
end = text.index("\n\nstatic int test_valid_data_access", start)
replacement = r'''static int test_block_local_boundary(void) {
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
'''
path.write_text(text[:start] + replacement + text[end:], encoding="utf-8")
PY

LLVM_CONFIG="$(find /usr/lib -path '*/bin/llvm-config' -type f 2>/dev/null | sort -V | tail -n 1)"
if [[ -z "$LLVM_CONFIG" ]]; then
  LLVM_CONFIG="$(command -v llvm-config || true)"
fi
if [[ -z "$LLVM_CONFIG" ]]; then
  echo "No installed llvm-config was found" >&2
  exit 1
fi
LLVM_BINDIR="$($LLVM_CONFIG --bindir)"
"$LLVM_CONFIG" --version

CC="$LLVM_BINDIR/clang"
if [[ ! -x "$CC" ]]; then CC="$(command -v clang || command -v cc)"; fi
"$CC" \
  -std=c11 \
  -Wall -Wextra -Werror \
  -Wno-unused-function \
  -Wno-unused-variable \
  -Wno-unused-parameter \
  -Wno-strict-aliasing \
  tools/vmp-interpreter-bounds-smoke.c \
  -o /tmp/vmp-interpreter-bounds-smoke
set +e
/tmp/vmp-interpreter-bounds-smoke
native_status=$?
set -e
if [[ $native_status -ne 0 ]]; then
  echo "Authenticated VMP native regression exited with $native_status" >&2
  exit "$native_status"
fi

"$CC" \
  -O2 -emit-llvm -c \
  -target x86_64-pc-windows-msvc \
  aVMPInterpreter/aVMPInterpreter.c \
  -o aVMPInterpreter/aVMPInterpreter.bc

python3 - <<'PY'
from pathlib import Path

bitcode = Path("aVMPInterpreter/aVMPInterpreter.bc").read_bytes()
lines = [
    "#ifndef ALLVM_EMBEDDED_VMP_IR_H",
    "#define ALLVM_EMBEDDED_VMP_IR_H",
    "",
    "#include <vector>",
    "",
    f"static const int binary_ir_length = {len(bitcode)};",
    "static const char binary_ir_data[] =",
]
for offset in range(0, len(bitcode), 16):
    chunk = bitcode[offset:offset + 16]
    lines.append('"' + ''.join(f"\\x{byte:02x}" for byte in chunk) + '"')
lines.extend([
    ";",
    "",
    "static std::vector<char> get_binary_ir() {",
    "    return std::vector<char>(binary_ir_data, binary_ir_data + binary_ir_length);",
    "}",
    "",
    "#endif // ALLVM_EMBEDDED_VMP_IR_H",
    "",
])
Path("llvm/include/llvm/Transforms/Obfuscation/vm.h").write_text(
    "\n".join(lines), encoding="utf-8"
)
PY
python3 tools/check-vmp-embed.py

LLVM_DIS="$LLVM_BINDIR/llvm-dis"
if [[ ! -x "$LLVM_DIS" ]]; then LLVM_DIS="$(command -v llvm-dis)"; fi
"$LLVM_DIS" aVMPInterpreter/aVMPInterpreter.bc -o /tmp/aVMPInterpreter.ll
for symbol in \
  code_seg_size data_seg_size vm_fault \
  vm_integrity_key0 vm_integrity_key1 vm_block_end \
  vm_step_limit vm_call_limit vm_call_depth_limit \
  vm_steps_remaining vm_calls_remaining vm_call_depth vm_frame_active; do
  grep -q "@$symbol" /tmp/aVMPInterpreter.ll
done
grep -q 'llvm.trap' /tmp/aVMPInterpreter.ll
awk '/define .*@vm_interpreter\(/,/^}/' \
  /tmp/aVMPInterpreter.ll > /tmp/vm_interpreter.ll
! grep -E 'call .*@(get_byte_code|get_xorshift_seed|unpack_code|unpack_data|pack_data|vm_set_fault|vm_range_valid|vm_set_ip|vm_fail_closed|vm_enter_block|vm_consume_budget|vmp_integrity_)' \
  /tmp/vm_interpreter.ll

mkdir -p /tmp/allvm-include/llvm/Transforms /tmp/allvm-include/llvm
cp -R llvm/include/llvm/Transforms/Obfuscation \
  /tmp/allvm-include/llvm/Transforms/
cp llvm/include/llvm/CryptoUtils.h /tmp/allvm-include/llvm/CryptoUtils.h

CXX="$LLVM_BINDIR/clang++"
if [[ ! -x "$CXX" ]]; then CXX="$(command -v clang++ || command -v c++)"; fi
read -r -a LLVM_CXXFLAGS <<< "$($LLVM_CONFIG --cxxflags)"
"$CXX" \
  -I/tmp/allvm-include \
  "${LLVM_CXXFLAGS[@]}" \
  -std=c++17 \
  -Wall -Wextra \
  -Wno-unused-parameter \
  -fsyntax-only \
  llvm/lib/Transforms/Obfuscation/VMPCompatibility.cpp
"$CXX" \
  -I/tmp/allvm-include \
  "${LLVM_CXXFLAGS[@]}" \
  -std=c++17 \
  -Wno-unused-function \
  -Wno-unused-variable \
  -Wno-unused-but-set-variable \
  -Wno-sign-compare \
  -Wno-deprecated-declarations \
  -fsyntax-only \
  llvm/lib/Transforms/Obfuscation/aVMP.cpp

read -r -a LLVM_LDFLAGS <<< "$($LLVM_CONFIG --ldflags)"
read -r -a LLVM_LIBS <<< "$($LLVM_CONFIG --libs core asmparser support)"
read -r -a LLVM_SYSTEM_LIBS <<< "$($LLVM_CONFIG --system-libs)"
"$CXX" \
  -I/tmp/allvm-include \
  "${LLVM_CXXFLAGS[@]}" \
  -std=c++17 \
  -Wall -Wextra \
  -Wno-unused-parameter \
  llvm/lib/Transforms/Obfuscation/VMPCompatibility.cpp \
  tools/vmp-compatibility-smoke.cpp \
  "${LLVM_LDFLAGS[@]}" \
  "${LLVM_LIBS[@]}" \
  "${LLVM_SYSTEM_LIBS[@]}" \
  -o /tmp/vmp-compatibility-smoke
/tmp/vmp-compatibility-smoke

python3 -m py_compile \
  tools/allvm-doctor.py \
  tools/check-hardening.py \
  tools/check-vmp-embed.py
python3 tools/check-hardening.py --compile-header
python3 tools/check-hardening.py --json > /tmp/hardening-report.json
cat /tmp/hardening-report.json

git rm .github/workflows/apply-vmp-auth-budgets.yml
git rm .github/workflows/apply-vmp-auth-budgets-v2.yml
git rm tools/apply-vmp-auth-budgets.py
git rm tools/run-vmp-auth-migration.sh
for stale in \
  llvm/include/llvm/Transforms/Obfuscation/vm.h.bak \
  llvm/include/llvm/Transforms/Obfuscation/vm.h.backup \
  llvm/include/llvm/Transforms/Obfuscation/xVMP.h.bak; do
  if git ls-files --error-unmatch "$stale" >/dev/null 2>&1; then
    git rm "$stale"
  fi
done

git add \
  .github/workflows/hardening-smoke.yml \
  README.md \
  docs/ALLVM_HARDENING.md \
  aVMPInterpreter/VMPIntegrity.h \
  aVMPInterpreter/aVMPInterpreter.c \
  aVMPInterpreter/aVMPInterpreter.h \
  aVMPInterpreter/aVMPInterpreter.bc \
  llvm/include/llvm/Transforms/Obfuscation/vm.h \
  llvm/lib/Transforms/Obfuscation/VMPCompatibility.cpp \
  llvm/lib/Transforms/Obfuscation/aVMP.cpp \
  tools/check-hardening.py \
  tools/vmp-interpreter-bounds-smoke.c

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git commit -m "add authenticated VMP blocks and runtime budgets"
git push origin HEAD:hardening/p0-secure-seeding-doctor
