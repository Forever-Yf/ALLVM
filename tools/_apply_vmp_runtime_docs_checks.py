#!/usr/bin/env python3
from pathlib import Path
import re


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


# ---------------------------------------------------------------------------
# Static regression checker
# ---------------------------------------------------------------------------
checker_path = Path("tools/check-hardening.py")
checker = checker_path.read_text(encoding="utf-8")
checker = replace_once(
    checker,
    '    vmp_smoke = read("tools/vmp-compatibility-smoke.cpp")\n'
    '    build_helper = read("build.cpp")\n',
    '    vmp_smoke = read("tools/vmp-compatibility-smoke.cpp")\n'
    '    interpreter_header = read("aVMPInterpreter/aVMPInterpreter.h")\n'
    '    interpreter_source = read("aVMPInterpreter/aVMPInterpreter.c")\n'
    '    interpreter_smoke = read("tools/vmp-interpreter-bounds-smoke.c")\n'
    '    embed_checker = read("tools/check-vmp-embed.py")\n'
    '    embedded_header = read("llvm/include/llvm/Transforms/Obfuscation/vm.h")\n'
    '    build_helper = read("build.cpp")\n',
    "checker runtime inputs",
)

runtime_checks = r'''
    interpreter_header_markers = (
        "ALLVM_AVMP_INTERPRETER_H",
        "VM_FAULT_CODE_RANGE",
        "VM_FAULT_DATA_RANGE",
        "VM_FAULT_INVALID_OPCODE",
        "VM_FAULT_BAD_STATE",
        "extern uint64_t code_seg_size",
        "extern uint64_t data_seg_size",
        "extern uint32_t vm_fault",
    )
    ok, missing = contains_all(interpreter_header, interpreter_header_markers)
    add(
        results,
        "VMP 运行时故障 ABI",
        ok,
        "段长度、首故障状态和 include guard 已定义"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    interpreter_source_markers = (
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
    ok, missing = contains_all(interpreter_source, interpreter_source_markers)
    add(
        results,
        "VMP 解释器段边界",
        ok,
        "代码/数据边界、跳转、switch 预算和 fail-closed 路径存在"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    unsafe_interpreter_markers = [
        marker
        for marker in ("#define SEG_SIZE", "pack_store_addr(data_seg_addr")
        if marker in interpreter_source
    ]
    add(
        results,
        "VMP 解释器固定段回归",
        not unsafe_interpreter_markers,
        "未发现固定 5000 字节段或绕过内部数据边界的写入"
        if not unsafe_interpreter_markers
        else "仍存在: " + ", ".join(unsafe_interpreter_markers),
    )

    runtime_mapping_markers = (
        "getCodeSegmentSize",
        "getDataSegmentSize",
        "code_seg_size_gv",
        "data_seg_size_gv",
        "vm_fault_gv",
        '"code_seg_size", "data_seg_size", "vm_fault"',
        "vm_fault_gv->setThreadLocal(true)",
    )
    ok, missing = contains_all(avmp, runtime_mapping_markers)
    add(
        results,
        "VMP 运行时元数据接入",
        ok,
        "实际段长度和 TLS fault 已映射到嵌入解释器"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    abi_64_ok = "仅支持 64 位目标" in vmp_preflight and "PointerSize != 8" in vmp_preflight
    add(
        results,
        "VMP 64 位 ABI 限制",
        abi_64_ok,
        "当前嵌入解释器只放行 64 位目标"
        if abi_64_ok
        else "64 位目标限制缺失",
    )

    interpreter_smoke_markers = (
        "test_valid_data_access",
        "test_data_out_of_bounds",
        "test_code_out_of_bounds",
        "test_invalid_width_and_null",
        "test_tampered_switch_case_count",
        "test_invalid_branch_target",
        "test_return_clears_transient_data",
        "test_bad_interpreter_state",
        "VMP_TEST_NO_TRAP",
    )
    ok, missing = contains_all(interpreter_smoke, interpreter_smoke_markers)
    add(
        results,
        "VMP 原生边界测试",
        ok,
        "段越界、篡改 switch、跳转、清理和坏状态场景存在"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    embed_checker_markers = (
        'bitcode.startswith(b"BC\\xc0\\xde")',
        "embedded == bitcode",
        "binary_ir_length",
        "ALLVM_EMBEDDED_VMP_IR_H",
        "hashlib.sha256",
    )
    ok, missing = contains_all(embed_checker, embed_checker_markers)
    add(
        results,
        "VMP 嵌入产物检查器",
        ok,
        "bitcode magic、长度、逐字节一致性和摘要检查存在"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    embedded_header_markers = (
        "ALLVM_EMBEDDED_VMP_IR_H",
        "binary_ir_length",
        "binary_ir_data",
        "get_binary_ir",
    )
    ok, missing = contains_all(embedded_header, embedded_header_markers)
    add(
        results,
        "VMP 嵌入头结构",
        ok,
        "带 include guard 的嵌入头已生成"
        if ok
        else "缺少: " + ", ".join(missing),
    )
'''
checker = replace_once(
    checker,
    "\n    required_secure = (\n",
    "\n" + runtime_checks + "\n    required_secure = (\n",
    "checker runtime block",
)
checker = replace_once(
    checker,
    '        "-irobf-vmp-max-code-bytes",\n'
    '        "后续路线",\n',
    '        "-irobf-vmp-max-code-bytes",\n'
    '        "运行时段边界与 fail-closed",\n'
    '        "当前嵌入解释器仅支持 64 位目标",\n'
    '        "check-vmp-embed.py",\n'
    '        "后续路线",\n',
    "README runtime markers",
)
checker = replace_once(
    checker,
    '        "VMPResourceLimits",\n'
    '        "构建助手",\n',
    '        "VMPResourceLimits",\n'
    '        "运行时段边界与 fail-closed",\n'
    '        "VM_FAULT_CODE_RANGE",\n'
    '        "check-vmp-embed.py",\n'
    '        "构建助手",\n',
    "hardening document runtime markers",
)
checker = replace_once(
    checker,
    '        ROOT / "tools" / "check-hardening.py",\n',
    '        ROOT / "tools" / "check-hardening.py",\n'
    '        ROOT / "tools" / "check-vmp-embed.py",\n',
    "Python target list",
)
checker = replace_once(
    checker,
    '    add(results, "Python 工具语法", True, "doctor 与检查器均通过 py_compile")\n',
    '    add(\n'
    '        results,\n'
    '        "Python 工具语法",\n'
    '        True,\n'
    '        "doctor、加固检查器和 VMP 嵌入检查器均通过 py_compile",\n'
    '    )\n',
    "Python success detail",
)
checker_path.write_text(checker, encoding="utf-8")


# ---------------------------------------------------------------------------
# README
# ---------------------------------------------------------------------------
readme_path = Path("README.md")
readme = readme_path.read_text(encoding="utf-8")
readme = replace_once(
    readme,
    '- 新增 VMP 兼容性预检、可配置资源阈值、严格失败模式、实际容量检查与 IR verifier；\n',
    '- 新增 VMP 兼容性预检、可配置资源阈值、严格失败模式、实际容量检查与 IR verifier；\n'
    '- VMP 解释器加入 code/data 段长度、TLS fault 状态、跳转/switch 边界、fail-closed 和返回后临时数据清理；\n'
    '- 重新生成嵌入 bitcode，并用 `tools/check-vmp-embed.py` 校验 `.bc` 与 `vm.h` 逐字节一致；\n',
    "README summary runtime bullets",
)
readme = replace_once(
    readme,
    '| 旧版 VMP | 按模块和函数派生种子；转换前检查 IR/ABI/资源；运行状态使用 TLS；转换后运行 IR verifier | 字节码仍使用 xorshift 可逆流且没有认证标签；互递归和间接递归仍不能完全静态证明安全 |\n',
    '| 旧版 VMP | 按模块和函数派生种子；转换前检查 IR/ABI/资源；运行时检查 code/data 段与跳转边界；TLS fault fail-closed；转换后运行 IR verifier | 当前嵌入解释器仅支持 64 位目标；外部原始指针仍无法获知对象长度；字节码仍使用 xorshift 且没有认证标签 |\n',
    "README capability runtime row",
)
readme = replace_once(
    readme,
    '当前预检允许的核心子集包括：不超过 64 位的整数、普通地址空间指针、`float/double`、简单 `alloca/load/store`、受支持算术、无符号整数比较、简单 GEP、C 调用约定下的普通调用、`br/switch/ret`。结构体 GEP 使用 LLVM `StructLayout` 计算真实 padding 后偏移。\n',
    '当前嵌入解释器仅支持 **64 位目标**。预检允许的核心子集包括：不超过 64 位的整数、普通地址空间指针、`float/double`、简单 `alloca/load/store`、受支持算术、无符号整数比较、简单 GEP、C 调用约定下的普通调用、`br/switch/ret`。结构体 GEP 使用 LLVM `StructLayout` 计算真实 padding 后偏移。32 位目标会在预检阶段明确跳过或在严格模式下报错。\n',
    "README 64-bit statement",
)

runtime_readme = r'''
#### 运行时段边界与 fail-closed

转换器会把每个函数的实际 `code_seg_size` 和 `data_seg_size` 写入嵌入解释器，并为可变故障状态创建线程局部 `vm_fault`。解释器保留首次故障码，后续操作不会覆盖根因。

当前故障类型包括：

```text
VM_FAULT_CODE_RANGE
VM_FAULT_DATA_RANGE
VM_FAULT_NULL_ADDRESS
VM_FAULT_INVALID_SIZE
VM_FAULT_INVALID_OPCODE
VM_FAULT_ARITHMETIC
VM_FAULT_BAD_STATE
```

运行时会检查：

- opcode、种子、立即数和 switch 表不能越过 code 段；
- VM 内部 data 段读写不能越界；
- branch/switch 目标必须落在有效 code 段内；
- switch case 数不能超过剩余字节实际可容纳的数量；
- 访问空地址、非法值宽度、除零、越界移位和无效 opcode 会设置 fault；
- 返回时保留返回值槽，并清零其余 VM data 段；
- 状态或字节码损坏时通过 `__builtin_trap()` fail-closed，而不是继续解释不可信数据。

边界检查只能够完整覆盖 **VM 自己拥有的 code/data 段**。对于原始程序传入的外部指针，解释器能够拒绝空地址，但本地二进制没有通用、可靠的方法获知该指针对应对象的真实长度；错误的非空外部指针仍可能触发目标程序本身的内存错误。因此预检、调用方契约和 ASan/设备测试仍然必要。

仓库中的 `aVMPInterpreter.bc` 已由最新 C 源重新生成，`vm.h` 由 bitcode 原始字节产生。运行：

```bash
python3 tools/check-vmp-embed.py
```

可验证 bitcode magic、声明长度、逐字节一致性、include guard 和 SHA-256 摘要。
'''
readme = replace_once(
    readme,
    '每个受保护函数的可变运行状态被放入线程局部存储，改善不同线程同时调用的隔离性。**直接递归会被拒绝**；互递归和间接递归仍无法完全静态识别，应避免用于 VMP 函数。VM 内部栈和调用栈的完整动态预算仍属于后续工作。\n\n'
    '需要明确：xorshift 字节流仍只是可逆混淆，不是 AEAD，修改 VM 字节码也尚无统一认证标签。预检解决的是语义兼容性、资源失控和静默错误，不等于密码学完整性保护。\n',
    '每个受保护函数的可变运行状态被放入线程局部存储，改善不同线程同时调用的隔离性。**直接递归会被拒绝**；互递归和间接递归仍无法完全静态识别，应避免用于 VMP 函数。VM 内部栈和调用栈的完整动态预算仍属于后续工作。\n\n'
    + runtime_readme
    + '\n需要明确：xorshift 字节流仍只是可逆混淆，不是 AEAD，修改 VM 字节码也尚无统一认证标签。预检和运行时边界解决的是语义兼容性、资源失控、越界和静默错误，不等于密码学完整性保护。\n',
    "README runtime section",
)
readme = replace_once(
    readme,
    '| `llvm/include/llvm/Transforms/Obfuscation/VMPCompatibility.h` | VMP 预检结果和资源限制接口 |\n',
    '| `aVMPInterpreter/aVMPInterpreter.c` | 带 code/data 边界和 fail-closed fault 的嵌入解释器源码 |\n'
    '| `aVMPInterpreter/aVMPInterpreter.bc` | 由解释器 C 源生成的嵌入 bitcode |\n'
    '| `llvm/include/llvm/Transforms/Obfuscation/vm.h` | bitcode 的逐字节 C++ 嵌入头 |\n'
    '| `llvm/include/llvm/Transforms/Obfuscation/VMPCompatibility.h` | VMP 预检结果和资源限制接口 |\n',
    "README VMP files",
)
readme = replace_once(
    readme,
    '| `tools/vmp-compatibility-smoke.cpp` | 解析真实 IR 的 VMP 兼容性行为测试 |\n',
    '| `tools/vmp-compatibility-smoke.cpp` | 解析真实 IR 的 VMP 兼容性行为测试 |\n'
    '| `tools/vmp-interpreter-bounds-smoke.c` | 原生执行 VMP 段边界和 fault 行为测试 |\n'
    '| `tools/check-vmp-embed.py` | 检查 `.bc` 与 `vm.h` 逐字节一致 |\n',
    "README VMP tools",
)
readme_path.write_text(readme, encoding="utf-8")


# ---------------------------------------------------------------------------
# Hardening design document
# ---------------------------------------------------------------------------
doc_path = Path("docs/ALLVM_HARDENING.md")
doc = doc_path.read_text(encoding="utf-8")
doc = replace_once(
    doc,
    '预检按当前 uint64 解释器的真实能力保守放行：至多 64 位整数、普通地址空间指针、`float/double`、简单内存操作、受支持算术、无符号比较、简单 GEP、普通 C 调用、分支、switch 和返回。\n',
    '当前嵌入解释器以 64 位 `uintptr_t` 为 ABI，因此预检只放行 64 位目标。其核心子集包括：至多 64 位整数、普通地址空间指针、`float/double`、简单内存操作、受支持算术、无符号比较、简单 GEP、普通 C 调用、分支、switch 和返回。32 位目标会明确拒绝，而不是依赖截断行为。\n',
    "hardening 64-bit statement",
)

runtime_doc = r'''### 5.5 运行时段边界与 fail-closed

解释器 ABI 新增三个每函数元数据：

```text
code_seg_size : i64，只读
数据段大小 data_seg_size : i64，只读
vm_fault      : i32，线程局部、保存首个故障
```

`aVMP.cpp` 从翻译器实际产生的 `vm_code.size()` 和 `curr_data_offset` 初始化长度，并把解释器 bitcode 中的 extern 声明映射到目标 Module 的对应全局变量。

故障代码包括：

```text
VM_FAULT_CODE_RANGE
VM_FAULT_DATA_RANGE
VM_FAULT_NULL_ADDRESS
VM_FAULT_INVALID_SIZE
VM_FAULT_INVALID_OPCODE
VM_FAULT_ARITHMETIC
VM_FAULT_BAD_STATE
```

运行时规则：

- 所有 code 字节读取在推进 IP 前验证剩余长度；
- VM 内部 data 读写统一使用 offset + size 边界检查；
- data 段内的绝对地址自动转回受检 offset；
- branch/switch 目标必须落在 code 段内；
- switch 的 case 数必须小于等于剩余字节可容纳数量，防止篡改计数造成长循环；
- opcode 解码设置尝试上限；
- 除零、越界移位、非法宽度和无效 opcode 设置 fault；
- 返回后保留返回值槽并清零其余 data 段；
- 首个 fault 触发 `__builtin_trap()` fail-closed。

辅助边界函数被强制内联。CI 会把 C 源编译为 Windows x64 bitcode，检查 `vm_interpreter` 不再调用未被克隆的内部 helper。

该边界只能完整覆盖 VM 自有 code/data 段。非空外部原始指针没有可移植的对象长度元数据，因此只能做空地址检查，不能承诺防止所有调用方指针错误。

### 5.6 嵌入产物与可执行测试

仓库中的 `aVMPInterpreter/aVMPInterpreter.bc` 已由最新解释器 C 源重新生成，`llvm/include/llvm/Transforms/Obfuscation/vm.h` 由 bitcode 的原始字节生成。

`tools/check-vmp-embed.py` 检查：

- LLVM bitcode magic；
- `binary_ir_length` 与文件长度；
- `binary_ir_data` 与 `.bc` 逐字节一致；
- include guard；
- SHA-256 摘要。

`tools/vmp-interpreter-bounds-smoke.c` 原生执行并验证：

- 正常 VM data 读写；
- code/data 越界；
- 空地址和非法宽度；
- 篡改的 switch case 数；
- 非法 branch 目标；
- 返回后临时 data 清理；
- 解释器坏状态。

`tools/vmp-compatibility-smoke.cpp` 使用 LLVM AsmParser 解析真实 IR，验证允许、拒绝和资源超限场景。CI 还会分别编译 `VMPCompatibility.cpp` 和集成后的 `aVMP.cpp`。

需要明确：运行时边界和兼容性预检不能替代 VMP 字节码认证。现有字节流仍无密码学篡改标签。

'''
doc = re.sub(
    r'### 5\.5 可执行行为测试\n.*?'
    r'需要明确：兼容性预检和资源预算不能替代 VMP 字节码认证。现有字节流仍无篡改标签。\n\n',
    runtime_doc,
    doc,
    count=1,
    flags=re.S,
)
if "### 5.5 运行时段边界与 fail-closed" not in doc:
    raise SystemExit("hardening runtime section replacement failed")
doc = replace_once(
    doc,
    '- 编译检查 `tools/allvm-doctor.py` 和 `tools/check-hardening.py`；\n',
    '- 编译检查 `tools/allvm-doctor.py`、`tools/check-hardening.py` 和 `tools/check-vmp-embed.py`；\n',
    "hardening Python tools bullet",
)
doc = replace_once(
    doc,
    '- 构建并运行解析真实 IR 的 VMP 兼容性行为测试；\n',
    '- 构建并运行解析真实 IR 的 VMP 兼容性行为测试；\n'
    '- 原生编译并执行 VMP 解释器 code/data/fault 边界测试；\n'
    '- 临时生成 Windows x64 bitcode，检查 helper 内联、fault/size 全局和 `llvm.trap`；\n'
    '- 检查仓库 `.bc` 与 `vm.h` 逐字节一致；\n',
    "hardening runtime CI bullets",
)
doc_path.write_text(doc, encoding="utf-8")
