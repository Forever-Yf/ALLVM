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


checker_path = Path("tools/check-hardening.py")
checker = checker_path.read_text(encoding="utf-8")
checker = replace_once(
    checker,
    '    string_pass = read("llvm/lib/Transforms/Obfuscation/StringEncryption.cpp")\n'
    '    build_helper = read("build.cpp")\n',
    '    string_pass = read("llvm/lib/Transforms/Obfuscation/StringEncryption.cpp")\n'
    '    vmp_header = read("llvm/include/llvm/Transforms/Obfuscation/VMPCompatibility.h")\n'
    '    vmp_preflight = read("llvm/lib/Transforms/Obfuscation/VMPCompatibility.cpp")\n'
    '    vmp_smoke = read("tools/vmp-compatibility-smoke.cpp")\n'
    '    build_helper = read("build.cpp")\n',
    "checker input files",
)

vmp_checks = r'''
    vmp_limit_markers = (
        "uint64_t MaxBasicBlocks = 4096",
        "uint64_t MaxInstructions = 50000",
        "MaxCodeBytes = 16ULL * 1024ULL * 1024ULL",
        "MaxDataBytes = 16ULL * 1024ULL * 1024ULL",
        "analyzeVMPFunction",
    )
    ok, missing = contains_all(vmp_header, vmp_limit_markers)
    add(
        results,
        "VMP 默认资源限制",
        ok,
        "基本块、指令、代码和数据默认阈值存在"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    vmp_preflight_markers = (
        "PHI 节点",
        "原子指令",
        "直接递归",
        "可变参数调用",
        "undef/poison",
        "getStructLayout",
        "MaxBasicBlocks",
        "MaxInstructions",
        "MaxCodeBytes",
        "MaxDataBytes",
    )
    ok, missing = contains_all(vmp_preflight, vmp_preflight_markers)
    add(
        results,
        "VMP 兼容性预检",
        ok,
        "危险 IR、递归、ABI 和资源边界检查存在"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    vmp_integration_markers = (
        "irobf-vmp-max-bbs",
        "irobf-vmp-max-instructions",
        "irobf-vmp-max-code-bytes",
        "irobf-vmp-max-data-bytes",
        "irobf-vmp-strict",
        "analyzeVMPFunction",
        "checkActualResourceUsage",
        "setThreadLocal(true)",
        "verifyFunction(F, &errs())",
        "isa<ConstantPointerNull>(value)",
    )
    ok, missing = contains_all(avmp, vmp_integration_markers)
    add(
        results,
        "VMP 转换器防护",
        ok,
        "预检、实际资源检查、TLS 状态和 IR verifier 已接入"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    obsolete_vmp_markers = [
        marker
        for marker in ("#define VM_CODE_SEG_SIZE", "MAX_BASIC_BLOCKS")
        if marker in avmp
    ]
    add(
        results,
        "VMP 固定容量回归",
        not obsolete_vmp_markers,
        "未发现旧固定代码段或硬编码基本块上限"
        if not obsolete_vmp_markers
        else "仍存在: " + ", ".join(obsolete_vmp_markers),
    )

    timing_ok = avmp.count("prepareVMPFunction(F);") == 1
    if timing_ok:
        required_positions = (
            "if (!Interpreter.run())",
            "prepareVMPFunction(F);",
            "GOVMModifier Modifier",
        )
        if all(marker in avmp for marker in required_positions):
            timing_ok = (
                avmp.index(required_positions[0])
                < avmp.index(required_positions[1])
                < avmp.index(required_positions[2])
            )
        else:
            timing_ok = False
    add(
        results,
        "VMP 函数属性时机",
        timing_ok,
        "仅在翻译器和解释器成功后添加 noinline/optnone"
        if timing_ok
        else "VMP 属性可能污染跳过或失败的函数",
    )

    vmp_smoke_markers = (
        'getFunction("supported")',
        'getFunction("padded_gep")',
        'getFunction("with_phi")',
        'getFunction("atomic_load")',
        'getFunction("recursive")',
        'getFunction("variadic_call")',
        'getFunction("undef_value")',
        "TightLimits.MaxInstructions = 1",
    )
    ok, missing = contains_all(vmp_smoke, vmp_smoke_markers)
    add(
        results,
        "VMP IR 行为测试",
        ok,
        "支持、拒绝和资源超限场景均有可执行测试"
        if ok
        else "缺少: " + ", ".join(missing),
    )
'''
checker = replace_once(
    checker,
    "\n    required_secure = (\n",
    "\n" + vmp_checks + "\n    required_secure = (\n",
    "checker VMP block",
)
checker = replace_once(
    checker,
    '        "--install-into-ndk",\n'
    '        "默认不会修改原 NDK",\n'
    '        "后续路线",\n',
    '        "--install-into-ndk",\n'
    '        "默认不会修改原 NDK",\n'
    '        "VMP 兼容性预检",\n'
    '        "-irobf-vmp-strict",\n'
    '        "-irobf-vmp-max-code-bytes",\n'
    '        "后续路线",\n',
    "README checker markers",
)
checker = replace_once(
    checker,
    '        "旧版 VMP 随机化",\n'
    '        "构建助手",\n',
    '        "旧版 VMP 随机化",\n'
    '        "VMP 兼容性预检",\n'
    '        "VMPResourceLimits",\n'
    '        "构建助手",\n',
    "hardening document checker markers",
)
checker_path.write_text(checker, encoding="utf-8")


readme_path = Path("README.md")
readme = readme_path.read_text(encoding="utf-8")
readme = replace_once(
    readme,
    '- 旧版 VMP 不再使用 `srand(time(0))` 和 `rand()` 生成种子；\n',
    '- 旧版 VMP 不再使用 `srand(time(0))` 和 `rand()` 生成种子；\n'
    '- 新增 VMP 兼容性预检、可配置资源阈值、严格失败模式、实际容量检查与 IR verifier；\n',
    "README summary bullet",
)
readme = replace_once(
    readme,
    '| 旧版 VMP | 按模块和函数派生不可预测种子 | 字节码仍使用 xorshift 类可逆流，尚未实现认证加密 |\n',
    '| 旧版 VMP | 按模块和函数派生种子；转换前检查 IR/ABI/资源；运行状态使用 TLS；转换后运行 IR verifier | 字节码仍使用 xorshift 可逆流且没有认证标签；互递归和间接递归仍不能完全静态证明安全 |\n',
    "README capability table",
)
readme = replace_once(
    readme,
    'LOCAL_CFLAGS += -mllvm -irobf-vmp\nLOCAL_CFLAGS += -frtti -fno-exceptions\n',
    'LOCAL_CFLAGS += -mllvm -irobf-vmp\n'
    '# CI/发布构建可启用严格模式：不兼容函数直接使构建失败\n'
    'LOCAL_CFLAGS += -mllvm -irobf-vmp-strict\n'
    'LOCAL_CFLAGS += -frtti -fno-exceptions\n',
    "README high-strength config",
)

vmp_readme = r'''### VMP 兼容性预检

启用 `-irobf-vmp` 后，每个带 `annotate("vmp")` 的函数会先经过**不修改 IR 的预检**。默认行为是跳过不兼容函数，并逐条输出原因；启用 `-irobf-vmp-strict` 后，任何不兼容函数都会使编译立即失败，适合 CI 和发布构建。

当前默认资源阈值：

| 参数 | 默认值 | 说明 |
|---|---:|---|
| `-mllvm -irobf-vmp-max-bbs=N` | `4096` | 单个函数允许的最大基本块数 |
| `-mllvm -irobf-vmp-max-instructions=N` | `50000` | 单个函数允许的最大指令数 |
| `-mllvm -irobf-vmp-max-code-bytes=N` | `16777216` | 估算和实际 VM 字节码上限，16 MiB |
| `-mllvm -irobf-vmp-max-data-bytes=N` | `16777216` | 估算和实际 VM 数据区上限，16 MiB |
| `-mllvm -irobf-vmp-strict` | 关闭 | 不再跳过，而是对不兼容函数直接报错 |

数值限制设为 `0` 表示关闭对应阈值，但通常不建议在不受信任或自动生成的 IR 上这样做。

当前预检允许的核心子集包括：不超过 64 位的整数、普通地址空间指针、`float/double`、简单 `alloca/load/store`、受支持算术、无符号整数比较、简单 GEP、C 调用约定下的普通调用、`br/switch/ret`。结构体 GEP 使用 LLVM `StructLayout` 计算真实 padding 后偏移。

以下构造会在转换前被拒绝并给出原因：

- PHI、`select`、浮点比较、有符号比较和当前未实现的 opcode；
- 向量、聚合值、超过 64 位的整数、`undef/poison`；
- 动态或数组 `alloca`、atomic/volatile、`va_arg`；
- exception personality、`invoke`、landing pad、`callbr`、`indirectbr`；
- inline asm、`musttail`、operand bundle、非 C 调用约定和特殊 ABI 参数属性；
- 可变参数调用和直接递归；
- 超出基本块、指令、代码或数据预算的函数。

代码和数据缓冲区现按实际翻译结果动态创建，并在翻译期间再次检查实际大小及跳转补丁边界。只有翻译器和嵌入解释器都成功后，才为目标函数添加 `noinline/optnone` 并改写函数体；失败或跳过不会留下这些属性。

每个受保护函数的可变运行状态被放入线程局部存储，改善不同线程同时调用的隔离性。**直接递归会被拒绝**；互递归和间接递归仍无法完全静态识别，应避免用于 VMP 函数。VM 内部栈和调用栈的完整动态预算仍属于后续工作。

需要明确：xorshift 字节流仍只是可逆混淆，不是 AEAD，修改 VM 字节码也尚无统一认证标签。预检解决的是语义兼容性、资源失控和静默错误，不等于密码学完整性保护。
'''
readme = regex_once(
    readme,
    r'当前旧版 VMP 的已知边界：\n\n.*?因此，本阶段改进解决的是\*\*种子不可预测性和跨函数隔离\*\*，并不宣称 VMP 字节码已达到认证加密等级。\n',
    vmp_readme,
    "README VMP section",
)
readme = replace_once(
    readme,
    '| `-mllvm -irobf-vmp` | VMP 虚拟机保护 |\n',
    '| `-mllvm -irobf-vmp` | VMP 虚拟机保护 |\n'
    '| `-mllvm -irobf-vmp-max-bbs=N` | VMP 基本块上限；默认 4096，0 表示关闭 |\n'
    '| `-mllvm -irobf-vmp-max-instructions=N` | VMP 指令上限；默认 50000，0 表示关闭 |\n'
    '| `-mllvm -irobf-vmp-max-code-bytes=N` | VMP 代码预算；默认 16 MiB，0 表示关闭 |\n'
    '| `-mllvm -irobf-vmp-max-data-bytes=N` | VMP 数据预算；默认 16 MiB，0 表示关闭 |\n'
    '| `-mllvm -irobf-vmp-strict` | 不兼容 VMP 函数直接使构建失败 |\n',
    "README parameter table",
)
readme = replace_once(
    readme,
    '| `llvm/lib/Transforms/Obfuscation/aVMP.cpp` | 旧版 VMP 翻译器 |\n',
    '| `llvm/include/llvm/Transforms/Obfuscation/VMPCompatibility.h` | VMP 预检结果和资源限制接口 |\n'
    '| `llvm/lib/Transforms/Obfuscation/VMPCompatibility.cpp` | VMP IR/ABI/资源兼容性分析 |\n'
    '| `llvm/lib/Transforms/Obfuscation/aVMP.cpp` | 旧版 VMP 翻译器及预检接入 |\n',
    "README key files",
)
readme = replace_once(
    readme,
    '| `tools/check-hardening.py` | 弱随机、文档和安全默认值回归检查 |\n',
    '| `tools/check-hardening.py` | 弱随机、VMP 预检、文档和安全默认值回归检查 |\n'
    '| `tools/vmp-compatibility-smoke.cpp` | 解析真实 IR 的 VMP 兼容性行为测试 |\n',
    "README tool files",
)
readme = replace_once(
    readme,
    '2. 为 VMP 字节码增加分块完整性验证和动态容量计算；\n',
    '2. 为 VMP 字节码增加分块完整性验证，并继续动态化 VM 内部栈和调用栈预算；\n',
    "README roadmap",
)
readme_path.write_text(readme, encoding="utf-8")


doc_path = Path("docs/ALLVM_HARDENING.md")
doc = doc_path.read_text(encoding="utf-8")
vmp_doc = r'''## 5. 旧版 VMP 随机化与兼容性预检

### 5.1 函数级随机域

旧版 `aVMP.cpp` 原先使用：

```cpp
srand(time(0));
xorshift32_seed ^= rand();
```

同一秒内的构建容易产生相关种子，也难以在不同函数之间建立稳定隔离。现在每个翻译器按以下域派生独立 `CryptoUtils`：

```text
legacy-vmp | ModuleIdentifier | FunctionName
```

随后取得非零 32 位种子，保证 xorshift 状态不会以零启动。该改动只改善种子质量和隔离；xorshift 仍是可逆混淆，不是 AEAD。

### 5.2 VMP 兼容性预检

新增：

```text
llvm/include/llvm/Transforms/Obfuscation/VMPCompatibility.h
llvm/lib/Transforms/Obfuscation/VMPCompatibility.cpp
```

`analyzeVMPFunction()` 在创建 helper、导入解释器或改写目标函数前执行，不修改 IR。分析结果包含：

- 是否支持；
- 基本块和指令数量；
- ConstantExpr 数量；
- 估算代码和数据字节数；
- 最多 16 条去重后的拒绝原因。

预检按当前 uint64 解释器的真实能力保守放行：至多 64 位整数、普通地址空间指针、`float/double`、简单内存操作、受支持算术、无符号比较、简单 GEP、普通 C 调用、分支、switch 和返回。

预检明确拒绝：

- PHI、`select`、浮点比较、有符号比较；
- 向量、聚合值、超过 64 位整数、`undef/poison`；
- 动态/数组 alloca、atomic/volatile、`va_arg`；
- exception personality、`invoke`、EH pad、`callbr`、`indirectbr`；
- inline asm、`musttail`、operand bundle、非 C 调用约定；
- byval/sret/inalloca/preallocated 参数；
- 可变参数调用、直接递归；
- 超出资源预算的函数。

结构体 GEP 不再手工累加字段大小，而是使用 `DataLayout::getStructLayout()` 和 `getElementOffset()`，因此能够包含 ABI padding。

### 5.3 资源阈值和严格模式

`VMPResourceLimits` 默认值：

| 资源 | 默认值 |
|---|---:|
| 基本块 | 4096 |
| 指令 | 50000 |
| 估算/实际代码 | 16 MiB |
| 估算/实际数据 | 16 MiB |

命令行对应：

```text
-irobf-vmp-max-bbs
-irobf-vmp-max-instructions
-irobf-vmp-max-code-bytes
-irobf-vmp-max-data-bytes
-irobf-vmp-strict
```

数值设为 0 可关闭该项阈值。默认模式会跳过并报告不兼容函数；严格模式通过 `report_fatal_error` 终止构建，适合 CI 和发布管线。

翻译器还会检查实际 `vm_code`、数据偏移、32 位 IP 范围以及 branch/switch patch 边界。旧的固定 code/data 宏和 4096 基本块静默返回路径已经移除。

### 5.4 失败副作用和并发状态

- 只有 translator 与嵌入解释器都成功后，才添加 `noinline/optnone` 并运行 modifier；
- modifier 完成后调用 `verifyFunction()`，无效 IR 立即终止；
- 每函数的 IP、数据区地址、数据区和 xorshift 状态使用 TLS，改善多线程并发隔离；
- 直接递归提前拒绝，互递归和间接递归仍不能完全静态识别；
- ConstantExpr 在翻译时会被物化为等价指令，极晚期失败时尚未实现完整 IR 事务回滚；
- VM 内部栈和调用栈的完整动态预算仍是后续工作。

### 5.5 可执行行为测试

`tools/vmp-compatibility-smoke.cpp` 使用 LLVM AsmParser 解析真实 IR，验证：

- 普通标量控制流、空指针和含 padding 的结构体 GEP被接受；
- PHI、atomic、signed compare、直接递归、可变参数调用、`undef` 和动态 alloca 被拒绝；
- 指令上限可触发资源拒绝。

CI 同时对 `VMPCompatibility.cpp` 和集成后的 `aVMP.cpp` 执行实际 C++/LLVM 语法编译。

需要明确：兼容性预检和资源预算不能替代 VMP 字节码认证。现有字节流仍无篡改标签。

'''
doc = regex_once(
    doc,
    r'## 5\. 旧版 VMP 随机化\n.*?(?=## 6\. 环境诊断)',
    vmp_doc,
    "hardening VMP section",
)
doc = replace_once(
    doc,
    '- 编译并运行 `SecureRandom.h` 的最小 C++17 烟雾测试；\n',
    '- 编译并运行 `SecureRandom.h` 的最小 C++17 烟雾测试；\n'
    '- 使用同一套 LLVM 头文件分别编译 `VMPCompatibility.cpp` 和 `aVMP.cpp`；\n'
    '- 构建并运行解析真实 IR 的 VMP 兼容性行为测试；\n',
    "hardening automation bullets",
)
doc = replace_once(
    doc,
    '3. 动态计算 VM code/data/stack 容量，替代固定 5000 字节；\n'
    '4. 增加不支持 IR 构造的 capability analysis 和跳过报告；\n',
    '3. 在已动态化 code/data 缓冲并加入资源预检的基础上，继续动态化 VM 内部栈和调用栈；\n'
    '4. 扩展 capability analysis 覆盖面、互递归检测和机器可读跳过报告；\n',
    "hardening remaining work",
)
doc_path.write_text(doc, encoding="utf-8")
