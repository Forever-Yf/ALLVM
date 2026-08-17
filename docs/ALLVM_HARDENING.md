# ALLVM 加固说明

本文记录 `hardening/p0-secure-seeding-doctor` 分支已经完成的安全改造、验证范围、剩余风险和后续实施顺序。目标是把大规模重构拆成可独立审查、可回归的小步骤。

## 1. 威胁模型

本阶段主要对抗：

- 通过构建时间推测 PRNG 种子；
- 不同 Pass 或不同函数复用相同随机序列；
- 从编译日志中直接取得显式种子；
- 利用错误的十六进制种子解析触发越界写入；
- 通过固定随机序列批量匹配常量保护和 VMP 产物；
- 因 NDK、工具链或 ELF 页对齐配置错误造成构建和运行失败。

本阶段不宣称解决：

- 客户端长期密钥不可提取；
- 字符串记录的标准 AEAD，以及客户端认证密钥不可提取；
- 运行时内存中的明文绝对不可观察；
- 对所有 LLVM IR 构造、ABI 和 Android ROM 的兼容；
- 自定义 ELF 装载器的全部边界检查和 16 KiB 页适配。

## 2. 构建级安全随机根

新增：

```text
llvm/include/llvm/Transforms/Obfuscation/SecureRandom.h
```

默认随机源：

- Windows：`BCryptGenRandom` 与 `BCRYPT_USE_SYSTEM_PREFERRED_RNG`；
- POSIX：`/dev/urandom`，处理短读和 `EINTR`；
- 无法获得系统熵时立即终止，不再回退到时间、地址或弱 PRNG。

每个编译进程只生成一次 32 字节构建根。随后使用 SHA-256 将根种子和域字符串组合，派生现有 `CryptoUtils` 所需的 128 位 AES-CTR 种子：

```text
BuildSeed（32 字节）
├── constant-int
├── constant-fp
├── string-encryption | ModuleIdentifier
├── legacy-vmp-layout | ModuleIdentifier | FunctionName
└── legacy-vmp-integrity | ModuleIdentifier | FunctionName
```

这样可以避免整数常量、浮点常量和不同 VMP 函数之间意外复用随机序列。

### 可复现构建

设置 `ALLVM_BUILD_SEED` 可以显式进入确定性模式：

```bash
export ALLVM_BUILD_SEED=9f3d0f0f2a37d64e7adbb5bf402f8de02ecdf73334edb81beeaaf9d6f2aaf02c
```

规则：

- 必须是 64 个十六进制字符；
- 可选 `0x` 或 `0X` 前缀；
- 不接受普通密码或任意长度文本；
- 发布构建建议不设置；
- 变量只保证 ALLVM 随机域可重复，不保证完整二进制逐字节一致。

## 3. CryptoUtils 修复

### 3.1 默认种子

旧实现的问题：

- Windows 使用当前时间播种 `std::mt19937`；
- 只有 16 字节 AES 密钥外形，并不代表输入熵达到 128 位；
- POSIX 使用独立文件流逻辑，错误处理和 Windows 不一致。

现在所有主机统一调用 `fillSecureRandom()`，从操作系统 CSPRNG 取得 16 字节材料，再初始化现有 AES-CTR 池。

### 3.2 显式十六进制种子

旧实现接受 34 字符形式时从索引 2 开始读取，却使用 `i >> 1` 作为目标索引。最后一个字节会写到 `s[16]`，超出 16 字节数组。

现在：

1. 先验证 `0x` 前缀；
2. 去除前缀后要求长度严格为 32；
3. 对每个字符执行显式十六进制校验；
4. 使用独立目标索引解码 16 字节；
5. 不在调试日志中输出种子；
6. 使用后清理临时解码缓冲。

### 3.3 敏感数据清理

析构时使用 volatile 写循环清理：

- AES 密钥；
- key schedule；
- CTR；
- 随机池；
- 内部种子字符串存储。

这比普通 `memset` 更不容易被优化器视为无用写入而移除。

### 3.4 无偏范围随机

旧 `get_range()` 通过计算位掩码进行拒绝采样。当 `log == 32` 且主机的 `unsigned long` 为 32 位时，`1UL << 32` 存在未定义行为。

现在使用拒绝阈值：

```cpp
const uint32_t Threshold = static_cast<uint32_t>(-max) % max;
```

先拒绝低于阈值的 32 位值，再执行 `% max`，避免移位未定义行为并保持 `[0, max)` 上的均匀分布。

## 4. 常量保护 Pass 修复

整数和浮点 Pass 已完成：

- 分别使用 `constant-int` 与 `constant-fp` 域；
- 判断当前函数的 `FuncModifyIRs`，不再错误检查整个全局 map；
- 对 PHI 节点统一使用 incoming-value API；
- 保留 switch 前驱的跳过行为；
- 显式包含 `unordered_map`，减少间接 include 依赖。

### 字符串 Pass 随机生命周期

`StringEncryption.cpp` 现在按 `string-encryption | ModuleIdentifier` 派生独立随机序列，因此显式 `ALLVM_BUILD_SEED` 模式可以复现字符串保护，而不同模块不会意外共享同一序列。

同时完成：

- 使用 `CryptoUtils::get_range()` 无偏选择 8/16 位密钥和垃圾区长度，包含配置的最大值；
- 以 `std::vector<uint8_t>` 代替裸 `new[]` 临时随机缓冲；
- 使用后清理临时随机缓冲；
- Pass finalization 时清理编译进程内的字符串数据和密钥向量。

这些改动改善的是构建随机性、可复现性和编译期敏感数据生命周期。现有字符串记录仍使用自定义可逆变换，密钥与密文共同存放在二进制中，也没有认证标签，因此不能称为 AEAD；标准认证加密仍是后续独立改造。

## 5. 旧版 VMP 随机化与兼容性预检

### 5.1 函数级随机域

旧版 `aVMP.cpp` 原先使用：

```cpp
srand(time(0));
xorshift32_seed ^= rand();
```

同一秒内的构建容易产生相关种子，也难以在不同函数之间建立稳定隔离。现在每个翻译器按以下域派生独立 `CryptoUtils`：

```text
legacy-vmp-layout | ModuleIdentifier | FunctionName
legacy-vmp-integrity | ModuleIdentifier | FunctionName
```

随后取得非零 32 位种子，保证 xorshift 状态不会以零启动。布局随机流与认证密钥使用不同域。xorshift 仍是可逆混淆，不是 AEAD；完整性由后述分块标签单独负责。

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

当前嵌入解释器以 64 位 `uintptr_t` 为 ABI，因此预检只放行 64 位目标。其核心子集包括：至多 64 位整数、普通地址空间指针、`float/double`、简单内存操作、受支持算术、无符号比较、简单 GEP、普通 C 调用、分支、switch 和返回。32 位目标会明确拒绝，而不是依赖截断行为。

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
- 旧版解释器没有独立操作数栈；数据值槽继续按实际结果动态创建；
- 运行时限制 opcode 步数、Call opcode 次数和线程共享调用深度，并用每函数活动标志拒绝同函数重入。

### 5.5 分块认证与执行预算

每个基本块格式由原来的 8 字节种子头升级为固定 32 字节认证头：

```text
opcode_seed : u32
code_seed   : u32
body_size   : u32
magic       : u32
tag0        : u64
tag1        : u64
ciphertext  : body_size bytes
```

翻译器使用独立的 `legacy-vmp-integrity` 域派生 128 位函数密钥。两个域分离的 SipHash-2-4 标签覆盖版本、块偏移、正文长度、两个种子及加密正文。解释器先验证范围、magic 和两个标签，再设置流状态和 IP。branch/switch 目标必须指向完整块头，读取也不能跨过当前认证块。

新增运行时参数：

```text
-irobf-vmp-max-runtime-steps=10000000
-irobf-vmp-max-runtime-calls=65536
-irobf-vmp-max-call-depth=64
```

0 表示关闭对应限制。步数预算限制循环，调用预算限制单次解释中的 Call opcode，模块级 TLS 深度限制跨 VMP 函数嵌套；每函数 TLS 活动标志拒绝同函数重入。密钥位于客户端，所以标签不是不可伪造的远程信任根，也不提供 xorshift 之外的保密性。

### 5.6 运行时段边界与 fail-closed

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
VM_FAULT_INTEGRITY
VM_FAULT_STEP_LIMIT
VM_FAULT_CALL_LIMIT
VM_FAULT_CALL_DEPTH
VM_FAULT_REENTRANT
VM_FAULT_BLOCK_RANGE
```

运行时规则：

- 每次进入基本块先验证双标签，所有 code 字节读取同时受当前块和总 code 段边界约束；
- VM 内部 data 读写统一使用 offset + size 边界检查；
- data 段内的绝对地址自动转回受检 offset；
- branch/switch 目标必须落在 code 段内；
- switch 的 case 数必须小于等于剩余字节可容纳数量，防止篡改计数造成长循环；
- opcode 解码设置尝试上限；
- 除零、越界移位、非法宽度和无效 opcode 设置 fault；
- opcode 步数、Call 次数、调用深度和重入超过预算时设置独立 fault；
- 返回后保留返回值槽并清零其余 data 段；
- 首个 fault 触发 `__builtin_trap()` fail-closed。

辅助边界函数被强制内联。CI 会把 C 源编译为 Windows x64 bitcode，检查 `vm_interpreter` 不再调用未被克隆的内部 helper。

该边界只能完整覆盖 VM 自有 code/data 段。非空外部原始指针没有可移植的对象长度元数据，因此只能做空地址检查，不能承诺防止所有调用方指针错误。

### 5.7 嵌入产物与可执行测试

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
- 解释器坏状态；
- 固定 SipHash 向量、合法认证块、密文/标签/长度篡改和块内越界；
- opcode 步数、Call 次数、调用深度和重入预算。

`tools/vmp-compatibility-smoke.cpp` 使用 LLVM AsmParser 解析真实 IR，验证允许、拒绝和资源超限场景。CI 还会分别编译 `VMPCompatibility.cpp` 和集成后的 `aVMP.cpp`。

需要明确：双 SipHash 标签会在执行前检测块篡改，但密钥和验证器同驻客户端，不能提供服务端级不可伪造信任；xorshift 也仍不是 AEAD。

## 6. 环境诊断

新增：

```text
tools/allvm-doctor.py
```

工具只依赖 Python 标准库，可检查：

- Python、CMake、Ninja；
- Java、ADB；
- 显式 NDK 路径；
- `ANDROID_NDK_HOME`、`ANDROID_NDK_ROOT`；
- Android SDK 下的 side-by-side NDK；
- NDK 主机工具链和 `clang`、`clang++`、`ld.lld`；
- 主机页大小；
- Android ELF 的 LOAD 段对齐；
- JSON 机器可读输出。

示例：

```bash
python3 tools/allvm-doctor.py --ndk /path/to/android-ndk
python3 tools/allvm-doctor.py --ndk /path/to/android-ndk --elf libexample.so
python3 tools/allvm-doctor.py --json
```

诊断工具不会修改 NDK。

## 7. 构建助手

`build.cpp` 已完成第一轮易用性和环境隔离改造：

- 支持 `--ndk <path>`；
- 支持 `ALLVM_NDK`、`ANDROID_NDK_HOME`、`ANDROID_NDK_ROOT`；
- 可从 `ANDROID_SDK_ROOT`、`ANDROID_HOME` 和 Windows 默认 SDK 目录发现 side-by-side NDK；
- 可识别 Visual Studio 2022 Enterprise、Professional、Community、Build Tools，并使用 `vswhere` 兜底；
- 支持 `--doctor` 和 `--doctor-only`；
- 默认把产物保留在 `build-windows\bin`，不会修改原 NDK；
- 只有显式 `--install-into-ndk` 才执行复制，并为原文件创建 `.bak`；
- 对目标 triple 和并行任务数进行输入校验。

当前仍是 Windows 专用构建助手，且显式安装模式本质上仍会复制文件。长期方案是独立 toolchain overlay，并通过 CMake、Gradle 或 ndk-build 显式选择编译器。

## 8. 当前自动化验证

`.github/workflows/hardening-smoke.yml` 用于：

- 编译检查 `tools/allvm-doctor.py`、`tools/check-hardening.py` 和 `tools/check-vmp-embed.py`；
- 验证 doctor 的 `--help` 入口；
- 编译并运行 `SecureRandom.h` 的最小 C++17 烟雾测试；
- 使用同一套 LLVM 头文件分别编译 `VMPCompatibility.cpp` 和 `aVMP.cpp`；
- 构建并运行解析真实 IR 的 VMP 兼容性行为测试；
- 原生编译并执行 VMP 解释器 code/data/fault 边界测试；
- 临时生成 Windows x64 bitcode，检查 helper 内联、fault/size 全局和 `llvm.trap`；
- 检查仓库 `.bc` 与 `vm.h` 逐字节一致；
- 检查安全随机头文件包含 Windows 与 POSIX 路径；
- 阻止常量保护、`CryptoUtils` 和旧版 VMP 重新引入弱随机调用；
- 检查构建助手保持“默认不修改 NDK”；
- 在 Windows runner 上使用 MSVC 编译 `build.cpp`；
- 检查中文 README 中的确定性种子、安全默认值和安全边界说明。

这些是烟雾测试，不等价于完整 LLVM 构建。

## 9. 验收标准

### 随机性

- 不设置 `ALLVM_BUILD_SEED` 时，两次构建应产生不同保护布局；
- 设置相同种子时，同一模块和函数的随机域应可重复；
- 不同函数不得共享同一 VMP 初始序列；
- 源码和日志不得出现时间播种路径或原始种子值。

### 正确性

- 32 字符和带 `0x` 的 34 字符种子都必须正确解码；
- 非十六进制、过短和过长种子必须明确失败；
- `get_range(0)` 返回 0；
- 对常见和极端 `max` 值进行分布与边界测试；
- PHI、switch 前驱和空函数保持语义一致。

### 兼容性

至少覆盖：

- Windows 与 Linux 主机构建；
- `arm64-v8a`、`x86_64`；
- 4 KiB 与 16 KiB 页；
- RTTI/exceptions 开关组合；
- `-O0`、`-O2`、`-Oz`、LTO/ThinLTO；
- 递归、并发、JNI、函数指针与虚函数。

## 10. 仍需完成的高优先级改造

### P0/P1

1. 字符串记录改为标准 AEAD，并定义缓存、TLS 和调用期明文生命周期；
2. 扩展 capability analysis 覆盖面、互递归静态检测和机器可读跳过报告；
3. 为分块认证增加可选设备/服务端派生因子，降低纯离线重签名能力；
4. 增加真实 Android 递归、并发和长循环的预算回归矩阵；
5. 清理符号、日志、统计数据中的密钥和内部状态；
6. 修复自定义 ELF 装载器的 16 KiB 页、边界溢出和 W^X；
7. 在现有显式 NDK 和安全默认值基础上实现完整 toolchain overlay，移除向 NDK 复制工具的兼容模式。

### P2

1. 迁移 New Pass Manager；
2. 将大部分保护拆为 out-of-tree 插件；
3. 建立 LLVM/NDK/ABI 构建矩阵；
4. 添加体积、编译时间、启动时间和热点开销预算；
5. 增加产物密钥特征扫描和差分测试。

## 11. 安全结论

当前改造显著提升了构建时随机源、种子隔离和错误处理质量，并修复了一个真实的显式种子越界问题。但保护逻辑和解密逻辑仍同时存在于客户端，攻击者在足够权限和时间下仍可观察运行时状态。

因此，ALLVM 应被视为分层防护中的客户端成本提升手段，而不是服务端信任、硬件密钥和完整授权协议的替代品。
