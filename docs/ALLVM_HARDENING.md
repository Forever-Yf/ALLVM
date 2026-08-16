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
- 字符串和 VMP 字节码的认证加密；
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
└── legacy-vmp | ModuleIdentifier | FunctionName
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

## 5. 旧版 VMP 随机化

旧版 `aVMP.cpp` 原先：

```cpp
srand(time(0));
xorshift32_seed ^= rand();
```

同一秒内的构建容易产生相关种子，也难以在不同函数之间建立稳定隔离。

现在每个翻译器按以下域派生独立 `CryptoUtils`：

```text
legacy-vmp | ModuleIdentifier | FunctionName
```

随后从该实例取得非零 32 位种子，保证 xorshift 状态不会以零启动。

需要明确：这只改善**种子质量和函数级隔离**。现有 xorshift 字节流仍是可逆混淆，不是 AEAD，也不能检测字节码篡改。

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

- 编译检查 `tools/allvm-doctor.py` 和 `tools/check-hardening.py`；
- 验证 doctor 的 `--help` 入口；
- 编译并运行 `SecureRandom.h` 的最小 C++17 烟雾测试；
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
2. VMP 字节码增加分块完整性标签；
3. 动态计算 VM code/data/stack 容量，替代固定 5000 字节；
4. 增加不支持 IR 构造的 capability analysis 和跳过报告；
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
