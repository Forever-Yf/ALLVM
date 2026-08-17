# ALLVM / OLLVM Obfuscator 21.x

ALLVM 是一套基于 LLVM 21.x、面向 Android NDK/C/C++ 的代码保护工具链，提供控制流平坦化、间接调用与跳转、常量隐藏、**带完整性认证的字符串记录**、选择性 VMP、系统调用替换以及多种运行时检测能力。

- 维护仓库：<https://github.com/Forever-Yf/ALLVM>
- 上游仓库：<https://github.com/abcdefgjh-li/ALLVM>
- 当前安全分支：`security/p3-authenticated-strings`
- CLI 与项目接入：[`docs/ALLVM_USAGE_CN.md`](docs/ALLVM_USAGE_CN.md)
- 安全设计与验收：[`docs/ALLVM_HARDENING.md`](docs/ALLVM_HARDENING.md)
- 字符串记录设计：[`docs/AUTHENTICATED_STRINGS_CN.md`](docs/AUTHENTICATED_STRINGS_CN.md)

> [!IMPORTANT]
> 本项目用于合法软件、授权逻辑和商业代码的防护研究。客户端混淆与加密的目标是提高静态分析、动态跟踪、批量补丁和自动化攻击的成本，不能把离线二进制变成绝对安全的密钥保险箱。长期私钥、授权根密钥和高价值凭据仍应放在服务端，或交给 Android Keystore 等不可导出密钥设施处理。

## 当前分支已经完成的加固

### 随机源和密钥域

- Windows 使用 `BCryptGenRandom`；
- POSIX 主机使用 `/dev/urandom`，处理短读和 `EINTR`；
- 每个编译进程生成一次 32 字节构建根；
- 不再回退到时间、地址、`rand()` 或 `std::mt19937(time)`；
- 支持显式 `ALLVM_BUILD_SEED`，用于可复现构建和回归测试；
- 常量、字符串、VMP 布局和 VMP 完整性使用不同域；
- 编译期密钥、摘要和随机临时缓冲在使用后清理。

当前主要域：

```text
BuildSeed
├── constant-int
├── constant-fp
├── string-record-layout | ModuleIdentifier
├── string-record-key    | ModuleIdentifier | Global | Record | PlaintextFingerprint
├── string-record-mask   | ModuleIdentifier | Global | Record | PlaintextFingerprint
├── legacy-vmp-layout    | ModuleIdentifier | FunctionName
└── legacy-vmp-integrity | ModuleIdentifier | FunctionName
```

### 认证字符串记录

旧的 XOR/取反/加减自定义字符串变换已经从正式构建中移除。当前字符串保护采用：

```text
ChaCha20（保密）
+
两个独立 SipHash-2-4 标签（128 位总标签，完整性）
+
验签后解密、失败即 trap
```

每条记录格式：

```text
magic/version/flags
record_id
plaintext_size
nonce
record_offset
64-bit tag 0
64-bit tag 1
ChaCha20 ciphertext
```

标签绑定：

```text
记录版本
字符串类型（UTF-8/字节或 UTF-16LE）
记录 ID
明文长度
nonce
记录在加密表中的偏移
密文正文
```

运行时行为：

1. 字符串 Pass 在其他混淆 Pass 完成后才生成认证运行时，避免密码学辅助函数再次被平坦化、间接化或常量改写；
2. 优先级为 `0` 的模块构造函数在普通 C++ 全局构造函数之前处理字符串；
3. 每条记录先验证两个标签，成功后才执行 ChaCha20 解密；
4. 任意头字段、nonce、偏移、长度、标签或密文发生变化都会 fail-closed；
5. 解密结果存入私有可写缓冲，原始明文常量从模块中删除；
6. 默认在普通析构函数之后用 volatile memset 清理明文缓冲。

> [!NOTE]
> 这是自包含的 `ChaCha20 + 双 SipHash` Encrypt-then-MAC 记录，不是标准 ChaCha20-Poly1305 API，也不能阻止具备高权限、能够提取客户端密钥材料的攻击者重新生成标签。两个 64 字节 key share 主要用于打散静态模式，不等于不可导出的密钥存储。兼容模式下明文会在模块生命周期内缓存；调用期/TLS 短生命周期模式仍属于后续工作。

### VMP

- 每函数独立布局和认证域；
- 转换前检查 IR、ABI、调用约定、递归和资源预算；
- 每个基本块使用 32 字节认证头和两个 SipHash 标签；
- branch/switch 只能进入完整认证块；
- code/data 段、当前块、跳转和 switch 表均有边界检查；
- 限制单次 opcode 步数、Call opcode 次数和线程调用深度；
- 拒绝同一 VMP 函数重入；
- 运行时 fault 后 fail-closed；
- 转换后运行 LLVM verifier；
- 只支持当前嵌入解释器明确放行的 64 位目标和 IR 子集。

### 构建与易用性

- 统一跨平台 CLI：`allvm.py`、`allvm.cmd`、`allvm.ps1`、`allvm.sh`；
- 内置 `compat`、`balanced`、`strong` 三档配置；
- 可生成 CMake、ndk-build、Gradle Kotlin/Groovy、shell、PowerShell、JSON 和响应文件；
- `allvm sync --check` 可检测项目生成文件是否过期；
- `overlay create/status/update/verify/remove` 管理独立 NDK 副本；
- Windows 构建助手默认不修改原始 NDK；
- `allvm doctor` 检查 NDK、工具链和 16 KiB ELF LOAD 对齐；
- GitHub Actions 覆盖 Linux、Windows、VMP、CLI、字符串密码向量和完整 Pass 产物执行。

---

## 安全能力与边界

| 模块 | 当前能力 | 需要注意 |
|---|---|---|
| 字符串记录 | ChaCha20；双 SipHash 标签；构造期验签；失败清零并 trap；原始明文全局删除；卸载时清理缓存 | 客户端 key share 可被提取；不是标准 AEAD；明文默认缓存到模块卸载；特殊 section、别名或不安全用户会跳过/严格失败 |
| 常量整数/浮点 | 安全构建根、独立随机域、不同使用点编码 | 主要用于隐藏和增加分析成本，不是长期秘密管理 |
| VMP | 分块认证、IR 预检、资源限制、TLS fault、深度/重入保护 | 64 位和受支持 IR 子集；客户端认证密钥仍可被高权限攻击者恢复 |
| 控制流平坦化 | 改变基本块调度结构 | 可能增加体积、寄存器压力和编译时间 |
| 间接调用/跳转 | 隐藏直接调用与分支关系 | 异常、内联汇编和特殊 ABI 需要回归 |
| Syscall Protect | ARM64 下将部分 libc 调用替换为直接系统调用 | 与 Android API、ABI 和 seccomp 策略相关，不适合无条件全开 |
| 反调试/环境检测 | ptrace、hook、maps、root、VPN 等信号 | 可能误报，应作为风险信号而非唯一授权依据 |

---

## 环境要求

- Windows 10/11 x64，或用于 CLI/检查的 Linux/macOS；
- Visual Studio 2022 C++ 工具链（Windows 全量构建）；
- CMake；
- Ninja；
- Python 3.9 或更高；
- Android SDK 与 Android NDK；
- Java、ADB（设备测试可选）；
- 真实发布前应覆盖 arm64-v8a、x86_64、4 KiB 和 16 KiB 页环境。

LLVM/Clang/lld 的仓库构建助手目前仍主要面向 Windows；统一 CLI、配置生成、环境诊断和 overlay 管理可在 Windows、Linux 与 macOS 使用。

---

## 快速开始

### 1. 获取当前分支

```bash
git clone https://github.com/Forever-Yf/ALLVM.git
cd ALLVM
git switch security/p3-authenticated-strings
```

### 2. 查看 CLI

```bash
python3 allvm.py --help
python3 allvm.py profile list
python3 allvm.py profile show strong
```

Windows：

```powershell
.\allvm.ps1 --help
.\allvm.ps1 profile list
```

### 3. 诊断 NDK

```bash
python3 allvm.py doctor --ndk /path/to/android-ndk
```

```powershell
.\allvm.ps1 doctor --ndk D:\Android\Sdk\ndk\29.0.14206865
```

检查 Android `.so` 的 16 KiB LOAD 对齐：

```bash
python3 allvm.py doctor \
  --ndk /path/to/android-ndk \
  --elf path/to/libexample.so
```

### 4. 构建 Windows 工具链

```powershell
cl /std:c++17 /EHsc /utf-8 build.cpp /Fe:build.exe
.\build.exe --ndk D:\Android\Sdk\ndk\29.0.14206865 --doctor
```

默认产物位于：

```text
build-windows/bin
```

默认不会覆盖 NDK。不要把 `--install-into-ndk` 指向日常使用的原始 NDK。

### 5. 创建独立 NDK 副本

```bash
python3 allvm.py overlay create \
  --ndk /path/to/android-ndk \
  --allvm-bin /path/to/host-compatible/allvm/bin \
  --output ~/.allvm/ndk/r29-allvm
```

```bash
python3 allvm.py overlay status \
  --path ~/.allvm/ndk/r29-allvm \
  --size
```

重新编译 ALLVM 后只更新工具：

```bash
python3 allvm.py overlay update \
  --path ~/.allvm/ndk/r29-allvm \
  --allvm-bin /path/to/new/allvm/bin \
  --dry-run

python3 allvm.py overlay update \
  --path ~/.allvm/ndk/r29-allvm \
  --allvm-bin /path/to/new/allvm/bin
```

### 6. 初始化项目

```bash
python3 /path/to/ALLVM/allvm.py init \
  --directory . \
  --profile balanced \
  --build-system both \
  --gradle both
```

生成：

```text
.allvm/
├── allvm.json
├── allvm-options.cmake
├── allvm.mk
├── allvm.gradle.kts
├── allvm.gradle
├── allvm.lock.json
└── README.md
```

修改 `.allvm/allvm.json` 后：

```bash
python3 /path/to/ALLVM/allvm.py sync --directory .
python3 /path/to/ALLVM/allvm.py sync --directory . --check
```

### 7. CMake

```cmake
add_library(native-lib SHARED native-lib.cpp)
include(${CMAKE_SOURCE_DIR}/.allvm/allvm-options.cmake)
allvm_apply(native-lib)
```

### 8. ndk-build

在 `include $(CLEAR_VARS)` 后、`BUILD_*` 前加入：

```makefile
include $(LOCAL_PATH)/../.allvm/allvm.mk
```

### 9. Gradle

Kotlin DSL：

```kotlin
apply(from = rootProject.file(".allvm/allvm.gradle.kts"))
```

Groovy DSL：

```groovy
apply from: rootProject.file('.allvm/allvm.gradle')
```

NDK 路径读取顺序：

```text
-Pallvm.ndkPath
ALLVM_NDK_HOME
ANDROID_NDK_HOME
ANDROID_NDK_ROOT
```

---

## 保护预设

### `compat`

- 认证字符串记录；
- 常量整数/浮点 level 1；
- 间接调用 level 1；
- 不默认启用平坦化或 VMP。

适合第一次接入和大多数普通模块。

### `balanced`

在 `compat` 上增加：

- 常量与间接保护 level 2；
- 间接全局变量；
- 控制流平坦化；
- 间接分支。

适合经过测试覆盖的授权、协议和核心业务模块。

### `strong`

- `-irobf-cse-strict`；
- 单字符串上限 1 MiB；
- 加密表上限 64 MiB；
- 模块卸载时清理明文缓存；
- 字符串改写后运行 LLVM verifier；
- 常量/间接保护 level 3；
- 严格、选择性 VMP；
- VMP 编译期与运行时预算。

只建议用于少量高价值模块和显式标记的 VMP 函数。

---

## 字符串保护参数

```text
-mllvm -irobf-cse
-mllvm -irobf-cse-strict
-mllvm -irobf-cse-max-record-bytes=1048576
-mllvm -irobf-cse-max-table-bytes=67108864
-mllvm -irobf-cse-wipe-at-exit
-mllvm -irobf-cse-verify
```

| 参数 | 默认值 | 说明 |
|---|---:|---|
| `-irobf-cse` | 关闭 | 启用认证字符串记录 |
| `-irobf-cse-strict` | 关闭 | 遇到不安全/不支持的字符串用户时终止构建，而不是跳过 |
| `-irobf-cse-max-record-bytes=N` | 1 MiB | 单条明文记录上限；`0` 表示关闭限制 |
| `-irobf-cse-max-table-bytes=N` | 64 MiB | 整个认证字符串表上限；`0` 表示关闭限制 |
| `-irobf-cse-wipe-at-exit` | 开启 | 普通析构后 volatile 清理明文缓冲 |
| `-irobf-cse-verify` | 开启 | 字符串改写后运行 LLVM module verifier |

默认保护本地链接、常量、普通地址空间中的 `i8` 字符串或 `i16` UTF-16LE 数组。以下对象默认跳过，严格模式下涉及已选候选时会失败：

- 外部可见或非本地链接字符串；
- 自定义 section、COMDAT、TLS、非零地址空间；
- alias/ifunc 等不安全全局关系；
- 同一字符串同时流向启用和禁用 CSE 的函数；
- 无法安全重写的用户链；
- 大端目标。

### 可复现构建和 nonce 复用

设置 `ALLVM_BUILD_SEED` 时，字符串密钥/nonce 域还会绑定：

```text
模块标识
原始全局名称
记录 ID
字符串类型
128 位明文指纹
```

因此同一显式构建种子下修改明文，不会因为记录位置不变而直接复用原密钥/nonce。指纹用于 KDF 域隔离，不作为认证标签。

---

## VMP 使用

只对少量函数显式标记：

```cpp
#if defined(__clang__)
#define ALLVM_VMP __attribute__((annotate("vmp")))
#else
#define ALLVM_VMP
#endif

ALLVM_VMP
bool verify_license(const unsigned char *data, unsigned long size) {
    return data != nullptr && size > 0;
}
```

常用参数：

```text
-mllvm -irobf-vmp
-mllvm -irobf-vmp-strict
-mllvm -irobf-vmp-max-bbs=4096
-mllvm -irobf-vmp-max-instructions=50000
-mllvm -irobf-vmp-max-code-bytes=16777216
-mllvm -irobf-vmp-max-data-bytes=16777216
-mllvm -irobf-vmp-max-runtime-steps=10000000
-mllvm -irobf-vmp-max-runtime-calls=65536
-mllvm -irobf-vmp-max-call-depth=64
```

不支持或保守拒绝的典型构造包括 PHI、部分聚合/向量、异常处理、atomic/volatile、特殊调用约定、动态 alloca、直接递归和超出预算的函数。默认跳过并报告；严格模式终止构建。

---

## 构建随机性

生产构建不设置种子：

```bash
unset ALLVM_BUILD_SEED
```

仅在回归测试或差分调试中使用 64 个十六进制字符：

```bash
export ALLVM_BUILD_SEED=9f3d0f0f2a37d64e7adbb5bf402f8de02ecdf73334edb81beeaaf9d6f2aaf02c
```

PowerShell：

```powershell
$env:ALLVM_BUILD_SEED = "9f3d0f0f2a37d64e7adbb5bf402f8de02ecdf73334edb81beeaaf9d6f2aaf02c"
```

不要把生产种子提交到 Git 或输出到 CI 日志。

---

## 自动化验证

本分支的正式检查包括：

### Authenticated string security checks

- RFC 8439 ChaCha20 block 固定向量；
- 双标签固定向量；
- split-key round trip；
- UTF-16LE 和头字段绑定；
- 密文篡改拒绝并清零输出；
- Windows MSVC `/W4 /WX`；
- 生成 LLVM 密码运行时并由 `lli` 执行；
- 完整 StringEncryption Pass 改写；
- 原始明文全局消失；
- 优先构造函数验签解密；
- 卸载清理函数存在；
- 生成模块通过 LLVM verifier。

### Hardening smoke checks

- 安全随机源和域分离；
- VMP 预检、认证、边界和嵌入 bitcode；
- Windows 构建助手严格编译；
- 中文文档与安全默认值。

### Usability smoke checks

- Python 3.9/3.13；
- Windows/Linux 启动器；
- CMake、ndk-build、Gradle 渲染；
- `sync --check`；
- manifest-safe NDK overlay 生命周期。

本地基础检查：

```bash
python3 tools/check-hardening.py --compile-header
python3 tools/test-allvm-cli.py
```

---

## 当前仍未完成

- 完整 LLVM 21 + Clang + lld 的 Windows 全量构建验证；
- 真实 Android NDK arm64-v8a/x86_64 编译与设备矩阵；
- 4 KiB/16 KiB 真机运行；
- 字符串调用期/TLS 短生命周期明文模式；
- 标准 ChaCha20-Poly1305 或平台密码库后端；
- Android Keystore/服务端派生因子；
- 自定义 ELF 装载器的 16 KiB、溢出边界和 W^X 重构；
- 完整的函数跳过原因和体积/性能机器可读报告。

在上述验证完成前，安全分支继续保持 Draft PR，并建议先在独立 NDK overlay 和测试应用中使用。
