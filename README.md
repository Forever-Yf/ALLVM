# ALLVM / OLLVM Obfuscator 21.x

基于 LLVM 21.x 的 Android NDK 代码保护工具链，提供控制流混淆、间接调用与跳转、字符串和常量隐藏、VMP 虚拟机保护、系统调用替换及多种运行时检测能力。

- **当前维护分支**：<https://github.com/Forever-Yf/ALLVM>
- **上游项目**：<https://github.com/abcdefgjh-li/ALLVM>
- **当前加固 PR**：`hardening/p0-secure-seeding-doctor`
- **当前易用性分支**：`usability/p1-cli-presets-overlay`
- **中文 CLI 指南**：[`docs/ALLVM_USAGE_CN.md`](docs/ALLVM_USAGE_CN.md)

> [!IMPORTANT]
> 本项目用于合法软件、授权逻辑和商业代码的防护研究。代码混淆只能提高静态分析、动态跟踪和批量自动化攻击的成本，不能把客户端二进制变成绝对安全的密钥保险箱。真正的长期私钥、授权根密钥和高价值凭据应放在服务端，或交给 Android Keystore 等不可导出密钥设施处理。

## 本加固分支做了什么

相较原始版本，本分支已经完成第一阶段 P0 改造：

- Windows 使用 `BCryptGenRandom`，POSIX 主机使用 `/dev/urandom`；
- 每次构建生成 32 字节根种子，再按保护 Pass、模块和函数做域分离；
- 支持显式 `ALLVM_BUILD_SEED`，便于复现构建和回归测试；
- 修复显式 `0x` 前缀种子解码可能越界的问题；
- 不再在调试输出中打印显式 PRNG 种子；
- 使用不可轻易被编译器优化掉的方式清理临时密钥和随机缓冲；
- 修复 `CryptoUtils::get_range()` 在 32 位 `unsigned long` 平台可能发生的移位未定义行为，并保持均匀分布；
- 常量整数、常量浮点、字符串保护和旧版 VMP 使用彼此独立的随机域；
- 字符串保护按模块派生随机序列，使用无偏长度选择，并清理编译期临时密钥缓冲；
- 旧版 VMP 不再使用 `srand(time(0))` 和 `rand()` 生成种子；
- 新增 VMP 兼容性预检、可配置资源阈值、严格失败模式、实际容量检查与 IR verifier；
- VMP 解释器加入 code/data 段长度、TLS fault 状态、跳转/switch 边界、fail-closed 和返回后临时数据清理；
- VMP 每个基本块采用 32 字节认证头和双 64 位 SipHash 标签，执行前认证块元数据与加密正文；
- VMP 增加每次调用的 opcode 步数、Call opcode 次数、线程共享调用深度和同函数重入限制；
- 重新生成嵌入 bitcode，并用 `tools/check-vmp-embed.py` 校验 `.bc` 与 `vm.h` 逐字节一致；
- 修复常量保护 Pass 对 PHI incoming value 的处理和空工作集判断；
- 新增 `tools/allvm-doctor.py`，可诊断 NDK、构建工具和 16 KiB ELF 对齐；
- 新增 GitHub Actions 烟雾检查，防止弱随机路径回归；
- Windows 构建助手支持显式 NDK、环境变量和 SDK side-by-side NDK 发现，默认不会修改原 NDK。

详细设计和后续路线见 [`docs/ALLVM_HARDENING.md`](docs/ALLVM_HARDENING.md)。

## 统一 CLI 快速入口

易用性分支新增了只依赖 Python 标准库的跨平台入口，最低支持 Python 3.9：

```text
allvm
├── doctor       环境与 16 KiB ELF 诊断
├── profile      查看 compat / balanced / strong 预设
├── render       生成 CMake、ndk-build、shell、JSON 或响应文件参数
├── init         在项目内生成 .allvm 配置与接入片段
└── overlay      创建、校验和删除不修改源 NDK 的独立副本
```

仓库根目录入口：

```bash
python3 allvm.py --help
python3 allvm.py profile list
python3 allvm.py doctor --ndk /path/to/android-ndk
```

Windows：

```powershell
.\allvm.ps1 profile list
.\allvm.ps1 doctor --ndk D:\Android\Sdk\ndk\29.0.14206865
```

推荐项目接入：

```bash
# 1. 初始化 CMake 和 ndk-build 片段
python3 /path/to/ALLVM/allvm.py init \
  --directory . \
  --profile balanced \
  --build-system both

# 2. 创建完整、独立的 NDK 副本，并只在副本中安装 ALLVM 编译器
python3 /path/to/ALLVM/allvm.py overlay create \
  --ndk /path/to/android-ndk \
  --allvm-bin /path/to/ALLVM/build-windows/bin \
  --output ~/.allvm/ndk/r29-allvm

# 3. 验证副本工具哈希和源 NDK 未发生变化
python3 /path/to/ALLVM/allvm.py overlay verify \
  --path ~/.allvm/ndk/r29-allvm
```

Linux 的 `overlay create --mode auto` 优先请求写时复制，不支持时安全退回普通复制；Windows 和 macOS 使用完整复制。工具不会创建硬链接镜像，也不会直接覆盖源 NDK。完整说明见 [`docs/ALLVM_USAGE_CN.md`](docs/ALLVM_USAGE_CN.md)。

## 安全能力与边界

| 模块 | 当前能力 | 需要注意 |
|---|---|---|
| 常量整数/浮点保护 | 使用构建级安全随机根并按 Pass 分离 | 主要用于隐藏和增加分析成本，不等同于服务端秘密管理 |
| 字符串保护 | 按模块分离随机域、无偏选择密钥长度，并清理编译期临时缓冲 | 现有记录格式仍是自定义可逆变换，密钥与密文同驻二进制，尚无标准 AEAD 完整性标签 |
| 旧版 VMP | 布局与认证密钥按函数分域；转换前检查 IR/ABI/资源；每块执行前验证双 SipHash 标签；运行时限制步数、调用数、线程调用深度和重入；TLS fault fail-closed；转换后运行 IR verifier | 当前嵌入解释器仅支持 64 位目标；外部原始指针仍无法获知对象长度；认证密钥位于客户端，标签不是 AEAD，也不提供密钥不可提取保证 |
| 控制流平坦化 | 改变基本块调度结构 | 可能增加体积、寄存器压力和编译时间 |
| 间接调用/跳转 | 隐藏直接调用与分支关系 | 对异常、内联汇编和特殊控制流需充分回归 |
| Syscall Protect | ARM64 下将部分 libc 调用替换为直接系统调用 | 与 Android 版本、ABI 和 seccomp 策略相关，不适合无条件全开 |
| 反调试/环境检测 | 提供 ptrace、hook、maps、root 等检测 | 可能误报；建议作为风险信号，不要把单一检测作为唯一授权依据 |

## 环境要求

LLVM/Clang/lld 的全量编译助手目前仍主要面向 Windows；统一 CLI、预设渲染、项目初始化、环境诊断和独立 NDK 管理可在 Windows、Linux 与 macOS 使用：

- Windows 10/11 x64；
- Visual Studio 2022 C++ 工具链；
- CMake；
- Ninja；
- Python 3.9 或更高版本；
- Android SDK 与 Android NDK；
- Java 和 ADB 为 Android 测试所需的可选依赖。

LLVM 源码本身可在其他主机上构建，但仓库中的 `build.cpp` 仍是 Windows 专用的全量编译助手。它已移除单一 NDK 和 Visual Studio Enterprise 的硬编码依赖。跨平台的日常入口由 `allvm.py` 提供；它不会替代 LLVM 全量构建，而是统一诊断、预设、项目接入和隔离工具链管理。

## 先运行环境诊断

不要先猜 NDK 路径。建议在编译前运行：

```bash
python3 allvm.py doctor --ndk /path/to/android-ndk
```

工具会检查：

- Python、CMake、Ninja；
- Java、ADB；
- Android NDK 版本与主机预编译目录；
- NDK 中的 `clang`、`clang++`、`ld.lld`；
- 当前主机页大小；
- 可选 ELF 文件的 `PT_LOAD` 对齐。

Windows 示例：

```powershell
.\allvm.ps1 doctor --ndk D:\Android\Sdk\ndk\29.0.14206865
```

JSON 输出：

```bash
python3 allvm.py doctor --json
```

检查 Android `.so` 是否满足 16 KiB LOAD 段对齐：

```bash
python3 allvm.py doctor \
  --ndk /path/to/android-ndk \
  --elf app/build/intermediates/stripped_native_libs/release/out/lib/arm64-v8a/libexample.so
```

## 快速开始

### 1. 获取源码

```bash
git clone https://github.com/Forever-Yf/ALLVM.git
cd ALLVM
git switch usability/p1-cli-presets-overlay
```

### 2. 编译工具链

先查看构建助手参数：

```powershell
.\build.exe --help
```

推荐先运行诊断，再开始构建：

```powershell
.\build.exe `
  --ndk D:\Android\Sdk\ndk\29.0.14206865 `
  --doctor
```

也可以只诊断环境而不构建：

```powershell
.\build.exe `
  --ndk D:\Android\Sdk\ndk\29.0.14206865 `
  --doctor-only
```

也可以从 `build.cpp` 重新生成构建程序：

```powershell
cl /std:c++17 /EHsc /utf-8 build.cpp /Fe:build.exe
.\build.exe --ndk D:\Android\Sdk\ndk\29.0.14206865
```

NDK 发现顺序：

```text
--ndk
→ ALLVM_NDK
→ ANDROID_NDK_HOME
→ ANDROID_NDK_ROOT
→ ANDROID_SDK_ROOT / ANDROID_HOME 下的 side-by-side NDK
→ 仓库内旧版兼容目录
```

> [!NOTE]
> 构建助手默认不会修改原 NDK。编译完成的工具保留在 `build-windows\bin`。只有显式传入 `--install-into-ndk` 才会把工具复制到 NDK，并在首次复制前创建 `.bak`：
>
> ```powershell
> .\build.exe `
>   --ndk D:\Android\ALLVM-NDK-COPY `
>   --install-into-ndk
> ```
>
> 即使使用显式开关，也只应操作专门为 ALLVM 准备的 NDK 副本。更推荐使用 `allvm.py overlay create`：它先创建完整独立副本，再只替换副本中的编译工具，并通过 manifest 和 SHA-256 校验源 NDK 未改变。

### 3. 编译测试项目

将下面的 NDK 路径替换为你的实际目录：

```powershell
cd test
D:\Android\Sdk\ndk\29.0.14206865\ndk-build.cmd clean
D:\Android\Sdk\ndk\29.0.14206865\ndk-build.cmd `
  NDK_PROJECT_PATH=. `
  APP_BUILD_SCRIPT=.\jni\Android.mk `
  APP_PLATFORM=android-21 `
  APP_ABI=arm64-v8a
```

## 构建随机性与可复现构建

### 默认生产模式

不设置任何种子变量。ALLVM 会从操作系统 CSPRNG 获取新的 32 字节构建根：

```text
构建根种子
├── constant-int
├── constant-fp
├── string-encryption | ModuleIdentifier
├── legacy-vmp-layout | ModuleIdentifier | FunctionName
└── legacy-vmp-integrity | ModuleIdentifier | FunctionName
```

不同构建应生成不同的常量编码和 VMP 种子。

### 可复现模式

仅在回归测试、差分调试或需要可重复产物时设置 `ALLVM_BUILD_SEED`。值必须是 **64 个十六进制字符**，可带 `0x` 前缀：

```bash
export ALLVM_BUILD_SEED=9f3d0f0f2a37d64e7adbb5bf402f8de02ecdf73334edb81beeaaf9d6f2aaf02c
```

PowerShell：

```powershell
$env:ALLVM_BUILD_SEED = "9f3d0f0f2a37d64e7adbb5bf402f8de02ecdf73334edb81beeaaf9d6f2aaf02c"
```

注意事项：

- 不要使用人类可读密码作为构建种子；
- 不要把生产种子提交到 Git；
- 相同种子只能保证 ALLVM 随机域可重复，完整二进制是否逐字节一致还取决于编译器、路径、时间戳和链接器设置；
- 发布构建建议不设置该变量。

## 预设与构建系统生成

优先通过 CLI 生成参数，避免手工维护几十个 `-mllvm`：

```bash
python3 allvm.py profile list
python3 allvm.py render --profile compat --format cmake
python3 allvm.py render --profile balanced --format ndk-build
python3 allvm.py render --profile strong --format json
```

`init` 会生成：

```text
.allvm/
├── allvm.json
├── allvm-options.cmake
├── allvm.mk
└── README.md
```

CMake 目标创建后：

```cmake
include(${CMAKE_SOURCE_DIR}/.allvm/allvm-options.cmake)
allvm_apply(your_native_target)
```

ndk-build 在 `CLEAR_VARS` 后、`BUILD_*` 前 include 生成的 `allvm.mk`。下面的手工配置继续保留，主要用于审计预设展开结果和高级定制。

## Android.mk 推荐配置

所有 Pass 参数通过 `-mllvm` 传递。不要默认把全部保护同时打开，应按函数价值和性能预算选择。

### 兼容优先

适合首次接入和大多数普通模块：

```makefile
LOCAL_CFLAGS += -mllvm -irobf
LOCAL_CFLAGS += -mllvm -irobf-cse
LOCAL_CFLAGS += -mllvm -irobf-cie
LOCAL_CFLAGS += -mllvm -level-cie=1
LOCAL_CFLAGS += -mllvm -irobf-cfe
LOCAL_CFLAGS += -mllvm -level-cfe=1
LOCAL_CFLAGS += -mllvm -irobf-icall
LOCAL_CFLAGS += -mllvm -level-icall=1
```

### 平衡配置

适合授权、协议和业务规则模块：

```makefile
LOCAL_CFLAGS += -mllvm -irobf
LOCAL_CFLAGS += -mllvm -irobf-cse
LOCAL_CFLAGS += -mllvm -irobf-cie
LOCAL_CFLAGS += -mllvm -level-cie=2
LOCAL_CFLAGS += -mllvm -irobf-cfe
LOCAL_CFLAGS += -mllvm -level-cfe=2
LOCAL_CFLAGS += -mllvm -irobf-indgv
LOCAL_CFLAGS += -mllvm -level-indgv=2
LOCAL_CFLAGS += -mllvm -irobf-icall
LOCAL_CFLAGS += -mllvm -level-icall=2
LOCAL_CFLAGS += -mllvm -irobf-fla
LOCAL_CFLAGS += -mllvm -irobf-indbr
LOCAL_CFLAGS += -mllvm -level-indbr=2
```

### 高强度、选择性 VMP

只建议用于少量高价值、低频函数：

```makefile
LOCAL_CFLAGS += -mllvm -irobf
LOCAL_CFLAGS += -mllvm -irobf-cse
LOCAL_CFLAGS += -mllvm -irobf-cie
LOCAL_CFLAGS += -mllvm -level-cie=3
LOCAL_CFLAGS += -mllvm -irobf-cfe
LOCAL_CFLAGS += -mllvm -level-cfe=3
LOCAL_CFLAGS += -mllvm -irobf-indgv
LOCAL_CFLAGS += -mllvm -level-indgv=3
LOCAL_CFLAGS += -mllvm -irobf-icall
LOCAL_CFLAGS += -mllvm -level-icall=3
LOCAL_CFLAGS += -mllvm -irobf-fla
LOCAL_CFLAGS += -mllvm -irobf-indbr
LOCAL_CFLAGS += -mllvm -level-indbr=3

# 仅对带 annotate("vmp") 的函数虚拟化
LOCAL_CFLAGS += -mllvm -irobf-vmp
# CI/发布构建可启用严格模式：不兼容函数直接使构建失败
LOCAL_CFLAGS += -mllvm -irobf-vmp-strict
LOCAL_CFLAGS += -mllvm -irobf-vmp-max-runtime-steps=10000000
LOCAL_CFLAGS += -mllvm -irobf-vmp-max-runtime-calls=65536
LOCAL_CFLAGS += -mllvm -irobf-vmp-max-call-depth=64
LOCAL_CFLAGS += -frtti -fno-exceptions
```

不建议对整个应用无差别 VMP 化。这样会显著增加代码体积、启动耗时、编译时间和兼容性风险。

## VMP 使用方式

```cpp
#define VMP_PROTECT __attribute__((annotate("vmp")))

int VMP_PROTECT verify_license(const char *token, int length) {
    // 只放真正需要保护、调用频率较低的核心逻辑
    return token != nullptr && length > 16;
}
```

### VMP 兼容性预检

启用 `-irobf-vmp` 后，每个带 `annotate("vmp")` 的函数会先经过**不修改 IR 的预检**。默认行为是跳过不兼容函数，并逐条输出原因；启用 `-irobf-vmp-strict` 后，任何不兼容函数都会使编译立即失败，适合 CI 和发布构建。

当前默认资源阈值：

| 参数 | 默认值 | 说明 |
|---|---:|---|
| `-mllvm -irobf-vmp-max-bbs=N` | `4096` | 单个函数允许的最大基本块数 |
| `-mllvm -irobf-vmp-max-instructions=N` | `50000` | 单个函数允许的最大指令数 |
| `-mllvm -irobf-vmp-max-code-bytes=N` | `16777216` | 估算和实际 VM 字节码上限，16 MiB |
| `-mllvm -irobf-vmp-max-data-bytes=N` | `16777216` | 估算和实际 VM 数据区上限，16 MiB |
| `-mllvm -irobf-vmp-max-runtime-steps=N` | `10000000` | 单次解释调用允许的最大 opcode 步数，0 表示不限 |
| `-mllvm -irobf-vmp-max-runtime-calls=N` | `65536` | 单次解释调用允许的最大 Call opcode 次数，0 表示不限 |
| `-mllvm -irobf-vmp-max-call-depth=N` | `64` | 同一线程允许的嵌套 VMP wrapper 深度，0 表示不限 |
| `-mllvm -irobf-vmp-strict` | 关闭 | 不再跳过，而是对不兼容函数直接报错 |

数值限制设为 `0` 表示关闭对应阈值，但通常不建议在不受信任或自动生成的 IR 上这样做。

当前嵌入解释器仅支持 **64 位目标**。预检允许的核心子集包括：不超过 64 位的整数、普通地址空间指针、`float/double`、简单 `alloca/load/store`、受支持算术、无符号整数比较、简单 GEP、C 调用约定下的普通调用、`br/switch/ret`。结构体 GEP 使用 LLVM `StructLayout` 计算真实 padding 后偏移。32 位目标会在预检阶段明确跳过或在严格模式下报错。

以下构造会在转换前被拒绝并给出原因：

- PHI、`select`、浮点比较、有符号比较和当前未实现的 opcode；
- 向量、聚合值、超过 64 位的整数、`undef/poison`；
- 动态或数组 `alloca`、atomic/volatile、`va_arg`；
- exception personality、`invoke`、landing pad、`callbr`、`indirectbr`；
- inline asm、`musttail`、operand bundle、非 C 调用约定和特殊 ABI 参数属性；
- 可变参数调用和直接递归；
- 超出基本块、指令、代码或数据预算的函数。

代码和数据缓冲区现按实际翻译结果动态创建，并在翻译期间再次检查实际大小及跳转补丁边界。只有翻译器和嵌入解释器都成功后，才为目标函数添加 `noinline/optnone` 并改写函数体；失败或跳过不会留下这些属性。

每个受保护函数的可变运行状态被放入线程局部存储。直接递归仍在预检阶段拒绝；运行时另用模块级 TLS 记录跨 VMP 函数调用深度，并用每函数 `vm_frame_active` 拒绝同函数重入，因此互递归或间接递归即使逃过静态分析也会 fail-closed。旧版解释器没有独立操作数栈，值槽已按实际数据区动态创建；新增的步数、Call 次数和调用深度预算用于限制循环和嵌套执行资源。


#### 分块认证

每个 VM 基本块现在使用固定 32 字节头：两个非零随机种子、密文正文长度、格式 magic 和两个 64 位认证标签。标签使用按函数独立派生的 128 位密钥，对块偏移、版本、正文长度、两个种子和**加密后的正文**计算。branch/switch 只能跳到完整块头，解释器在设置 opcode/代码流状态前先认证目标块，任意正文、长度、种子、标签或块位置变更都会设置 `VM_FAULT_INTEGRITY` 或 `VM_FAULT_BLOCK_RANGE`。

这是客户端内嵌密钥的分块 MAC，不是 AEAD：xorshift 仍只负责混淆，标签不提供额外保密性；有能力提取并复用客户端密钥的攻击者仍可重签名补丁。它解决的是未授权修改在执行前可检测，以及普通二进制补丁不能再静默改变 VM 语义。

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
VM_FAULT_INTEGRITY
VM_FAULT_STEP_LIMIT
VM_FAULT_CALL_LIMIT
VM_FAULT_CALL_DEPTH
VM_FAULT_REENTRANT
VM_FAULT_BLOCK_RANGE
```

运行时会检查：

- 块头和密文正文必须通过双标签认证，且读取不能越过当前认证块；
- opcode、立即数和 switch 表不能越过当前块或 code 段；
- VM 内部 data 段读写不能越界；
- branch/switch 目标必须落在有效 code 段内；
- switch case 数不能超过剩余字节实际可容纳的数量；
- 访问空地址、非法值宽度、除零、越界移位和无效 opcode 会设置 fault；
- 每次解释调用限制 opcode 步数和 Call opcode 次数；跨函数共享 TLS 调用深度，并拒绝同函数重入；
- 返回时保留返回值槽，并清零其余 VM data 段；
- 状态或字节码损坏时通过 `__builtin_trap()` fail-closed，而不是继续解释不可信数据。

边界检查只能够完整覆盖 **VM 自己拥有的 code/data 段**。对于原始程序传入的外部指针，解释器能够拒绝空地址，但本地二进制没有通用、可靠的方法获知该指针对应对象的真实长度；错误的非空外部指针仍可能触发目标程序本身的内存错误。因此预检、调用方契约和 ASan/设备测试仍然必要。

仓库中的 `aVMPInterpreter.bc` 已由最新 C 源重新生成，`vm.h` 由 bitcode 原始字节产生。运行：

```bash
python3 tools/check-vmp-embed.py
```

可验证 bitcode magic、声明长度、逐字节一致性、include guard 和 SHA-256 摘要。

需要明确：xorshift 字节流仍只是可逆混淆，不是 AEAD。新增双 SipHash 标签提供执行前的分块完整性验证，但认证密钥也存在于客户端，因此不能替代服务端信任、硬件密钥或不可导出的长期秘密。

## 参数速查

### 总开关

| 参数 | 说明 |
|---|---|
| `-mllvm -irobf` | 启用 IR 保护总开关 |
| `-mllvm -irobf-debug` | 输出调试信息；发布构建不建议开启 |

### 代码结构与常量保护

| 参数 | 说明 |
|---|---|
| `-mllvm -irobf-indbr` | 间接跳转 |
| `-mllvm -level-indbr=1..3` | 间接跳转强度 |
| `-mllvm -irobf-icall` | 间接调用 |
| `-mllvm -level-icall=1..3` | 间接调用强度 |
| `-mllvm -irobf-fla` | 控制流平坦化 |
| `-mllvm -irobf-indgv` | 间接全局变量 |
| `-mllvm -level-indgv=1..3` | 全局变量保护强度 |
| `-mllvm -irobf-cse` | 字符串常量保护 |
| `-mllvm -irobf-cie` | 整数常量保护 |
| `-mllvm -level-cie=1..3` | 整数常量保护强度 |
| `-mllvm -irobf-cfe` | 浮点常量保护 |
| `-mllvm -level-cfe=1..3` | 浮点常量保护强度 |
| `-mllvm -irobf-rtti` | Microsoft RTTI 信息擦除 |
| `-mllvm -irobf-vmp` | VMP 虚拟机保护 |
| `-mllvm -irobf-vmp-max-bbs=N` | VMP 基本块上限；默认 4096，0 表示关闭 |
| `-mllvm -irobf-vmp-max-instructions=N` | VMP 指令上限；默认 50000，0 表示关闭 |
| `-mllvm -irobf-vmp-max-code-bytes=N` | VMP 代码预算；默认 16 MiB，0 表示关闭 |
| `-mllvm -irobf-vmp-max-data-bytes=N` | VMP 数据预算；默认 16 MiB，0 表示关闭 |
| `-mllvm -irobf-vmp-max-runtime-steps=N` | 单次 VM opcode 步数预算；默认 10000000 |
| `-mllvm -irobf-vmp-max-runtime-calls=N` | 单次 Call opcode 预算；默认 65536 |
| `-mllvm -irobf-vmp-max-call-depth=N` | 每线程嵌套 VMP wrapper 深度；默认 64 |
| `-mllvm -irobf-vmp-strict` | 不兼容 VMP 函数直接使构建失败 |

### 运行时检测

| 参数 | 说明 |
|---|---|
| `-mllvm -irobf-ldpreload` | `LD_PRELOAD` 注入检测 |
| `-mllvm -irobf-vmdetect` | 虚拟机环境检测 |
| `-mllvm -irobf-usb` | USB 调试相关检测 |
| `-mllvm -irobf-ida` | IDA 相关检测 |
| `-mllvm -irobf-vpn` | VPN 检测 |
| `-mllvm -irobf-proxy` | 代理和 iptables 检测 |
| `-mllvm -irobf-time` | 时间差调试检测 |
| `-mllvm -irobf-hosts` | hosts 文件检测 |
| `-mllvm -irobf-mem` | 内存驻留检测 |
| `-mllvm -irobf-ptrace` | ptrace 调试检测 |
| `-mllvm -irobf-inlinehook` | Inline Hook 检测 |
| `-mllvm -irobf-plthook` | PLT Hook 检测 |
| `-mllvm -irobf-memprotect` | 内存 Dump 相关保护 |
| `-mllvm -irobf-root` | Root 环境检测 |
| `-mllvm -irobf-noroot` | 无 Root 环境检测 |
| `-mllvm -irobf-hidemaps` | 隐藏 `/proc/self/maps`，需要 Root |
| `-mllvm -irobf-fakemaps` | 伪造 maps 内容 |

运行时检测可能受到 ROM、容器、企业网络和辅助功能工具影响。建议记录风险评分并进行多信号判断，而不是检测到单一条件就直接退出。

### Syscall Protect

```makefile
LOCAL_CFLAGS += -mllvm -irobf-syscall
```

当前实现主要面向 ARM64，可替换部分 `connect`、`send`、`recv`、`read`、`write` 和 `clock_gettime` 调用。启用前必须在目标 Android API、ABI 和设备策略上测试。

## Pass 执行顺序

当前管理器的大致顺序：

```text
1. SyscallProtect
2. VMProtect
3. 运行时检测注入
4. 常量与控制流保护
   ├── ConstantIntEncryption
   ├── IndirectGlobalVariable
   ├── ConstantFPEncryption
   ├── StringEncryption
   ├── IndirectCall
   ├── Flattening
   ├── IndirectBranch
   └── MsRttiEraser
```

改变顺序可能影响语义、优化效果和兼容性；新增 Pass 时应补充 IR verifier 和差分测试。

## 16 KiB Android 页支持

诊断工具可以检查产物是否具有至少 `0x4000` 的 LOAD 段对齐：

```bash
python3 tools/allvm-doctor.py --elf libexample.so
```

这只是产物检查的一部分。自定义 ELF 装载器若仍硬编码 4096 字节页大小，也必须改用运行时页大小并重新验证映射边界、W^X 权限和段对齐。当前仓库的自定义装载路径仍属于后续改造范围。

## 测试建议

至少建立以下矩阵：

| 维度 | 建议覆盖 |
|---|---|
| ABI | `arm64-v8a`、`x86_64`；按需要测试 `armeabi-v7a` |
| Android 页大小 | 4 KiB、16 KiB |
| NDK | 一个稳定基线、一个较新版本 |
| 优化 | `-O0`、`-O2`、`-Oz`、LTO/ThinLTO |
| C++ 特性 | RTTI、exceptions、atomics、TLS、varargs |
| 调用形态 | 递归、并发、JNI、函数指针、虚函数 |
| 验证 | 保护前后差分测试、随机输入、ASan/UBSan |

每次发布还应检查：

```bash
llvm-nm protected.so
strings protected.so
llvm-readelf -lW protected.so
```

确保没有意外密钥日志、调试标记和明文敏感字符串。

## 关键文件

| 文件 | 说明 |
|---|---|
| `llvm/include/llvm/Transforms/Obfuscation/SecureRandom.h` | 操作系统 CSPRNG、构建根和域分离入口 |
| `llvm/lib/Transforms/Obfuscation/CryptoUtils.cpp` | AES-CTR PRNG 与随机范围函数 |
| `llvm/lib/Transforms/Obfuscation/ConstantIntEncryption.cpp` | 整数常量保护 |
| `llvm/lib/Transforms/Obfuscation/ConstantFPEncryption.cpp` | 浮点常量保护 |
| `llvm/lib/Transforms/Obfuscation/StringEncryption.cpp` | 字符串保护 |
| `aVMPInterpreter/VMPIntegrity.h` | 翻译器与解释器共享的认证块格式和双 SipHash 标签实现 |
| `aVMPInterpreter/aVMPInterpreter.c` | 带分块认证、执行预算、code/data 边界和 fail-closed fault 的嵌入解释器源码 |
| `aVMPInterpreter/aVMPInterpreter.bc` | 由解释器 C 源生成的嵌入 bitcode |
| `llvm/include/llvm/Transforms/Obfuscation/vm.h` | bitcode 的逐字节 C++ 嵌入头 |
| `llvm/include/llvm/Transforms/Obfuscation/VMPCompatibility.h` | VMP 预检结果和资源限制接口 |
| `llvm/lib/Transforms/Obfuscation/VMPCompatibility.cpp` | VMP IR/ABI/资源兼容性分析 |
| `llvm/lib/Transforms/Obfuscation/aVMP.cpp` | 旧版 VMP 翻译器及预检接入 |
| `llvm/lib/Transforms/Obfuscation/ObfuscationPassManager.cpp` | Pass 注册与调度 |
| `build.cpp` | Windows 构建助手、NDK 发现和显式安装入口 |
| `tools/allvm-doctor.py` | 环境和 ELF 诊断工具 |
| `tools/check-hardening.py` | 弱随机、VMP 预检、文档和安全默认值回归检查 |
| `tools/vmp-compatibility-smoke.cpp` | 解析真实 IR 的 VMP 兼容性行为测试 |
| `tools/vmp-interpreter-bounds-smoke.c` | 原生执行 VMP 段边界和 fault 行为测试 |
| `tools/check-vmp-embed.py` | 检查 `.bc` 与 `vm.h` 逐字节一致 |
| `.github/workflows/hardening-smoke.yml` | 加固回归烟雾检查 |

## 新增 Pass 的基本步骤

1. 在 `llvm/lib/Transforms/Obfuscation/` 添加实现；
2. 在 `llvm/include/llvm/Transforms/Obfuscation/` 添加头文件；
3. 在 `llvm/lib/Transforms/Obfuscation/CMakeLists.txt` 注册源文件；
4. 在 Pass Manager 中注册并明确执行阶段；
5. 为不支持的 IR 构造提供“跳过并报告”，不要静默破坏语义；
6. 添加正常输入、边界输入、异常控制流和多线程回归测试；
7. 运行 `verifyModule`、差分测试和目标 ABI 构建。

## 后续路线

当前优先级：

1. 为字符串记录引入标准 AEAD 格式和明确的明文生命周期；
2. 为 VMP 字节码增加分块完整性验证，并继续动态化 VM 内部栈和调用栈预算；
3. 清理密钥、nonce 和内部状态的符号或日志泄漏；
4. 在现有显式 NDK 和安全默认值基础上实现完整的独立 toolchain overlay，彻底取消向 NDK 复制工具；
5. 修复自定义 ELF 装载器的 16 KiB 页和 W^X；
6. 增加 LLVM/NDK/ABI 自动化构建矩阵；
7. 逐步迁移 New Pass Manager 和 out-of-tree 插件结构。

## 致谢

- LLVM Project：<https://github.com/llvm/llvm-project>
- OLLVM / obfuscator-llvm：<https://github.com/obfuscator-llvm/obfuscator>
- xVMP：<https://github.com/amunmv/xvmp>
- 原始 ALLVM 作者与贡献者

## License

本仓库中的 OLLVM 扩展部分按 GPL v3 发布，详见 [`LICENSE`](LICENSE)。LLVM、Clang 和 lld 本体遵循 [`llvm/LICENSE.TXT`](llvm/LICENSE.TXT) 中的 Apache License 2.0 with LLVM Exceptions。
