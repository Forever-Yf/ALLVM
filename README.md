# ALLVM / OLLVM Obfuscator 21.x

基于 LLVM 21.x 的 Android NDK 代码保护工具链，提供控制流混淆、间接调用与跳转、字符串和常量隐藏、VMP 虚拟机保护、系统调用替换及多种运行时检测能力。

- **当前维护分支**：<https://github.com/Forever-Yf/ALLVM>
- **上游项目**：<https://github.com/abcdefgjh-li/ALLVM>
- **当前加固 PR**：`hardening/p0-secure-seeding-doctor`

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
- 常量整数、常量浮点和旧版 VMP 使用彼此独立的随机域；
- 旧版 VMP 不再使用 `srand(time(0))` 和 `rand()` 生成种子；
- 修复常量保护 Pass 对 PHI incoming value 的处理和空工作集判断；
- 新增 `tools/allvm-doctor.py`，可诊断 NDK、构建工具和 16 KiB ELF 对齐；
- 新增 GitHub Actions 烟雾检查，防止弱随机路径回归。

详细设计和后续路线见 [`docs/ALLVM_HARDENING.md`](docs/ALLVM_HARDENING.md)。

## 安全能力与边界

| 模块 | 当前能力 | 需要注意 |
|---|---|---|
| 常量整数/浮点保护 | 使用构建级安全随机根并按 Pass 分离 | 主要用于隐藏和增加分析成本，不等同于服务端秘密管理 |
| 字符串保护 | 编译期变换并在运行时还原 | 目前仍缺少标准 AEAD 完整性标签，属于后续重点 |
| 旧版 VMP | 按模块和函数派生不可预测种子 | 字节码仍使用 xorshift 类可逆流，尚未实现认证加密 |
| 控制流平坦化 | 改变基本块调度结构 | 可能增加体积、寄存器压力和编译时间 |
| 间接调用/跳转 | 隐藏直接调用与分支关系 | 对异常、内联汇编和特殊控制流需充分回归 |
| Syscall Protect | ARM64 下将部分 libc 调用替换为直接系统调用 | 与 Android 版本、ABI 和 seccomp 策略相关，不适合无条件全开 |
| 反调试/环境检测 | 提供 ptrace、hook、maps、root 等检测 | 可能误报；建议作为风险信号，不要把单一检测作为唯一授权依据 |

## 环境要求

当前仓库的主要构建入口仍面向 Windows：

- Windows 10/11 x64；
- Visual Studio 2022 C++ 工具链；
- CMake；
- Ninja；
- Python 3.9 或更高版本；
- Android SDK 与 Android NDK；
- Java 和 ADB 为 Android 测试所需的可选依赖。

LLVM 源码本身可在其他主机上构建，但仓库中的 `build.cpp` 仍包含 Windows 专用路径和批处理调用，尚未完成跨平台重构。

## 先运行环境诊断

不要先猜 NDK 路径。建议在编译前运行：

```bash
python3 tools/allvm-doctor.py --ndk /path/to/android-ndk
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
py tools/allvm-doctor.py --ndk D:\Android\Sdk\ndk\29.0.14206865
```

JSON 输出：

```bash
python3 tools/allvm-doctor.py --json
```

检查 Android `.so` 是否满足 16 KiB LOAD 段对齐：

```bash
python3 tools/allvm-doctor.py \
  --ndk /path/to/android-ndk \
  --elf app/build/intermediates/stripped_native_libs/release/out/lib/arm64-v8a/libexample.so
```

## 快速开始

### 1. 获取源码

```bash
git clone https://github.com/Forever-Yf/ALLVM.git
cd ALLVM
git switch hardening/p0-secure-seeding-doctor
```

### 2. 编译工具链

仓库保留原有 Windows 构建入口：

```powershell
.\build.exe
```

也可以从 `build.cpp` 重新生成构建程序：

```powershell
cl /std:c++17 /EHsc /utf-8 build.cpp /Fe:build.exe
.\build.exe
```

> [!WARNING]
> 当前 `build.cpp` 在完整构建流程末尾仍会调用 `replace_ndk_clang()`：它会先生成 `.bak`，随后把部分 OLLVM 工具复制进所配置的 NDK。请只对专门用于 ALLVM 的 NDK 副本执行该操作，不要直接对日常开发或生产 NDK 运行。后续版本会改为独立 toolchain overlay，默认不修改原 NDK。

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
└── legacy-vmp | ModuleIdentifier | FunctionName
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

当前旧版 VMP 的已知边界：

- 仍使用固定的 VM code/data segment 容量；
- xorshift 仍是可逆混淆流，不是经过认证的密码算法；
- 对异常处理、协程、`callbr`、复杂内联汇编、动态栈分配和特殊 ABI 需要单独测试；
- 修改字节码后尚无统一认证标签；
- 递归和并发调用需要应用侧专项回归。

因此，本阶段改进解决的是**种子不可预测性和跨函数隔离**，并不宣称 VMP 字节码已达到认证加密等级。

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
| `llvm/lib/Transforms/Obfuscation/aVMP.cpp` | 旧版 VMP 翻译器 |
| `llvm/lib/Transforms/Obfuscation/ObfuscationPassManager.cpp` | Pass 注册与调度 |
| `tools/allvm-doctor.py` | 环境和 ELF 诊断工具 |
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
2. 为 VMP 字节码增加分块完整性验证和动态容量计算；
3. 清理密钥、nonce 和内部状态的符号或日志泄漏；
4. 将 `build.cpp` 改为显式 NDK 参数和独立 toolchain overlay；
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
