# ALLVM 加固设计与验收说明

本文记录从原始 ALLVM 到当前 `security/p3-authenticated-strings` 分支已经完成的安全改造、验证范围、剩余边界和后续实施顺序。

相关文档：

- 总览与使用：[`../README.md`](../README.md)
- CLI 与项目接入：[`ALLVM_USAGE_CN.md`](ALLVM_USAGE_CN.md)
- 认证字符串细节：[`AUTHENTICATED_STRINGS_CN.md`](AUTHENTICATED_STRINGS_CN.md)

## 1. 威胁模型

### 1.1 重点提高成本的攻击

- 静态提取字符串、常量、控制流和调用关系；
- 批量模式匹配旧 XOR/加减字符串解密器；
- 修改 VMP 字节码或字符串密文后继续运行；
- 复制受保护记录到不同位置；
- 利用弱随机种子复现多个构建；
- 通过未支持 IR 让 VMP 静默生成错误语义；
- 利用固定 VM/code/data 容量、错误跳转或 switch 表导致越界；
- 通过 NDK 被直接覆盖造成环境污染和不可恢复构建；
- 项目配置与生成参数漂移。

### 1.2 不声称完全解决

- 具备 root、内核、调试器或完整动态插桩能力的攻击者；
- 能够提取客户端所有 key share 并复刻认证算法的攻击者；
- 服务端授权逻辑缺失；
- 长期私钥放在客户端；
- Android 平台本身被完全控制；
- 未经真实 NDK/设备验证的 ABI、页面大小和性能问题。

## 2. 构建级随机根

### 2.1 系统随机源

```text
Windows → BCryptGenRandom
POSIX   → /dev/urandom（短读和 EINTR 处理）
```

无法获取系统熵时直接终止，不回退到：

```text
time
地址
rand/srand
std::mt19937(time)
```

### 2.2 可复现构建

仅显式设置 `ALLVM_BUILD_SEED` 时启用。格式为 64 个十六进制字符，可带 `0x` 前缀。

默认发布构建不设置该变量。

### 2.3 域分离

```text
BuildSeed
├── constant-int
├── constant-fp
├── string-record-layout | module
├── string-record-key    | module | global | id | flags | plaintext fingerprint
├── string-record-mask   | module | global | id | flags | plaintext fingerprint
├── legacy-vmp-layout    | module | function
└── legacy-vmp-integrity | module | function
```

用途之间不直接复用随机流。

### 2.4 CryptoUtils 修复

- 严格检查显式种子长度和十六进制字符；
- 修复 `0x` 前缀处理可能越界；
- 不打印原始种子；
- 清理 AES key、schedule、CTR、随机池和临时缓冲；
- 修复 `get_bytes()` 结束条件；
- `get_range()` 使用无偏拒绝采样；
- 避免 32 位平台移位未定义行为。

## 3. 认证字符串记录

### 3.1 旧实现问题

旧字符串格式依赖 XOR、取反、加减和前一明文字节反馈，密钥、垃圾和密文位于同一表中。攻击者识别记录布局和解密器后即可批量还原，且记录被修改时没有可靠完整性验证。

旧实现已从 `LLVMObfuscation` 正式构建中移除；`StringEncryption.cpp` 现在是认证记录实现。

### 3.2 当前密码结构

```text
ChaCha20（20 轮，counter=1）
+
SipHash-2-4 tag 0（独立 128 位密钥）
+
SipHash-2-4 tag 1（另一独立 128 位密钥）
```

两个标签和不同 domain 合计提供 128 位记录标签。采用 Encrypt-then-MAC：先验证，后解密。

记录头 48 字节：

```text
magic/version/flags
record_id
plaintext_size
12-byte nonce
record_offset
64-bit tag0
64-bit tag1
ciphertext
```

认证覆盖头部 0..31 和密文，因此记录 ID、类型、长度、nonce、位置和正文均被绑定。

### 3.3 密钥派生和 nonce 复用防护

每条记录的 KDF 域绑定：

```text
ModuleIdentifier
GlobalName
RecordID
Flags
PlaintextFingerprint128
```

因此即使测试中固定 `ALLVM_BUILD_SEED`，修改明文也会改变 key/nonce 派生域。

指纹由两个固定独立 SipHash 值组成，用于 KDF 域分离，不作为记录认证标签。

### 3.4 key share

64 字节记录密钥被拆成两个 64 字节 XOR share。运行时按需 XOR 使用，不创建长期完整 key 全局。

这只增加提取步骤，不提供不可导出保证；两个 share 和验证器都在客户端。

### 3.5 Pass 执行顺序

字符串 Pass 的 `runOnModule()` 不直接改写；实际工作位于 `doFinalization()`。

自定义 ObfuscationPassManager 在所有 Module/Function Pass 运行后调用子 Pass finalization，因此：

```text
其他混淆完成
→ 认证字符串改写
→ 生成密码运行时
→ module verifier
```

密码辅助函数不会再被平坦化、间接调用、常量保护或 VMP 处理。

### 3.6 用户链预检

允许：

- 本地常量 `i8` 字节字符串；
- 本地常量 `i16` UTF-16LE 数组；
- 地址空间 0；
- 通过本地常量容器和 ConstantExpr 到达函数指令；
- 所有可达函数均启用 CSE。

保守跳过或严格失败：

- 外部可见全局；
- DLL import/export；
- TLS、COMDAT、自定义 section；
- alias、ifunc 或其他不支持 GlobalValue；
- 非零地址空间；
- CSE enabled/disabled 混合用户；
- 无函数指令用户；
- 大端目标；
- 单记录或总表超限。

### 3.7 运行时生命周期

优先级 0 的构造函数在普通 C++ 构造函数之前：

```text
逐条验证双标签
→ 通过后 ChaCha20 解密
→ 写入私有可写缓冲
→ 任意失败 llvm.trap
```

原始明文 GlobalVariable 被删除，所有指令和本地全局初始化器重映射到明文缓冲。

默认明文缓存到模块卸载。优先级 0 的 dtor 在普通 65535 析构之后 volatile 清零，避免普通析构先看到空字符串。

### 3.8 参数

```text
-irobf-cse
-irobf-cse-strict
-irobf-cse-max-record-bytes=1048576
-irobf-cse-max-table-bytes=67108864
-irobf-cse-wipe-at-exit
-irobf-cse-verify
```

### 3.9 安全边界

- 不是标准 ChaCha20-Poly1305 API；
- 客户端 key share 可提取；
- 高权限攻击者理论上可修改后重新计算标签；
- 默认明文生命周期是模块级，不是调用级；
- 认证标签解决未授权篡改在执行前可检测，不等于远程信任根。

## 4. 常量保护

- 整数和浮点使用独立域；
- 修复空工作集判断；
- PHI incoming value 使用一致 API；
- 临时随机材料清理；
- 仍定位为 constant hiding，而非长期秘密加密。

## 5. VMP

### 5.1 IR 兼容性预检

预检拒绝或限制：

- PHI、select 和未实现 opcode；
- 向量、聚合、超过 64 位整数；
- undef/poison；
- dynamic/array alloca；
- atomic/volatile；
- EH、invoke、callbr、indirectbr；
- inline asm、musttail、operand bundle；
- 特殊调用约定和 ABI 属性；
- 可变参数调用；
- 直接递归；
- 资源超限；
- 非 64 位目标。

结构体 GEP 使用 `StructLayout` 的 ABI padding 偏移。

### 5.2 分块认证

每个基本块：

```text
opcode_seed : u32
code_seed   : u32
body_size   : u32
magic       : u32
tag0        : u64
tag1        : u64
ciphertext  : body_size
```

标签覆盖块位置、版本、长度、种子和加密正文。branch/switch 只能进入完整块头。

### 5.3 编译期预算

```text
-irobf-vmp-max-bbs=4096
-irobf-vmp-max-instructions=50000
-irobf-vmp-max-code-bytes=16777216
-irobf-vmp-max-data-bytes=16777216
-irobf-vmp-strict
```

### 5.4 运行时预算

```text
-irobf-vmp-max-runtime-steps=10000000
-irobf-vmp-max-runtime-calls=65536
-irobf-vmp-max-call-depth=64
```

- opcode 步数限制循环；
- Call opcode 次数限制单次调用；
- 模块 TLS 记录跨 VMP 函数深度；
- 每函数 TLS 标志拒绝同函数重入；
- fault 后 fail-closed。

### 5.5 运行时边界

- code/data 总段边界；
- 当前认证块边界；
- branch/switch 目标；
- switch case 数量和表大小；
- 除零和非法移位；
- 解释器坏状态；
- 返回后清理临时 data 段。

## 6. 构建和环境隔离

### 6.1 Windows 构建助手

- `--ndk`、`ALLVM_NDK`、`ANDROID_NDK_HOME/ROOT`；
- Android SDK side-by-side NDK；
- VS 2022 Enterprise/Professional/Community/Build Tools；
- `vswhere` fallback；
- `--doctor`、`--doctor-only`；
- 默认不修改 NDK；
- 只有显式 `--install-into-ndk` 才写入副本并建立 `.bak`。

### 6.2 overlay

`allvm overlay`：

- 创建完整独立 NDK；
- Linux 优先 reflink；
- 不使用硬链接；
- manifest 路径限制；
- 源工具和安装工具 SHA-256；
- status/update/verify/remove；
- 恶意 `..`、绝对路径和符号链接逃逸拒绝。

### 6.3 项目配置

- `compat`、`balanced`、`strong`；
- CMake、ndk-build、Gradle KTS/Groovy；
- `allvm.json` 唯一手工源；
- `allvm sync` 原子生成；
- `allvm.lock.json` 记录配置和生成文件摘要；
- `sync --check` 适合 CI。

## 7. 自动化验收

### 7.1 安全随机

- 不同默认构建随机化；
- 相同显式 seed 可复现；
- 无时间/rand 回归；
- Windows/POSIX CSPRNG 路径编译。

### 7.2 认证字符串

- RFC 8439 ChaCha block 向量；
- 固定双标签；
- split-key round trip；
- UTF-16LE；
- 头字段绑定；
- 篡改拒绝和输出清零；
- Windows MSVC `/W4 /WX`；
- 生成 LLVM runtime 并用 `lli` 执行；
- 完整 Pass 删除明文 GlobalVariable；
- constructor 解密后 main 正常；
- dtor wipe 存在；
- module verifier。

### 7.3 VMP

- 支持/拒绝 IR 行为测试；
- 分块标签固定向量；
- 密文/标签/长度篡改；
- 块内和段边界；
- opcode 碰撞；
- 步数/调用/深度/重入；
- 嵌入 bitcode 与 `vm.h` 逐字节一致；
- `aVMP.cpp` 语法和运行时 smoke。

### 7.4 易用性

- Python 3.9/3.13；
- Windows/Linux；
- CMake/ndk-build/Gradle 渲染；
- project lock；
- stale 检测；
- overlay 创建/更新/篡改/安全删除；
- manifest 路径逃逸。

## 8. 仍需真实环境验证

- 完整 LLVM 21 Windows 全量构建；
- NDK r27/r29/后续版本矩阵；
- arm64-v8a、x86_64；
- Android 4 KiB/16 KiB 真机；
- exceptions/RTTI、LTO/ThinLTO；
- 全局构造/析构复杂项目；
- 字符串表启动时间和内存增量；
- VMP 长循环、深递归和多线程；
- 自定义 ELF 装载器 W^X 和 16 KiB。

## 9. 后续优先级

### P0

1. 在真实 Android app 中验证认证字符串 ctor/dtor；
2. 完整 LLVM 21 Windows 构建；
3. arm64/x86_64、4 KiB/16 KiB 设备矩阵；
4. 自定义 ELF 装载器的页大小、溢出和 W^X。

### P1

1. 字符串 `cache/tls/call` 生命周期；
2. 标准 ChaCha20-Poly1305 或平台密码后端；
3. Keystore/设备/服务端派生因子；
4. 机器可读保护和跳过报告；
5. 性能与体积预算。

### P2

1. New Pass Manager/out-of-tree 插件化；
2. Gradle 约定插件；
3. GUI 复用 CLI；
4. 多 LLVM/NDK overlay 生命周期。
