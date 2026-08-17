# ALLVM 认证字符串记录设计

本文档描述 `StringEncryption.cpp` 当前实现的威胁模型、记录格式、密钥派生、编译期改写、运行时生命周期、兼容性限制和验收标准。

## 1. 目标与非目标

### 目标

- 发布二进制中不保留原始本地字符串常量；
- 不再依赖容易模式匹配的 XOR/取反/加减自定义变换；
- 任意记录头、nonce、偏移、长度、标签或密文被修改时，在使用明文之前失败；
- 同一个显式构建种子下，修改字符串内容时避免直接复用旧密钥/nonce 域；
- 支持普通 `i8` 字节字符串和 `i16` UTF-16LE 数组；
- 不改变原始字符串指针的长期可用语义；
- 兼容多线程首次访问和 C++ 全局构造函数；
- 编译期和模块卸载时清理可清理的敏感缓冲；
- 对不安全用户关系保守跳过，严格模式可让 CI 直接失败。

### 非目标

- 不保证客户端密钥不可提取；
- 不替代服务端授权或 Android Keystore；
- 不保证抵御能够理解格式、动态提取 key share 并重新计算标签的高权限攻击者；
- 当前不是标准 ChaCha20-Poly1305 AEAD API；
- 当前不提供每次调用后立即擦除的短生命周期明文；
- 不自动保护外部可见、自定义 section、alias/ifunc 或大端目标中的字符串。

## 2. 密码结构

当前记录使用 Encrypt-then-MAC：

```text
ChaCha20(key[0..31], nonce, counter=1)
+
SipHash-2-4 tag 0(key[32..47], domain 0)
+
SipHash-2-4 tag 1(key[48..63], domain 1)
```

两个 SipHash 标签使用互不重叠的 128 位密钥和不同 domain，总标签长度为 128 位。

这比旧的可逆自定义变换有两个关键改进：

1. 保密层使用标准 ChaCha20 核心和标准 20 轮结构；
2. 解密前验证完整性，攻击者不能只修改密文并让运行时静默执行错误明文。

仍需明确：SipHash 通常用于短消息哈希/MAC，本方案是项目内自包含实现，不等同于使用经过平台审计的 ChaCha20-Poly1305 库。后续可以保留记录版本字段，迁移到 Poly1305 或平台密码后端。

## 3. 记录格式

固定头为 48 字节：

| 偏移 | 大小 | 字段 |
|---:|---:|---|
| 0 | 4 | magic：`STR1` |
| 4 | 2 | version：当前为 1 |
| 6 | 2 | flags：UTF-16LE 等 |
| 8 | 4 | record ID |
| 12 | 4 | 明文长度 |
| 16 | 12 | ChaCha20 nonce |
| 28 | 4 | 记录在加密表中的绝对偏移 |
| 32 | 8 | tag 0 |
| 40 | 8 | tag 1 |
| 48 | N | ChaCha20 密文 |

认证输入：

```text
domain
+
记录头 0..31（不包含标签）
+
密文正文
```

因此以下修改都会使标签失败：

- magic/version/flags；
- record ID；
- 明文长度；
- nonce；
- 表偏移；
- 密文；
- 任一标签。

记录偏移也被绑定，防止把一条合法记录简单搬到另一个位置后继续通过验证。

## 4. 构建级域分离

每个模块先得到：

```text
string-record-layout | ModuleIdentifier
```

用于表布局和随机垃圾。

每条记录的 key/nonce 域包含：

```text
ModuleIdentifier
OriginalGlobalName
RecordID
Flags
PlaintextFingerprint128
```

再分别派生：

```text
string-record-key  | suffix
string-record-mask | suffix
```

`PlaintextFingerprint128` 由两个固定独立 SipHash 值拼接，作用是让显式 `ALLVM_BUILD_SEED` 模式下的域也随明文变化。它不替代记录标签，也不作为长期秘密。

## 5. key share

64 字节记录密钥在二进制中拆成：

```text
share A = random 64 bytes
share B = key XOR share A
```

运行时按 32/64 位字进行 XOR 重建使用，不创建长期完整 key 全局。

安全边界：两个 share 都在客户端中，静态或动态分析者仍能重建密钥。拆分的价值是减少单个连续密钥模式、增加自动化提取步骤，不是密钥不可导出保证。

## 6. 编译期流程

`StringEncryption` 是 ModulePass，但真正改写在 `doFinalization()`：

```text
其他 Module/Function 混淆 Pass 完成
→ 收集候选字符串和用户链
→ 构建认证加密表
→ 创建私有明文缓冲和 key share
→ 生成 ChaCha/SipHash LLVM IR 运行时
→ 创建早期构造函数
→ 重映射全局初始化器和指令用户
→ 删除原始明文全局
→ 创建卸载清理函数
→ 清理编译期明文、key、nonce 和 share 临时缓冲
→ LLVM verifier
```

延迟到 finalization 的原因是：密码运行时生成后不应再被控制流平坦化、间接调用、常量保护或 VMP 改写。这样更容易审计，也降低后续 Pass 破坏密码语义的风险。

## 7. 候选和用户链

默认只处理：

- 本地链接；
- 常量全局；
- 普通地址空间 0；
- 无自定义 section；
- 非 TLS；
- 非 COMDAT；
- `ConstantDataSequential` 的 `i8` 或 `i16` 数组；
- 至少存在一个函数指令用户；
- 所有可达函数用户都启用了 CSE。

保守拒绝：

- 外部可见全局；
- DLL import/export；
- alias、ifunc 或其他不支持的 GlobalValue；
- 自定义 section；
- 非零地址空间；
- 同一字符串流向 CSE-enabled 和 CSE-disabled 函数；
- 无法安全遍历的用户；
- 大端 DataLayout；
- 超出单记录或总表预算。

默认模式跳过并在 debug 日志中给出原因。`-irobf-cse-strict` 会终止构建，适合发布 CI。

## 8. 运行时生命周期

### 构造期解密

Pass 创建优先级 0 的 `llvm.global_ctors` 函数：

```text
验证 record 0 → 解密
验证 record 1 → 解密
...
任意失败 → llvm.trap
全部成功 → 进入普通 C++ 全局构造函数和 main
```

这样避免：

- 首次访问时的数据竞争；
- 每个函数重复插入解密调用；
- 全局构造函数在字符串尚未初始化时访问空缓冲。

代价是明文从模块初始化成功后一直保留到卸载。

### 卸载清理

默认创建优先级 0 的 `llvm.global_dtors` 清理函数。析构按反向优先级执行，因此清理发生在普通 65535 优先级析构之后，减少其他析构函数访问已清零字符串的兼容性风险。

清理使用 volatile memset，避免优化器删除写入。

## 9. 参数

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
| `irobf-cse` | false | 启用认证字符串 |
| `irobf-cse-strict` | false | 不支持候选直接使构建失败 |
| `irobf-cse-max-record-bytes` | 1 MiB | 单条明文上限；0 关闭 |
| `irobf-cse-max-table-bytes` | 64 MiB | 总认证表上限；0 关闭 |
| `irobf-cse-wipe-at-exit` | true | 模块卸载时清理明文 |
| `irobf-cse-verify` | true | 改写后执行 module verifier |

`strong` 预设显式开启严格模式和上述安全限制。

## 10. 自动化测试

`Authenticated string security checks` 覆盖：

### 密码向量

- RFC 8439 ChaCha20 block 向量；
- 固定双标签向量；
- split-key 解密；
- UTF-16LE；
- record ID/offset/flags/length 绑定；
- 密文篡改后拒绝并清零输出；
- Linux Clang 和 Windows MSVC `/W4 /WX`。

### LLVM 运行时

- 生成全部 ChaCha/SipHash/open LLVM IR；
- module verifier；
- 写出 bitcode；
- 由 `lli` 实际执行合法记录和篡改记录；
- 检查失败输出为零。

### 完整 Pass

- 构造含 `hello\0` 明文的 LLVM 模块；
- 运行正式 `StringEncryption` Pass；
- 确认原始明文 GlobalVariable 被删除；
- 确认加密表不包含连续明文；
- 确认 ctor/dtor 和密码运行时存在；
- 写出改写后的 bitcode；
- 由 `lli` 执行，确认构造期解密后 main 读取正确；
- `llvm-dis` 确认不再出现原始明文常量。

## 11. 后续路线

1. 增加 `compat/cache`、`tls`、`call` 三种明文生命周期；
2. 对可证明不逃逸的字符串使用调用期临时缓冲；
3. 为 Android 可选接入平台或经过审计的 ChaCha20-Poly1305 实现；
4. 支持设备/Keystore/服务端派生因子；
5. 对重复字符串做安全去重和性能预算；
6. 生成机器可读保护报告：受保护记录、跳过原因、体积和启动耗时；
7. 在真实 Android arm64-v8a/x86_64、4 KiB/16 KiB 设备上建立启动和卸载测试。
