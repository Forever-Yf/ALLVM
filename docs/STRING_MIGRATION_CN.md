# 从旧字符串保护迁移到认证记录

本清单用于将已有 ALLVM 项目从旧的可逆字符串变换迁移到当前认证记录实现。正式实现仍位于原路径 `llvm/lib/Transforms/Obfuscation/StringEncryption.cpp`，现有 Pass 名称和 `-mllvm -irobf-cse` 开关保持不变。

## 1. 更新分支和工具链

当前堆叠关系：

```text
PR #1 安全基础
→ PR #2 统一 CLI
→ PR #3 项目同步/Gradle/overlay
→ PR #4 认证字符串记录
```

在 PR #4 合并前，测试仓库应切换到：

```bash
git switch security/p3-authenticated-strings
```

重新构建 ALLVM 主机工具，并增量更新独立 NDK：

```bash
python3 allvm.py overlay update \
  --path ~/.allvm/ndk/r29-allvm \
  --allvm-bin /path/to/new/allvm/bin \
  --dry-run
python3 allvm.py overlay update \
  --path ~/.allvm/ndk/r29-allvm \
  --allvm-bin /path/to/new/allvm/bin
```

## 2. 刷新项目预设

`strong` 预设新增严格字符串参数。项目使用生成配置时：

```bash
python3 allvm.py sync --directory .
python3 allvm.py sync --directory . --check
```

手工参数项目至少应保留：

```text
-mllvm -irobf-cse
```

发布 CI 推荐：

```text
-mllvm -irobf-cse-strict
-mllvm -irobf-cse-max-record-bytes=1048576
-mllvm -irobf-cse-max-table-bytes=67108864
-mllvm -irobf-cse-wipe-at-exit
-mllvm -irobf-cse-verify
```

## 3. 处理严格模式失败

严格模式可能暴露旧实现曾静默跳过的情况：

- 字符串不是本地链接；
- 字符串位于自定义 section；
- 字符串经 alias/ifunc 使用；
- 同一字符串同时流向启用和禁用 CSE 的函数；
- TLS、COMDAT、非零地址空间；
- 单字符串或总表超过预算；
- 大端目标。

处理原则：

1. 优先把只在模块内部使用的字符串改为内部链接；
2. 避免将同一个常量地址公开给外部 ABI；
3. 对必须放在特殊 section 的数据显式关闭 CSE，而不是绕过预检；
4. 不能安全改写的场景应保留明文或改用应用层运行时方案；
5. 不要为了通过构建删除严格检查。

## 4. 启动与全局构造验证

认证字符串在优先级 0 的模块构造函数中验签解密。项目测试应覆盖：

- C++ 全局对象构造函数读取字符串；
- JNI_OnLoad 读取字符串；
- 主线程和后台线程同时读取；
- 共享库重复加载/卸载；
- 正常退出时全局析构函数读取字符串；
- Android 进程直接终止（此时 dtor 可能不执行，这是平台生命周期，不是加密错误）。

## 5. 篡改测试

在测试签名 APK 或本地 ELF 副本中，对认证字符串表任意修改一个字节。预期行为：

```text
模块构造阶段验证失败
→ llvm.trap
→ 不进入普通全局构造函数、JNI_OnLoad 或 main
```

不要在生产包上手工篡改并重新签名作为唯一测试；CI 中应保留 `string-crypto-smoke`、`string-runtime-ir-smoke` 和 `string-pass-smoke`。

## 6. 明文生命周期

当前默认是模块级缓存：

```text
模块加载时解密
→ 生命周期内复用
→ 普通析构后 volatile 清零
```

这保持旧代码的稳定指针语义，但意味着明文可在运行期内存中被读取。授权根密钥、API 私钥、长期身份密钥不应作为普通字符串常量嵌入客户端。

## 7. 性能基线

迁移前后至少记录：

- `.so` 文件大小；
- 加密表大小；
- 模块加载时间；
- JNI_OnLoad 时间；
- RSS/私有脏页增量；
- 被保护字符串数量；
- 被跳过字符串及原因。

当前构造函数一次处理所有记录，适合兼容优先场景。字符串数量非常多时，应按模块拆分，或等待后续分组/惰性生命周期实现。

## 8. 安全边界

- 当前实现不是 Android Keystore；
- key share 可被高权限攻击者重建；
- 双 SipHash 标签阻止普通未授权修改静默执行，但不能阻止提取密钥后的重新签名；
- ChaCha20 保密性依赖 key/nonce 不复用；确定性构建域已经绑定明文指纹；
- 生产构建不要固定 `ALLVM_BUILD_SEED`；
- 需要不可导出长期密钥时，使用服务端或 Keystore。
