#!/usr/bin/env python3
"""Synchronize Chinese documentation with string-pass hardening."""

from pathlib import Path


def replace_once(path_text: str, old: str, new: str) -> None:
    path = Path(path_text)
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"expected one match in {path_text}, found {count}: {old[:100]!r}"
        )
    path.write_text(text.replace(old, new), encoding="utf-8")


def main() -> None:
    replace_once(
        "README.md",
        "- 常量整数、常量浮点和旧版 VMP 使用彼此独立的随机域；",
        "- 常量整数、常量浮点、字符串保护和旧版 VMP 使用彼此独立的随机域；\n"
        "- 字符串保护按模块派生随机序列，使用无偏长度选择，并清理编译期临时密钥缓冲；",
    )

    replace_once(
        "README.md",
        "| 字符串保护 | 编译期变换并在运行时还原 | 目前仍缺少标准 AEAD 完整性标签，属于后续重点 |",
        "| 字符串保护 | 按模块分离随机域、无偏选择密钥长度，并清理编译期临时缓冲 | 现有记录格式仍是自定义可逆变换，密钥与密文同驻二进制，尚无标准 AEAD 完整性标签 |",
    )

    replace_once(
        "README.md",
        '''构建根种子
├── constant-int
├── constant-fp
└── legacy-vmp | ModuleIdentifier | FunctionName''',
        '''构建根种子
├── constant-int
├── constant-fp
├── string-encryption | ModuleIdentifier
└── legacy-vmp | ModuleIdentifier | FunctionName''',
    )

    replace_once(
        "docs/ALLVM_HARDENING.md",
        '''BuildSeed（32 字节）
├── constant-int
├── constant-fp
└── legacy-vmp | ModuleIdentifier | FunctionName''',
        '''BuildSeed（32 字节）
├── constant-int
├── constant-fp
├── string-encryption | ModuleIdentifier
└── legacy-vmp | ModuleIdentifier | FunctionName''',
    )

    replace_once(
        "docs/ALLVM_HARDENING.md",
        '''- 显式包含 `unordered_map`，减少间接 include 依赖。

## 5. 旧版 VMP 随机化''',
        '''- 显式包含 `unordered_map`，减少间接 include 依赖。

### 字符串 Pass 随机生命周期

`StringEncryption.cpp` 现在按 `string-encryption | ModuleIdentifier` 派生独立随机序列，因此显式 `ALLVM_BUILD_SEED` 模式可以复现字符串保护，而不同模块不会意外共享同一序列。

同时完成：

- 使用 `CryptoUtils::get_range()` 无偏选择 8/16 位密钥和垃圾区长度，包含配置的最大值；
- 以 `std::vector<uint8_t>` 代替裸 `new[]` 临时随机缓冲；
- 使用后清理临时随机缓冲；
- Pass finalization 时清理编译进程内的字符串数据和密钥向量。

这些改动改善的是构建随机性、可复现性和编译期敏感数据生命周期。现有字符串记录仍使用自定义可逆变换，密钥与密文共同存放在二进制中，也没有认证标签，因此不能称为 AEAD；标准认证加密仍是后续独立改造。

## 5. 旧版 VMP 随机化''',
    )

    readme = Path("README.md").read_text(encoding="utf-8")
    docs = Path("docs/ALLVM_HARDENING.md").read_text(encoding="utf-8")
    for marker in (
        "string-encryption | ModuleIdentifier",
        "现有记录格式仍是自定义可逆变换",
    ):
        if marker not in readme:
            raise SystemExit(f"README string marker missing: {marker}")
    for marker in (
        "字符串 Pass 随机生命周期",
        "不能称为 AEAD",
    ):
        if marker not in docs:
            raise SystemExit(f"hardening document string marker missing: {marker}")


if __name__ == "__main__":
    main()
