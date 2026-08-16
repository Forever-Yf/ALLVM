#!/usr/bin/env python3
"""Apply exact follow-up edits after the build helper rewrite."""

from pathlib import Path


def replace_once(path_text: str, old: str, new: str) -> None:
    path = Path(path_text)
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"expected exactly one match in {path_text}, found {count}: {old[:80]!r}"
        )
    path.write_text(text.replace(old, new), encoding="utf-8")


def main() -> None:
    replace_once(
        "build.cpp",
        "#include <fstream>\n#include <sstream>",
        "#include <fstream>\n#include <functional>\n#include <iterator>\n#include <sstream>",
    )

    replace_once(
        "README.md",
        "- 新增 GitHub Actions 烟雾检查，防止弱随机路径回归。",
        "- 新增 GitHub Actions 烟雾检查，防止弱随机路径回归；\n"
        "- Windows 构建助手支持显式 NDK、环境变量和 SDK side-by-side NDK 发现，默认不会修改原 NDK。",
    )

    replace_once(
        "README.md",
        "LLVM 源码本身可在其他主机上构建，但仓库中的 `build.cpp` 仍包含 Windows 专用路径和批处理调用，尚未完成跨平台重构。",
        "LLVM 源码本身可在其他主机上构建，但仓库中的 `build.cpp` 仍是 Windows 专用助手。它已移除单一 NDK 和 Visual Studio Enterprise 的硬编码依赖，支持参数、环境变量、Android SDK side-by-side NDK 以及多个 Visual Studio 2022 版本；跨平台构建前端仍属于后续工作。",
    )

    replace_once(
        "README.md",
        '''### 2. 编译工具链

仓库保留原有 Windows 构建入口：

```powershell
.\\build.exe
```

也可以从 `build.cpp` 重新生成构建程序：

```powershell
cl /std:c++17 /EHsc /utf-8 build.cpp /Fe:build.exe
.\\build.exe
```

> [!WARNING]
> 当前 `build.cpp` 在完整构建流程末尾仍会调用 `replace_ndk_clang()`：它会先生成 `.bak`，随后把部分 OLLVM 工具复制进所配置的 NDK。请只对专门用于 ALLVM 的 NDK 副本执行该操作，不要直接对日常开发或生产 NDK 运行。后续版本会改为独立 toolchain overlay，默认不修改原 NDK。''',
        '''### 2. 编译工具链

先查看构建助手参数：

```powershell
.\\build.exe --help
```

推荐先运行诊断，再开始构建：

```powershell
.\\build.exe `
  --ndk D:\\Android\\Sdk\\ndk\\29.0.14206865 `
  --doctor
```

也可以只诊断环境而不构建：

```powershell
.\\build.exe `
  --ndk D:\\Android\\Sdk\\ndk\\29.0.14206865 `
  --doctor-only
```

也可以从 `build.cpp` 重新生成构建程序：

```powershell
cl /std:c++17 /EHsc /utf-8 build.cpp /Fe:build.exe
.\\build.exe --ndk D:\\Android\\Sdk\\ndk\\29.0.14206865
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
> 构建助手默认不会修改原 NDK。编译完成的工具保留在 `build-windows\\bin`。只有显式传入 `--install-into-ndk` 才会把工具复制到 NDK，并在首次复制前创建 `.bak`：
>
> ```powershell
> .\\build.exe `
>   --ndk D:\\Android\\ALLVM-NDK-COPY `
>   --install-into-ndk
> ```
>
> 即使使用显式开关，也只应操作专门为 ALLVM 准备的 NDK 副本。完整的独立 toolchain overlay 仍在后续路线中。''',
    )

    replace_once(
        "README.md",
        "| `tools/allvm-doctor.py` | 环境和 ELF 诊断工具 |\n| `.github/workflows/hardening-smoke.yml` | 加固回归烟雾检查 |",
        "| `build.cpp` | Windows 构建助手、NDK 发现和显式安装入口 |\n"
        "| `tools/allvm-doctor.py` | 环境和 ELF 诊断工具 |\n"
        "| `tools/check-hardening.py` | 弱随机、文档和安全默认值回归检查 |\n"
        "| `.github/workflows/hardening-smoke.yml` | 加固回归烟雾检查 |",
    )

    replace_once(
        "README.md",
        "4. 将 `build.cpp` 改为显式 NDK 参数和独立 toolchain overlay；",
        "4. 在现有显式 NDK 和安全默认值基础上实现完整的独立 toolchain overlay，彻底取消向 NDK 复制工具；",
    )

    replace_once(
        "docs/ALLVM_HARDENING.md",
        '''诊断工具不会修改 NDK。

## 7. 当前自动化验证''',
        '''诊断工具不会修改 NDK。

## 7. 构建助手

`build.cpp` 已完成第一轮易用性和环境隔离改造：

- 支持 `--ndk <path>`；
- 支持 `ALLVM_NDK`、`ANDROID_NDK_HOME`、`ANDROID_NDK_ROOT`；
- 可从 `ANDROID_SDK_ROOT`、`ANDROID_HOME` 和 Windows 默认 SDK 目录发现 side-by-side NDK；
- 可识别 Visual Studio 2022 Enterprise、Professional、Community、Build Tools，并使用 `vswhere` 兜底；
- 支持 `--doctor` 和 `--doctor-only`；
- 默认把产物保留在 `build-windows\\bin`，不会修改原 NDK；
- 只有显式 `--install-into-ndk` 才执行复制，并为原文件创建 `.bak`；
- 对目标 triple 和并行任务数进行输入校验。

当前仍是 Windows 专用构建助手，且显式安装模式本质上仍会复制文件。长期方案是独立 toolchain overlay，并通过 CMake、Gradle 或 ndk-build 显式选择编译器。

## 8. 当前自动化验证''',
    )

    replace_once(
        "docs/ALLVM_HARDENING.md",
        '''- 编译检查 `tools/allvm-doctor.py`；
- 验证 `--help` 入口；
- 检查安全随机头文件包含 Windows 与 POSIX 路径；
- 阻止常量保护、`CryptoUtils` 和旧版 VMP 重新引入弱随机调用；
- 检查 README 中的确定性种子和安全边界说明。''',
        '''- 编译检查 `tools/allvm-doctor.py` 和 `tools/check-hardening.py`；
- 验证 doctor 的 `--help` 入口；
- 编译并运行 `SecureRandom.h` 的最小 C++17 烟雾测试；
- 检查安全随机头文件包含 Windows 与 POSIX 路径；
- 阻止常量保护、`CryptoUtils` 和旧版 VMP 重新引入弱随机调用；
- 检查构建助手保持“默认不修改 NDK”；
- 在 Windows runner 上使用 MSVC 编译 `build.cpp`；
- 检查中文 README 中的确定性种子、安全默认值和安全边界说明。''',
    )

    replace_once(
        "docs/ALLVM_HARDENING.md",
        "## 8. 验收标准",
        "## 9. 验收标准",
    )
    replace_once(
        "docs/ALLVM_HARDENING.md",
        "## 9. 仍需完成的高优先级改造",
        "## 10. 仍需完成的高优先级改造",
    )
    replace_once(
        "docs/ALLVM_HARDENING.md",
        "7. `build.cpp` 改为显式 NDK 参数和独立 toolchain overlay，默认禁止修改原 NDK。",
        "7. 在现有显式 NDK 和安全默认值基础上实现完整 toolchain overlay，移除向 NDK 复制工具的兼容模式。",
    )
    replace_once(
        "docs/ALLVM_HARDENING.md",
        "## 10. 安全结论",
        "## 11. 安全结论",
    )

    readme = Path("README.md").read_text(encoding="utf-8")
    docs = Path("docs/ALLVM_HARDENING.md").read_text(encoding="utf-8")
    build = Path("build.cpp").read_text(encoding="utf-8")
    for marker in ("默认不会修改原 NDK", "--install-into-ndk", "ALLVM_NDK"):
        if marker not in readme:
            raise SystemExit(f"README marker missing: {marker}")
    if "## 7. 构建助手" not in docs:
        raise SystemExit("hardening document build-helper section missing")
    for include in ("#include <functional>", "#include <iterator>"):
        if include not in build:
            raise SystemExit(f"build helper include missing: {include}")


if __name__ == "__main__":
    main()
