#!/usr/bin/env python3
"""One-time fail-fast Chinese README update for the unified CLI."""

from pathlib import Path


path = Path("README.md")
text = path.read_text(encoding="utf-8")


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"README marker count is {count}, expected 1: {old[:120]!r}")
    text = text.replace(old, new, 1)


replace_once(
    "- **当前加固 PR**：`hardening/p0-secure-seeding-doctor`\n",
    "- **当前加固 PR**：`hardening/p0-secure-seeding-doctor`\n"
    "- **当前易用性分支**：`usability/p1-cli-presets-overlay`\n"
    "- **中文 CLI 指南**：[`docs/ALLVM_USAGE_CN.md`](docs/ALLVM_USAGE_CN.md)\n",
)

replace_once(
    "详细设计和后续路线见 [`docs/ALLVM_HARDENING.md`](docs/ALLVM_HARDENING.md)。\n\n"
    "## 安全能力与边界",
    "详细设计和后续路线见 [`docs/ALLVM_HARDENING.md`](docs/ALLVM_HARDENING.md)。\n\n"
    "## 统一 CLI 快速入口\n\n"
    "易用性分支新增了只依赖 Python 标准库的跨平台入口，最低支持 Python 3.9：\n\n"
    "```text\n"
    "allvm\n"
    "├── doctor       环境与 16 KiB ELF 诊断\n"
    "├── profile      查看 compat / balanced / strong 预设\n"
    "├── render       生成 CMake、ndk-build、shell、JSON 或响应文件参数\n"
    "├── init         在项目内生成 .allvm 配置与接入片段\n"
    "└── overlay      创建、校验和删除不修改源 NDK 的独立副本\n"
    "```\n\n"
    "仓库根目录入口：\n\n"
    "```bash\n"
    "python3 allvm.py --help\n"
    "python3 allvm.py profile list\n"
    "python3 allvm.py doctor --ndk /path/to/android-ndk\n"
    "```\n\n"
    "Windows：\n\n"
    "```powershell\n"
    ".\\allvm.ps1 profile list\n"
    ".\\allvm.ps1 doctor --ndk D:\\Android\\Sdk\\ndk\\29.0.14206865\n"
    "```\n\n"
    "推荐项目接入：\n\n"
    "```bash\n"
    "# 1. 初始化 CMake 和 ndk-build 片段\n"
    "python3 /path/to/ALLVM/allvm.py init \\\n"
    "  --directory . \\\n"
    "  --profile balanced \\\n"
    "  --build-system both\n\n"
    "# 2. 创建完整、独立的 NDK 副本，并只在副本中安装 ALLVM 编译器\n"
    "python3 /path/to/ALLVM/allvm.py overlay create \\\n"
    "  --ndk /path/to/android-ndk \\\n"
    "  --allvm-bin /path/to/ALLVM/build-windows/bin \\\n"
    "  --output ~/.allvm/ndk/r29-allvm\n\n"
    "# 3. 验证副本工具哈希和源 NDK 未发生变化\n"
    "python3 /path/to/ALLVM/allvm.py overlay verify \\\n"
    "  --path ~/.allvm/ndk/r29-allvm\n"
    "```\n\n"
    "Linux 的 `overlay create --mode auto` 优先请求写时复制，不支持时安全退回普通复制；Windows 和 macOS 使用完整复制。工具不会创建硬链接镜像，也不会直接覆盖源 NDK。完整说明见 [`docs/ALLVM_USAGE_CN.md`](docs/ALLVM_USAGE_CN.md)。\n\n"
    "## 安全能力与边界",
)

replace_once(
    "当前仓库的主要构建入口仍面向 Windows：\n",
    "LLVM/Clang/lld 的全量编译助手目前仍主要面向 Windows；统一 CLI、预设渲染、项目初始化、环境诊断和独立 NDK 管理可在 Windows、Linux 与 macOS 使用：\n",
)

replace_once(
    "LLVM 源码本身可在其他主机上构建，但仓库中的 `build.cpp` 仍是 Windows 专用助手。它已移除单一 NDK 和 Visual Studio Enterprise 的硬编码依赖，支持参数、环境变量、Android SDK side-by-side NDK 以及多个 Visual Studio 2022 版本；跨平台构建前端仍属于后续工作。",
    "LLVM 源码本身可在其他主机上构建，但仓库中的 `build.cpp` 仍是 Windows 专用的全量编译助手。它已移除单一 NDK 和 Visual Studio Enterprise 的硬编码依赖。跨平台的日常入口由 `allvm.py` 提供；它不会替代 LLVM 全量构建，而是统一诊断、预设、项目接入和隔离工具链管理。",
)

replace_once(
    "python3 tools/allvm-doctor.py --ndk /path/to/android-ndk",
    "python3 allvm.py doctor --ndk /path/to/android-ndk",
)

replace_once(
    "py tools/allvm-doctor.py --ndk D:\\Android\\Sdk\\ndk\\29.0.14206865",
    ".\\allvm.ps1 doctor --ndk D:\\Android\\Sdk\\ndk\\29.0.14206865",
)

replace_once(
    "python3 tools/allvm-doctor.py --json",
    "python3 allvm.py doctor --json",
)

replace_once(
    "python3 tools/allvm-doctor.py \\\n  --ndk /path/to/android-ndk \\\n  --elf app/build/intermediates/stripped_native_libs/release/out/lib/arm64-v8a/libexample.so",
    "python3 allvm.py doctor \\\n  --ndk /path/to/android-ndk \\\n  --elf app/build/intermediates/stripped_native_libs/release/out/lib/arm64-v8a/libexample.so",
)

replace_once(
    "git switch hardening/p0-secure-seeding-doctor",
    "git switch usability/p1-cli-presets-overlay",
)

replace_once(
    "> 即使使用显式开关，也只应操作专门为 ALLVM 准备的 NDK 副本。完整的独立 toolchain overlay 仍在后续路线中。",
    "> 即使使用显式开关，也只应操作专门为 ALLVM 准备的 NDK 副本。更推荐使用 `allvm.py overlay create`：它先创建完整独立副本，再只替换副本中的编译工具，并通过 manifest 和 SHA-256 校验源 NDK 未改变。",
)

replace_once(
    "## Android.mk 推荐配置\n\n所有 Pass 参数通过 `-mllvm` 传递。不要默认把全部保护同时打开，应按函数价值和性能预算选择。",
    "## 预设与构建系统生成\n\n"
    "优先通过 CLI 生成参数，避免手工维护几十个 `-mllvm`：\n\n"
    "```bash\n"
    "python3 allvm.py profile list\n"
    "python3 allvm.py render --profile compat --format cmake\n"
    "python3 allvm.py render --profile balanced --format ndk-build\n"
    "python3 allvm.py render --profile strong --format json\n"
    "```\n\n"
    "`init` 会生成：\n\n"
    "```text\n"
    ".allvm/\n"
    "├── allvm.json\n"
    "├── allvm-options.cmake\n"
    "├── allvm.mk\n"
    "└── README.md\n"
    "```\n\n"
    "CMake 目标创建后：\n\n"
    "```cmake\n"
    "include(${CMAKE_SOURCE_DIR}/.allvm/allvm-options.cmake)\n"
    "allvm_apply(your_native_target)\n"
    "```\n\n"
    "ndk-build 在 `CLEAR_VARS` 后、`BUILD_*` 前 include 生成的 `allvm.mk`。下面的手工配置继续保留，主要用于审计预设展开结果和高级定制。\n\n"
    "## Android.mk 推荐配置\n\n所有 Pass 参数通过 `-mllvm` 传递。不要默认把全部保护同时打开，应按函数价值和性能预算选择。",
)

path.write_text(text, encoding="utf-8")
