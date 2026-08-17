# ALLVM 统一 CLI 与项目接入指南

本文档面向希望快速接入 ALLVM 的 Android/C/C++ 项目。新入口将环境诊断、保护预设、CMake/ndk-build 参数生成和独立 NDK 副本管理集中到一个跨平台命令行中。

```text
allvm
├── doctor            环境与 ELF 诊断
├── profile           查看兼容、平衡和高强度预设
├── render            输出 shell/CMake/ndk-build/Gradle/JSON/响应文件参数
├── init              在项目中生成 .allvm 配置和接入片段
├── sync              原子刷新生成文件、维护 lock、CI 检查过期
└── overlay           创建、状态、增量更新、校验和删除独立 NDK
```

CLI 只使用 Python 标准库，最低支持 Python 3.9。它不会直接修改源 Android NDK。

## 1. 启动方式

仓库根目录提供多种入口，实际都调用 `tools/allvm.py`。

### Windows CMD

```bat
allvm.cmd --version
allvm.cmd profile list
```

### PowerShell

```powershell
.\allvm.ps1 --version
.\allvm.ps1 profile list
```

### Linux/macOS

```bash
python3 allvm.py --version
python3 allvm.py profile list
```

也可以直接调用：

```bash
python3 tools/allvm.py --help
```

## 2. 推荐接入流程

### 第一步：诊断环境

```bash
python3 allvm.py doctor --ndk /path/to/android-ndk
```

Windows：

```powershell
.\allvm.ps1 doctor --ndk D:\Android\Sdk\ndk\29.0.14206865
```

该命令复用 `tools/allvm-doctor.py`，检查：

- Python、CMake 和 Ninja；
- Java、ADB；
- Android NDK 版本；
- 主机对应的 NDK LLVM prebuilt；
- `clang`、`clang++` 和 `ld.lld`；
- 主机页大小；
- 可选 ELF 的 16 KiB `PT_LOAD` 对齐。

机器可读输出：

```bash
python3 allvm.py doctor --json
```

检查编译后的 `.so`：

```bash
python3 allvm.py doctor \
  --ndk /path/to/android-ndk \
  --elf app/build/intermediates/stripped_native_libs/release/out/lib/arm64-v8a/libexample.so
```

### 第二步：选择保护预设

```bash
python3 allvm.py profile list
python3 allvm.py profile show balanced
```

内置三档：

| 预设 | 适用场景 | 默认内容 |
|---|---|---|
| `compat` | 首次接入、普通模块、兼容优先 | 字符串、常量和低强度间接调用 |
| `balanced` | 授权、协议和核心业务模块 | 在 `compat` 上增加间接全局变量、控制流平坦化和间接分支 |
| `strong` | 少量高价值、低频函数 | 三级保护及严格、选择性 VMP；只处理显式 `annotate("vmp")` 的函数 |

预设文件位于：

```text
configs/profiles/compat.json
configs/profiles/balanced.json
configs/profiles/strong.json
```

它们是普通 JSON，可以复制后作为自定义预设使用：

```bash
python3 allvm.py render \
  --profile /path/to/my-profile.json \
  --format cmake
```

### 第三步：构建 ALLVM 编译器

Windows 可继续使用现有构建助手：

```powershell
cl /std:c++17 /EHsc /utf-8 build.cpp /Fe:build.exe
.\build.exe --ndk D:\Android\Sdk\ndk\29.0.14206865 --doctor
```

默认产物目录：

```text
build-windows/bin
```

不要使用默认行为去覆盖原始 NDK。下面的 `overlay create` 会生成独立副本。

### 第四步：创建独立 NDK 副本

Linux/macOS：

```bash
python3 allvm.py overlay create \
  --ndk /opt/android-ndk-r29 \
  --allvm-bin build-windows/bin \
  --output ~/.allvm/ndk/r29-allvm
```

PowerShell：

```powershell
.\allvm.ps1 overlay create `
  --ndk D:\Android\Sdk\ndk\29.0.14206865 `
  --allvm-bin D:\src\ALLVM\build-windows\bin `
  --output D:\Android\ALLVM\ndk-29
```

行为：

1. 校验源 NDK 和 ALLVM 编译器目录；
2. 创建一个完整、独立的 NDK 副本；
3. 只在副本中替换 `clang`、`clang++`、`ld.lld` 和可用的 `lld`；
4. 记录源工具和 ALLVM 工具的 SHA-256；
5. 写入 `.allvm-overlay.json`；
6. 创建后立即校验源 NDK 未改变、目标工具哈希正确。

Linux 的默认 `--mode auto` 会优先请求文件系统写时复制：

```text
cp -a --reflink=auto
```

文件系统不支持时由 `cp` 自动退回普通复制。Windows/macOS 默认使用安全的完整复制。CLI **不会使用硬链接**，避免对副本的原地写入联动修改源 NDK。

强制普通复制：

```bash
python3 allvm.py overlay create ... --mode copy
```

Linux 强制要求写时复制命令可用：

```bash
python3 allvm.py overlay create ... --mode reflink
```

校验：

```bash
python3 allvm.py overlay verify --path ~/.allvm/ndk/r29-allvm
```

查看综合状态和可选逻辑大小：

```bash
python3 allvm.py overlay status \
  --path ~/.allvm/ndk/r29-allvm \
  --size
```

重新编译 ALLVM 主机工具后，无需复制整个 NDK，只更新副本中的工具：

```bash
python3 allvm.py overlay update \
  --path ~/.allvm/ndk/r29-allvm \
  --allvm-bin /path/to/new/allvm/bin \
  --dry-run
python3 allvm.py overlay update \
  --path ~/.allvm/ndk/r29-allvm \
  --allvm-bin /path/to/new/allvm/bin
```

`update` 会先验证源 NDK 哈希；源工具发生变化时拒绝更新。省略 `--allvm-bin` 时使用 manifest 中记录的目录。查看原始 manifest：

```bash
python3 allvm.py overlay info --path ~/.allvm/ndk/r29-allvm
```

删除时必须同时满足：

- 目录内存在有效 `.allvm-overlay.json`；
- manifest 表明这是 ALLVM overlay；
- 显式传入 `--yes`。

```bash
python3 allvm.py overlay remove \
  --path ~/.allvm/ndk/r29-allvm \
  --yes
```

`--force` 重建也只允许删除带有效 manifest 标记的旧 overlay，不会删除任意用户目录。

### 第五步：让构建系统使用独立 NDK

Linux/macOS：

```bash
export ANDROID_NDK_HOME="$HOME/.allvm/ndk/r29-allvm"
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
```

PowerShell：

```powershell
$env:ANDROID_NDK_HOME = "D:\Android\ALLVM\ndk-29"
$env:ANDROID_NDK_ROOT = $env:ANDROID_NDK_HOME
```

Gradle 也可以在项目 `local.properties` 中指向该副本：

```properties
ndk.dir=D\:\\Android\\ALLVM\\ndk-29
```

对于使用 Android Gradle Plugin 的新项目，更推荐在模块配置中指定与副本一致的 NDK 版本和 SDK 路径管理方式，而不是在仓库中提交个人绝对路径。

### 第六步：初始化项目配置

在原生项目根目录执行：

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

已存在非空 `.allvm` 时默认拒绝覆盖：

```bash
python3 allvm.py init --directory . --profile compat --force
```

`--force` 只初始化 `.allvm`，不会修改项目其他文件。日常修改只编辑 `allvm.json`，然后运行：

```bash
python3 allvm.py sync --directory .
python3 allvm.py sync --directory . --check
```

`sync` 原子刷新选择的生成文件和 `allvm.lock.json`。`--check` 不写文件，缺失、过期或存在可安全删除的旧生成文件时返回 1，适合 CI。切换 `generate` 后，未修改的旧生成文件会自动删除；用户改过的旧生成文件会保留并报错。

## 3. CMake 接入

初始化：

```bash
python3 /path/to/ALLVM/allvm.py init \
  --directory . \
  --profile balanced \
  --build-system cmake
```

在目标创建之后加入：

```cmake
add_library(native-lib SHARED native-lib.cpp)

include(${CMAKE_SOURCE_DIR}/.allvm/allvm-options.cmake)
allvm_apply(native-lib)
```

生成文件包含：

```cmake
ALLVM_COMPILE_OPTIONS
ALLVM_CXX_OPTIONS
ALLVM_LINK_OPTIONS
allvm_apply(target)
```

`allvm_apply()` 会检查目标是否存在，然后通过 `target_compile_options()` 和 `target_link_options()` 以 `PRIVATE` 作用域应用参数。

不初始化项目也可以直接生成：

```bash
python3 allvm.py render \
  --profile balanced \
  --format cmake \
  --output .allvm/allvm-options.cmake \
  --force
```

## 4. ndk-build 接入

初始化：

```bash
python3 /path/to/ALLVM/allvm.py init \
  --directory . \
  --profile compat \
  --build-system ndk-build
```

在 `Android.mk` 中：

```makefile
include $(CLEAR_VARS)
LOCAL_MODULE := native-lib
LOCAL_SRC_FILES := native-lib.cpp

include $(LOCAL_PATH)/../.allvm/allvm.mk

include $(BUILD_SHARED_LIBRARY)
```

实际相对路径取决于 `Android.mk` 和项目根目录的位置。生成的 `allvm.mk` 将通用参数写入 `LOCAL_CFLAGS`，C++ 专用参数写入 `LOCAL_CPPFLAGS`，链接参数写入 `LOCAL_LDFLAGS`。

直接输出到终端：

```bash
python3 allvm.py render --profile strong --format ndk-build
```

## 5. Gradle/Android Studio 接入

CLI 不直接改写 `build.gradle` 或 `build.gradle.kts`。初始化时使用：

```bash
python3 allvm.py init \
  --directory . \
  --profile balanced \
  --build-system cmake \
  --gradle both
```

Kotlin DSL 模块在 plugins 块之后加入：

```kotlin
apply(from = rootProject.file(".allvm/allvm.gradle.kts"))
```

Groovy DSL：

```groovy
apply from: rootProject.file('.allvm/allvm.gradle')
```

生成片段按顺序读取：

```text
-Pallvm.ndkPath
ALLVM_NDK_HOME
ANDROID_NDK_HOME
ANDROID_NDK_ROOT
```

找到路径后设置 Android Gradle Plugin 的 `ndkPath`。个人绝对路径不会写进仓库；保护参数仍由 `allvm-options.cmake` 或 `allvm.mk` 管理。Gradle 原生构建继续使用模块已有的 `externalNativeBuild.cmake` 或 `externalNativeBuild.ndkBuild` 配置。

也可单独渲染：

```bash
python3 allvm.py render --profile balanced --format gradle-kts
python3 allvm.py render --profile balanced --format gradle-groovy
```

## 6. 参数渲染格式
## 6. 参数渲染格式

```bash
python3 allvm.py render --profile balanced --format FORMAT
```

| 格式 | 用途 |
|---|---|
| `json` | 工具集成、审计和 CI |
| `cmake` | 可 include 的 CMake 文件 |
| `ndk-build` | 可 include 的 Android.mk 片段 |
| `gradle-kts` | 可 apply 的 Kotlin DSL NDK 选择片段 |
| `gradle-groovy` | 可 apply 的 Groovy DSL NDK 选择片段 |
| `shell` | POSIX shell 参数 |
| `powershell` | PowerShell 参数 |
| `rsp` | 一行一个参数的响应文件 |
| `lines` | 调试、脚本和差分检查 |

默认只渲染通用编译参数。可选范围：

```bash
--scope compile
--scope cxx
--scope link
--scope all
```

示例：

```bash
python3 allvm.py render \
  --profile strong \
  --format rsp \
  --scope compile \
  --output build/allvm.rsp \
  --force
```

## 7. 项目 `allvm.json`

`init` 生成的配置：

```json
{
  "schema": 1,
  "profile": "balanced",
  "generate": ["cmake", "ndk-build", "gradle-kts"],
  "extra_compile_options": [],
  "remove_compile_options": [],
  "extra_cxx_options": [],
  "remove_cxx_options": [],
  "extra_link_options": [],
  "remove_link_options": []
}
```

追加参数：

```json
{
  "schema": 1,
  "profile": "balanced",
  "extra_compile_options": [
    "-DALLVM_PROJECT_BUILD=1"
  ],
  "remove_compile_options": [
    "-irobf-fla"
  ],
  "extra_cxx_options": [],
  "remove_cxx_options": [],
  "extra_link_options": [],
  "remove_link_options": []
}
```

`-mllvm` 参数在内部按两个 token 作为一个逻辑组处理。因此移除：

```json
"remove_compile_options": ["-irobf-fla"]
```

会同时移除前面的 `-mllvm`，不会留下孤立参数。出于安全考虑，不能单独写：

```json
"remove_compile_options": ["-mllvm"]
```

从项目配置重新生成：

```bash
python3 allvm.py render \
  --config .allvm/allvm.json \
  --format cmake \
  --output .allvm/allvm-options.cmake \
  --force
```

以及：

```bash
python3 allvm.py render \
  --config .allvm/allvm.json \
  --format ndk-build \
  --output .allvm/allvm.mk \
  --force
```

当前 `init --force` 会按命令行指定的预设重新创建默认配置。若只修改了 `allvm.json`，应使用 `render --config` 刷新生成文件，以免覆盖自定义项。

## 8. VMP 函数标记

`strong` 预设启用 VMP Pass，但仍只处理显式标记的函数：

```cpp
#if defined(__clang__)
#define ALLVM_VMP __attribute__((annotate("vmp")))
#else
#define ALLVM_VMP
#endif

ALLVM_VMP
bool verify_license(const unsigned char *data, unsigned long size) {
    // 仅放置经过兼容性预检和性能评估的高价值逻辑
    return size > 0 && data != nullptr;
}
```

建议顺序：

1. 全项目先用 `compat`；
2. 对通过回归的模块升级为 `balanced`；
3. 只对少量函数添加 `annotate("vmp")`；
4. 最后切换 `strong` 并在 CI 中保持严格模式。

## 9. CI 建议

最小 CI：

```bash
python3 allvm.py profile list
python3 allvm.py sync --directory . --check
python3 allvm.py render --profile balanced --format json > allvm-flags.json
python3 allvm.py overlay status --path "$ANDROID_NDK_HOME" --json
python3 allvm.py overlay verify --path "$ANDROID_NDK_HOME"
python3 allvm.py doctor --ndk "$ANDROID_NDK_HOME"
```

构建完成后增加：

```bash
python3 allvm.py doctor \
  --ndk "$ANDROID_NDK_HOME" \
  --elf path/to/libexample.so
```

不要在 CI 日志输出生产 `ALLVM_BUILD_SEED`。需要可复现回归时，从 CI secret 注入，不要把值写入 `allvm.json`。

## 10. 常见问题

### `profile list` 显示为空

确保保留了仓库结构：

```text
tools/allvm.py
configs/profiles/*.json
```

不要只复制单个 `tools/allvm.py` 文件。自定义部署可以通过 `--profile /absolute/path/profile.json` 指定 JSON。

### Windows 输出中文乱码

CLI 会主动把标准输出和错误输出切换为 UTF-8。旧终端仍可能需要：

```bat
chcp 65001
```

PowerShell 7 和 Windows Terminal 通常无需额外设置。

### overlay 很大

Android NDK 本身较大。Linux 的 `--mode auto` 会优先使用写时复制；Windows 默认完整复制，以换取“修改副本不会影响源 NDK”的安全属性。可以把 overlay 放到支持压缩或重复数据删除的开发盘，但不要改成硬链接镜像。

### `--force` 拒绝重建目录

这是预期行为。只有带有效 `.allvm-overlay.json` 的目录才能被 `overlay create --force` 删除。对普通目录必须人工处理，CLI 不会猜测其内容是否可删除。

### 是否可以继续使用 `build.exe --install-into-ndk`

可以，但只应面向专用 NDK 副本。新流程优先推荐：

```text
原始 NDK
→ allvm overlay create
→ 得到独立 NDK
→ Gradle/CMake/ndk-build 指向独立 NDK
```

## 11. 安全边界

易用性工具不会改变已有保护的安全边界：

- `compat`、`balanced` 和 `strong` 是可审计参数集合，不是安全等级证明；
- 客户端中的字符串和认证密钥仍可能被高权限攻击者提取；
- overlay 解决的是环境隔离和可恢复性，不会让编译器或 NDK 自动可信；
- 高价值长期秘密仍应位于服务端或 Android Keystore；
- 每次升级 NDK、LLVM、AGP 或目标 API 后都应重新运行兼容性、性能和 4 KiB/16 KiB 页测试。
