# ALLVM Android 自动接入（P5）

## 目标

将 ALLVM 从需要手动配置的 LLVM 加固工具，升级为 Android 项目可直接接入的平台。

## 当前阶段

P5 第一阶段提供项目发现能力：

```bash
python3 tools/android_setup.py ./MyApp --json
```

输出项目结构：

- Gradle 是否存在；
- Kotlin DSL 或 Groovy DSL；
- 是否存在 native 构建；
- 后续 overlay、CMake、ndk-build 和 Gradle 自动配置所需信息。

## 后续计划

### android setup

目标命令：

```bash
allvm android setup
```

自动完成：

1. 检测 Android SDK/NDK；
2. 创建独立 ALLVM NDK overlay；
3. 生成 `.allvm/allvm.json`；
4. 生成 Gradle/CMake 接入文件；
5. 提供 dry-run 预览；
6. 生成保护报告。

## 安全原则

自动化不会默认覆盖用户构建文件。

所有修改应：

- 可预览；
- 可回滚；
- 写入 lock；
- 保留原始配置。
