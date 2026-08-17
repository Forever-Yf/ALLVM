# ALLVM Android setup P5.2

本阶段增加 Android setup 规划器。

运行：

```bash
python3 tools/allvm_android_command.py ./MyApp --json
```

功能：

- 检测 Gradle；
- 检测 Kotlin DSL / Groovy DSL；
- 检测 CMake；
- 检测 ndk-build；
- 输出后续自动接入计划。

后续将实现：

```bash
allvm android setup
```

包括：

- SDK/NDK 自动发现；
- overlay 自动创建；
- Gradle 自动接入；
- CMake 自动接入；
- dry-run；
- rollback；
- report。
