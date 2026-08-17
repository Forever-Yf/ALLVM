# Android setup planner P5.2

## 命令

```bash
python3 tools/allvm_android_command.py ./MyApp --json
```

## 当前能力

- Gradle 检测
- Kotlin DSL 检测
- Groovy DSL 检测
- CMake 检测
- ndk-build 检测
- 自动生成接入动作计划

## 设计原则

当前阶段只读，不修改工程。

后续 `allvm android setup` 将增加：

- NDK 自动发现；
- overlay 创建；
- Gradle/CMake 修改；
- dry-run；
- rollback。
