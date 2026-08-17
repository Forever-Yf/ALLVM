# ALLVM 后续开发路线

> 统一开发分支：`allvm-development`

后续功能不再创建大量临时分支，统一在该分支持续演进，最终通过一个总 PR 合并。

## 已完成

- LLVM 安全随机源加固
- VMP 兼容性与运行时检查
- CLI 统一入口
- NDK overlay 管理
- 项目 sync/lock
- Gradle/CMake 接入基础
- ChaCha20-Poly1305 字符串保护 record-v2
- Android 项目自动检测基础

## 下一阶段

### 1. allvm android setup

目标：

```bash
allvm android setup
```

自动完成：

- Android SDK/NDK 检测
- 项目类型识别
- Gradle 接入
- CMake 接入
- overlay 创建
- 配置生成
- 验证构建

### 2. allvm report

生成保护报告：

- 字符串保护数量
- VMP 函数数量
- 跳过原因
- 二进制体积变化
- 性能影响

### 3. allvm analyze

根据项目特征生成保护建议：

- 敏感函数识别
- JNI 分析
- 字符串风险分析
- VMP 推荐等级

### 4. GUI 配置

提供本地界面管理：

- profile 选择
- NDK 管理
- 构建配置
- 报告查看

### 5. Android Studio 集成

最终目标：

右键 Native Module → Enable ALLVM Protection

## 开发原则

- 保持一个长期开发分支
- 每个阶段独立 commit
- 保持 CI 可验证
- 不破坏已有 Android 构建流程
- 默认安全，兼顾易用性
