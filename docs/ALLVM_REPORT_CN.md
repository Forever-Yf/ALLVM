# ALLVM 保护报告

## 当前版本

`tools/allvm_report.py` 提供第一版项目级报告框架。

运行：

```bash
python3 tools/allvm_report.py .
```

JSON：

```bash
python3 tools/allvm_report.py . --json
```

## 当前信息来源

报告读取：

```text
.allvm/allvm.json
.allvm/allvm.lock.json
```

当前展示：

- 使用的保护 profile；
- 已生成构建文件数量；
- 字符串保护配置状态；
- VMP 配置状态。

## 后续增强

后续 LLVM pass 接入计数器后，将增加：

- 加密字符串数量；
- 跳过字符串数量及原因；
- VMP 函数数量；
- 跳过函数原因；
- 二进制体积变化；
- 构建时间变化；
- 启动性能影响。
