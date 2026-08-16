#!/usr/bin/env python3
"""Run lightweight ALLVM hardening regression checks.

The checker uses only Python's standard library. It verifies that known weak
random paths have not returned, checks the Chinese documentation and safe build
helper defaults, and can compile/run SecureRandom.h against minimal LLVM stubs.
"""

from __future__ import annotations

import argparse
import json
import py_compile
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Result:
    name: str
    status: str
    detail: str


def read(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        raise FileNotFoundError(f"missing required file: {relative}")
    return path.read_text(encoding="utf-8")


def add(results: list[Result], name: str, ok: bool, detail: str) -> None:
    results.append(Result(name=name, status="PASS" if ok else "FAIL", detail=detail))


def contains_all(text: str, markers: Iterable[str]) -> tuple[bool, list[str]]:
    missing = [marker for marker in markers if marker not in text]
    return not missing, missing


def static_checks(results: list[Result]) -> None:
    crypto = read("llvm/lib/Transforms/Obfuscation/CryptoUtils.cpp")
    avmp = read("llvm/lib/Transforms/Obfuscation/aVMP.cpp")
    secure = read("llvm/include/llvm/Transforms/Obfuscation/SecureRandom.h")
    constant_int = read("llvm/lib/Transforms/Obfuscation/ConstantIntEncryption.cpp")
    constant_fp = read("llvm/lib/Transforms/Obfuscation/ConstantFPEncryption.cpp")
    string_pass = read("llvm/lib/Transforms/Obfuscation/StringEncryption.cpp")
    vmp_header = read("llvm/include/llvm/Transforms/Obfuscation/VMPCompatibility.h")
    vmp_preflight = read("llvm/lib/Transforms/Obfuscation/VMPCompatibility.cpp")
    vmp_smoke = read("tools/vmp-compatibility-smoke.cpp")
    build_helper = read("build.cpp")
    readme = read("README.md")
    hardening_doc = read("docs/ALLVM_HARDENING.md")

    weak_crypto = [
        marker
        for marker in ("std::mt19937", "system_clock::now", "std::ifstream")
        if marker in crypto
    ]
    add(
        results,
        "CryptoUtils 弱随机路径",
        not weak_crypto,
        "未发现时间种子或文件流随机路径"
        if not weak_crypto
        else "仍存在: " + ", ".join(weak_crypto),
    )

    required_crypto = (
        "allvm::fillSecureRandom",
        "allvm::secureClear",
        "explicit deterministic seed",
        "const uint32_t Threshold",
        "while (sofar < len)",
    )
    ok, missing = contains_all(crypto, required_crypto)
    add(
        results,
        "CryptoUtils 加固标记",
        ok,
        "系统 CSPRNG、清理和无偏范围逻辑存在"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    old_vmp = [
        marker
        for marker in ("srand(time(0))", "xorshift32_seed ^= rand()")
        if marker in avmp
    ]
    add(
        results,
        "旧版 VMP 弱种子",
        not old_vmp,
        "未发现 srand/time/rand 种子路径"
        if not old_vmp
        else "仍存在: " + ", ".join(old_vmp),
    )

    required_vmp = (
        "legacy-vmp|",
        "getModuleIdentifier()",
        "getName().str()",
        "seedCryptoUtils(RandomEngine, RandomDomain.c_str())",
        "while (Seed == 0)",
    )
    ok, missing = contains_all(avmp, required_vmp)
    add(
        results,
        "VMP 函数级域分离",
        ok,
        "模块和函数域分离存在" if ok else "缺少: " + ", ".join(missing),
    )


    vmp_limit_markers = (
        "uint64_t MaxBasicBlocks = 4096",
        "uint64_t MaxInstructions = 50000",
        "MaxCodeBytes = 16ULL * 1024ULL * 1024ULL",
        "MaxDataBytes = 16ULL * 1024ULL * 1024ULL",
        "analyzeVMPFunction",
    )
    ok, missing = contains_all(vmp_header, vmp_limit_markers)
    add(
        results,
        "VMP 默认资源限制",
        ok,
        "基本块、指令、代码和数据默认阈值存在"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    vmp_preflight_markers = (
        "PHI 节点",
        "原子指令",
        "直接递归",
        "可变参数调用",
        "undef/poison",
        "getStructLayout",
        "MaxBasicBlocks",
        "MaxInstructions",
        "MaxCodeBytes",
        "MaxDataBytes",
    )
    ok, missing = contains_all(vmp_preflight, vmp_preflight_markers)
    add(
        results,
        "VMP 兼容性预检",
        ok,
        "危险 IR、递归、ABI 和资源边界检查存在"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    vmp_integration_markers = (
        "irobf-vmp-max-bbs",
        "irobf-vmp-max-instructions",
        "irobf-vmp-max-code-bytes",
        "irobf-vmp-max-data-bytes",
        "irobf-vmp-strict",
        "analyzeVMPFunction",
        "checkActualResourceUsage",
        "setThreadLocal(true)",
        "verifyFunction(F, &errs())",
        "isa<ConstantPointerNull>(value)",
    )
    ok, missing = contains_all(avmp, vmp_integration_markers)
    add(
        results,
        "VMP 转换器防护",
        ok,
        "预检、实际资源检查、TLS 状态和 IR verifier 已接入"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    obsolete_vmp_markers = [
        marker
        for marker in ("#define VM_CODE_SEG_SIZE", "MAX_BASIC_BLOCKS")
        if marker in avmp
    ]
    add(
        results,
        "VMP 固定容量回归",
        not obsolete_vmp_markers,
        "未发现旧固定代码段或硬编码基本块上限"
        if not obsolete_vmp_markers
        else "仍存在: " + ", ".join(obsolete_vmp_markers),
    )

    timing_ok = avmp.count("prepareVMPFunction(F);") == 1
    if timing_ok:
        required_positions = (
            "if (!Interpreter.run())",
            "prepareVMPFunction(F);",
            "GOVMModifier Modifier",
        )
        if all(marker in avmp for marker in required_positions):
            timing_ok = (
                avmp.index(required_positions[0])
                < avmp.index(required_positions[1])
                < avmp.index(required_positions[2])
            )
        else:
            timing_ok = False
    add(
        results,
        "VMP 函数属性时机",
        timing_ok,
        "仅在翻译器和解释器成功后添加 noinline/optnone"
        if timing_ok
        else "VMP 属性可能污染跳过或失败的函数",
    )

    vmp_smoke_markers = (
        'getFunction("supported")',
        'getFunction("padded_gep")',
        'getFunction("with_phi")',
        'getFunction("atomic_load")',
        'getFunction("recursive")',
        'getFunction("variadic_call")',
        'getFunction("undef_value")',
        "TightLimits.MaxInstructions = 1",
    )
    ok, missing = contains_all(vmp_smoke, vmp_smoke_markers)
    add(
        results,
        "VMP IR 行为测试",
        ok,
        "支持、拒绝和资源超限场景均有可执行测试"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    required_secure = (
        "BCryptGenRandom",
        "BCRYPT_USE_SYSTEM_PREFERRED_RNG",
        "/dev/urandom",
        "ALLVM_BUILD_SEED",
        "fillSecureRandom",
        "secureClear",
    )
    ok, missing = contains_all(secure, required_secure)
    add(
        results,
        "跨平台安全随机入口",
        ok,
        "Windows/POSIX 与确定性入口存在"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    domains_ok = (
        'seedCryptoUtils(RandomEngine, "constant-int")' in constant_int
        and 'seedCryptoUtils(RandomEngine, "constant-fp")' in constant_fp
    )
    add(
        results,
        "常量 Pass 域分离",
        domains_ok,
        "整数和浮点 Pass 使用独立域"
        if domains_ok
        else "常量 Pass 域配置缺失",
    )

    string_markers = (
        'RandomDomain = "string-encryption|"',
        "seedCryptoUtils(RandomEngine, RandomDomain.c_str())",
        "RandomEngine.get_range(Span)",
        "secureClear(Buffer.data(), Buffer.size())",
        "secureClear(Entry->EncKey.data()",
        "static_assert(std::is_same_v<T, uint8_t>",
    )
    ok, missing = contains_all(string_pass, string_markers)
    add(
        results,
        "字符串 Pass 随机生命周期",
        ok,
        "模块域分离、无偏长度和临时缓冲清理存在"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    raw_string_buffers = [
        marker
        for marker in ("new char[Len * sizeof(T)]", "delete[] Buffer")
        if marker in string_pass
    ]
    add(
        results,
        "字符串 Pass 裸随机缓冲",
        not raw_string_buffers,
        "未发现裸 new[] 临时随机缓冲"
        if not raw_string_buffers
        else "仍存在: " + ", ".join(raw_string_buffers),
    )

    build_markers = (
        'get_env("ALLVM_NDK")',
        'get_env("ANDROID_NDK_HOME")',
        "find_side_by_side_ndk",
        'arg == "--install-into-ndk"',
        "[SAFE DEFAULT] Original NDK was not modified.",
        'arg == "--doctor-only"',
        "fopen_s",
    )
    ok, missing = contains_all(build_helper, build_markers)
    add(
        results,
        "构建助手安全默认值",
        ok,
        "NDK 自动发现、诊断、MSVC 安全文件入口和显式安装开关存在"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    unsafe_build_patterns = (
        "static bool replace_ndk_clang()",
        "if (!replace_ndk_clang())",
        'g_ndk_bin = g_script_dir + "\\\\android-ndk-r30-beta1-windows',
        "std::fopen",
    )
    found_unsafe = [marker for marker in unsafe_build_patterns if marker in build_helper]
    add(
        results,
        "构建助手覆盖 NDK 回归",
        not found_unsafe,
        "默认流程未发现隐式覆盖 NDK 或弃用文件入口"
        if not found_unsafe
        else "仍存在: " + ", ".join(found_unsafe),
    )

    readme_markers = (
        "ALLVM_BUILD_SEED",
        "安全能力与边界",
        "本加固分支做了什么",
        "16 KiB Android 页支持",
        "--install-into-ndk",
        "默认不会修改原 NDK",
        "VMP 兼容性预检",
        "-irobf-vmp-strict",
        "-irobf-vmp-max-code-bytes",
        "后续路线",
    )
    ok, missing = contains_all(readme, readme_markers)
    add(
        results,
        "中文 README",
        ok,
        "加固、使用、安全默认值和边界说明完整"
        if ok
        else "缺少: " + ", ".join(missing),
    )

    doc_markers = (
        "威胁模型",
        "CryptoUtils 修复",
        "旧版 VMP 随机化",
        "VMP 兼容性预检",
        "VMPResourceLimits",
        "构建助手",
        "验收标准",
        "仍需完成的高优先级改造",
    )
    ok, missing = contains_all(hardening_doc, doc_markers)
    add(
        results,
        "中文加固文档",
        ok,
        "威胁模型、构建安全、验证和路线图存在"
        if ok
        else "缺少: " + ", ".join(missing),
    )


def validate_python(results: list[Result]) -> None:
    targets = [
        ROOT / "tools" / "allvm-doctor.py",
        ROOT / "tools" / "check-hardening.py",
    ]
    try:
        for target in targets:
            py_compile.compile(str(target), doraise=True)
    except py_compile.PyCompileError as exc:
        add(results, "Python 工具语法", False, str(exc))
        return
    add(results, "Python 工具语法", True, "doctor 与检查器均通过 py_compile")


def compile_secure_random_header(results: list[Result], required: bool) -> None:
    compiler = shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
    if compiler is None:
        add(
            results,
            "SecureRandom.h 编译烟雾测试",
            not required,
            "未找到 C++ 编译器" + ("（当前模式要求编译器）" if required else "，已跳过"),
        )
        return

    crypto_stub = r'''#ifndef LLVM_CRYPTOUTILS_H
#define LLVM_CRYPTOUTILS_H
#include <cstddef>
#include <cstring>
#include <string>
namespace llvm {
class CryptoUtils {
public:
  int sha256(const char *Message, unsigned char *Output) {
    const std::size_t Length = std::strlen(Message);
    for (std::size_t I = 0; I < 32; ++I)
      Output[I] = static_cast<unsigned char>((I * 37U) ^ Length);
    return 0;
  }
  void prng_seed(const std::string &Value) { LastSeed = Value; }
  std::string LastSeed;
};
} // namespace llvm
#endif
'''

    error_stub = r'''#ifndef LLVM_SUPPORT_ERRORHANDLING_H
#define LLVM_SUPPORT_ERRORHANDLING_H
#include <stdexcept>
namespace llvm {
[[noreturn]] inline void report_fatal_error(const char *Message) {
  throw std::runtime_error(Message);
}
} // namespace llvm
#endif
'''

    test_source = r'''#include "llvm/Transforms/Obfuscation/SecureRandom.h"
#include <cstddef>
#include <cstdint>

int main() {
  std::uint8_t Bytes[32] = {};
  if (!llvm::allvm::fillSecureRandom(Bytes, sizeof(Bytes)))
    return 1;

  llvm::CryptoUtils Engine;
  llvm::allvm::seedCryptoUtils(Engine, "header-smoke");
  if (Engine.LastSeed.size() != 32)
    return 2;

  llvm::allvm::secureClear(Bytes, sizeof(Bytes));
  for (std::uint8_t Byte : Bytes) {
    if (Byte != 0)
      return 3;
  }
  return 0;
}
'''

    with tempfile.TemporaryDirectory(prefix="allvm-hardening-") as temp_text:
        temp = Path(temp_text)
        (temp / "llvm" / "Support").mkdir(parents=True)
        (temp / "llvm" / "CryptoUtils.h").write_text(crypto_stub, encoding="utf-8")
        (temp / "llvm" / "Support" / "ErrorHandling.h").write_text(
            error_stub, encoding="utf-8"
        )
        source = temp / "secure_random_smoke.cpp"
        binary = temp / "secure_random_smoke"
        source.write_text(test_source, encoding="utf-8")

        command = [
            compiler,
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(temp),
            "-I",
            str(ROOT / "llvm" / "include"),
            str(source),
            "-o",
            str(binary),
        ]
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
        )
        if completed.returncode != 0:
            add(
                results,
                "SecureRandom.h 编译烟雾测试",
                False,
                completed.stdout.strip() or f"编译退出码 {completed.returncode}",
            )
            return

        executed = subprocess.run(
            [str(binary)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
        add(
            results,
            "SecureRandom.h 编译烟雾测试",
            executed.returncode == 0,
            "C++17 编译与运行通过"
            if executed.returncode == 0
            else executed.stdout.strip() or f"运行退出码 {executed.returncode}",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--compile-header",
        action="store_true",
        help="require a local C++ compiler and compile/run SecureRandom.h smoke test",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    args = parser.parse_args()

    results: list[Result] = []
    try:
        static_checks(results)
        validate_python(results)
        compile_secure_random_header(results, required=args.compile_header)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        add(results, "检查器执行", False, str(exc))

    if args.json:
        print(
            json.dumps(
                {"results": [asdict(result) for result in results]},
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        width = max((len(result.name) for result in results), default=0)
        for result in results:
            print(f"[{result.status:4}] {result.name:<{width}}  {result.detail}")

    return 1 if any(result.status == "FAIL" for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
