#!/usr/bin/env python3
"""Run source-level ALLVM hardening regression checks.

The checker intentionally uses only Python's standard library. It verifies
security capabilities and dangerous-regression absence without depending on
incidental local variable names. Cryptographic vectors and complete LLVM
execution are covered by the permanent GitHub workflows.
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


def require(
    results: list[Result],
    name: str,
    text: str,
    markers: Iterable[str],
    success: str,
) -> None:
    missing = [marker for marker in markers if marker not in text]
    add(results, name, not missing, success if not missing else "缺少: " + ", ".join(missing))


def forbid(
    results: list[Result],
    name: str,
    text: str,
    markers: Iterable[str],
    success: str,
) -> None:
    found = [marker for marker in markers if marker in text]
    add(results, name, not found, success if not found else "仍存在: " + ", ".join(found))


def static_checks(results: list[Result]) -> None:
    crypto = read("llvm/lib/Transforms/Obfuscation/CryptoUtils.cpp")
    secure = read("llvm/include/llvm/Transforms/Obfuscation/SecureRandom.h")
    constant_int = read("llvm/lib/Transforms/Obfuscation/ConstantIntEncryption.cpp")
    constant_fp = read("llvm/lib/Transforms/Obfuscation/ConstantFPEncryption.cpp")

    string_pass = read("llvm/lib/Transforms/Obfuscation/StringEncryption.cpp")
    string_crypto = read("llvm/include/llvm/Transforms/Obfuscation/AuthenticatedStringCrypto.h")
    string_ir = read("llvm/lib/Transforms/Obfuscation/AuthenticatedStringIR.cpp")
    cmake = read("llvm/lib/Transforms/Obfuscation/CMakeLists.txt")
    strong = read("configs/profiles/strong.json")
    string_tests = "\n".join(
        read(path)
        for path in (
            "tools/string-crypto-smoke.cpp",
            "tools/string-runtime-ir-smoke.cpp",
            "tools/string-pass-smoke.cpp",
        )
    )

    avmp = read("llvm/lib/Transforms/Obfuscation/aVMP.cpp")
    vmp_preflight = read("llvm/lib/Transforms/Obfuscation/VMPCompatibility.cpp")
    vmp_integrity = read("aVMPInterpreter/VMPIntegrity.h")
    interpreter_header = read("aVMPInterpreter/aVMPInterpreter.h")
    interpreter = read("aVMPInterpreter/aVMPInterpreter.c")
    vmp_tests = read("tools/vmp-interpreter-bounds-smoke.c")
    embed_checker = read("tools/check-vmp-embed.py")
    embedded_header = read("llvm/include/llvm/Transforms/Obfuscation/vm.h")

    build = read("build.cpp")
    readme = read("README.md")
    hardening_doc = read("docs/ALLVM_HARDENING.md")
    string_doc = read("docs/AUTHENTICATED_STRINGS_CN.md")

    forbid(
        results,
        "CryptoUtils 弱随机路径",
        crypto,
        ("std::mt19937", "system_clock::now", "srand(", "rand()"),
        "未发现时间、MT 或 rand 随机回退",
    )
    require(
        results,
        "CryptoUtils 加固",
        crypto,
        (
            "allvm::fillSecureRandom",
            "allvm::secureClear",
            "explicit deterministic seed",
            "const uint32_t Threshold",
            "while (sofar < len)",
        ),
        "系统 CSPRNG、显式种子、敏感清理和无偏范围逻辑存在",
    )
    require(
        results,
        "SecureRandom 构建根",
        secure,
        (
            "BCryptGenRandom",
            '::open("/dev/urandom"',
            "ALLVM_BUILD_SEED",
            "ALLVM-build-seed-v1|",
            "secureClear",
        ),
        "Windows/POSIX CSPRNG、构建根和域分离存在",
    )
    require(
        results,
        "常量保护独立域",
        constant_int + constant_fp,
        (
            'seedCryptoUtils(RandomEngine, "constant-int")',
            'seedCryptoUtils(RandomEngine, "constant-fp")',
        ),
        "整数和浮点常量保护使用独立随机域",
    )

    forbid(
        results,
        "旧字符串可逆变换回归",
        string_pass,
        (
            "previousPlainChar",
            "case 0: // XOR",
            "case 1: // NOT",
            "StringEncryptionKey",
            "EncryptedStringTable->setSection",
        ),
        "未发现旧 XOR/取反/反馈记录实现",
    )
    require(
        results,
        "认证字符串密码原语",
        string_crypto,
        (
            "ALLVM_STR_HEADER_SIZE 48U",
            "allvm_str_chacha_block",
            "allvm_str_chacha_xor_split",
            "allvm_str_sip_round",
            "allvm_str_tag",
            "allvm_str_open_record_split",
            "allvm_str_zero",
        ),
        "ChaCha20、双 SipHash、split-key、验签和失败清零存在",
    )
    require(
        results,
        "认证字符串记录绑定",
        string_crypto,
        (
            "expected_id",
            "expected_offset",
            "expected_flags",
            "expected_size",
            "ALLVM_STR_NONCE_OFFSET",
            "ALLVM_STR_TAG0_OFFSET",
            "ALLVM_STR_TAG1_OFFSET",
            "ALLVM_STR_CIPHERTEXT_OFFSET",
        ),
        "ID、偏移、类型、长度、nonce、标签和密文均进入验证路径",
    )
    require(
        results,
        "认证字符串 Pass 集成",
        string_pass,
        (
            "bool runOnModule(Module &) override { return false; }",
            "bool doFinalization(Module &M) override",
            "string-record-layout|",
            "string-record-key|",
            "string-record-mask|",
            "recordFingerprint",
            "__allvm_authenticated_string_table",
            "appendToGlobalCtors(M, Ctor, 0)",
            "appendToGlobalDtors(M, Dtor, 0)",
            "RemapInstruction",
            "eraseOriginalStrings",
            "secureClear",
            "verifyModule",
        ),
        "finalization、域分离、早期验签、晚期清理、重映射和 verifier 存在",
    )
    require(
        results,
        "认证字符串候选预检",
        string_pass,
        (
            "hasLocalLinkage",
            "isThreadLocal",
            "hasComdat",
            "hasSection",
            "getAddressSpace() != 0",
            "CSE-disabled function",
            "irobf-cse-max-record-bytes",
            "irobf-cse-max-table-bytes",
            "irobf-cse-strict",
        ),
        "链接、TLS、section、地址空间、用户链和资源边界检查存在",
    )
    require(
        results,
        "认证字符串 LLVM 运行时",
        string_ir,
        (
            "__allvm_string_open_v1",
            "__allvm_str_chacha_block_v1",
            "__allvm_str_chacha_xor_v1",
            "__allvm_str_tag_v1",
            "CreateMemSet",
            "TagDiff",
            "NoInline",
            "OptimizeNone",
        ),
        "生成式 ChaCha/SipHash/open 运行时和失败清理存在",
    )
    require(
        results,
        "认证字符串正式构建",
        cmake,
        ("AuthenticatedStringIR.cpp", "StringEncryption.cpp"),
        "CMake 编译认证运行时和规范 StringEncryption.cpp",
    )
    forbid(
        results,
        "认证字符串过渡源回归",
        cmake,
        ("StringEncryptionAuthenticated.cpp", "StringEncryptionAuthenticatedV2.cpp"),
        "正式构建未引用过渡源",
    )
    require(
        results,
        "strong 字符串安全预设",
        strong,
        (
            "-irobf-cse-strict",
            "-irobf-cse-max-record-bytes=1048576",
            "-irobf-cse-max-table-bytes=67108864",
            "-irobf-cse-wipe-at-exit",
            "-irobf-cse-verify",
        ),
        "严格模式、记录/表预算、卸载清理和 verifier 已启用",
    )
    require(
        results,
        "认证字符串可执行测试",
        string_tests,
        (
            "testChaChaVector",
            "testRecordRoundTrip",
            "testHeaderBindingAndUtf16",
            "allvm_str_open_record_split",
            "getOrCreateAuthenticatedStringOpen",
            "createStringEncryptionPass",
            "doFinalization",
            "__allvm_authenticated_string_table",
            'containsPlaintext(*Table, "hello")',
        ),
        "密码向量、篡改、LLVM runtime 和完整 Pass 产物均有测试",
    )

    forbid(
        results,
        "VMP 弱种子回归",
        avmp,
        ("srand(time(0))", "xorshift32_seed ^= rand()", "#define VM_CODE_SEG_SIZE"),
        "未发现 rand/time 或旧固定 code 段",
    )
    require(
        results,
        "VMP 域分离和预算",
        avmp,
        (
            "legacy-vmp-layout|",
            "legacy-vmp-integrity|",
            "irobf-vmp-max-bbs",
            "irobf-vmp-max-instructions",
            "irobf-vmp-max-code-bytes",
            "irobf-vmp-max-data-bytes",
            "irobf-vmp-max-runtime-steps",
            "irobf-vmp-max-runtime-calls",
            "irobf-vmp-max-call-depth",
            "irobf-vmp-strict",
        ),
        "布局/认证域及编译期/运行时预算存在",
    )
    require(
        results,
        "VMP 兼容性预检",
        vmp_preflight,
        (
            "MaxBasicBlocks",
            "MaxInstructions",
            "MaxCodeBytes",
            "MaxDataBytes",
            "PHI 节点",
            "原子指令",
            "直接递归",
            "可变参数调用",
            "getStructLayout",
            "PointerSize != 8",
        ),
        "危险 IR、ABI、递归和资源检查存在",
    )
    require(
        results,
        "VMP 分块认证",
        vmp_integrity + avmp,
        (
            "VMP_BLOCK_HEADER_SIZE",
            "VMP_BLOCK_MAGIC",
            "vmp_integrity_block_tags",
            "vmp_integrity_tag_equal",
            "seal_vm_blocks",
        ),
        "共享双标签块格式和翻译器封装存在",
    )
    require(
        results,
        "VMP 解释器 fail-closed",
        interpreter_header + interpreter,
        (
            "VM_FAULT_INTEGRITY",
            "VM_FAULT_STEP_LIMIT",
            "VM_FAULT_CALL_LIMIT",
            "VM_FAULT_CALL_DEPTH",
            "VM_FAULT_REENTRANT",
            "VM_FAULT_BLOCK_RANGE",
            "vm_enter_block",
            "vm_consume_budget",
            "vm_fail_closed",
            "data_seg_clean",
        ),
        "认证、预算、重入、边界和清理 fault 路径存在",
    )
    require(
        results,
        "VMP 原生测试",
        vmp_tests,
        (
            "test_integrity_known_vector",
            "test_authenticated_block_tamper",
            "test_block_local_boundary",
            "test_opcode_collision_sequence",
            "test_step_budget",
            "test_call_budget",
            "test_call_depth_limit",
            "test_reentrant_guard",
        ),
        "认证、边界、碰撞和预算场景存在",
    )
    require(
        results,
        "VMP 嵌入产物检查",
        embed_checker + embedded_header,
        (
            'bitcode.startswith(b"BC\\xc0\\xde")',
            "embedded == bitcode",
            "binary_ir_length",
            "ALLVM_EMBEDDED_VMP_IR_H",
            "hashlib.sha256",
        ),
        "bitcode magic、长度、逐字节一致性和摘要检查存在",
    )

    forbid(
        results,
        "构建助手隐式覆盖回归",
        build,
        ("static bool replace_ndk_clang()", "if (!replace_ndk_clang())", "std::fopen"),
        "未发现旧自动覆盖入口；仓库内旧 NDK 名称仅作为显式发现 fallback",
    )
    require(
        results,
        "构建助手安全默认值",
        build,
        (
            "--install-into-ndk",
            "Explicit installation into dedicated NDK copy",
            "Use only a dedicated NDK copy",
            "ANDROID_NDK_HOME",
            "ANDROID_NDK_ROOT",
            "vswhere",
            ".bak",
        ),
        "只有显式安装才写入专用副本，并保留环境发现和备份",
    )

    require(
        results,
        "中文 README",
        readme,
        (
            "认证字符串记录",
            "ChaCha20",
            "两个独立 SipHash-2-4 标签",
            "-irobf-cse-strict",
            "-irobf-cse-max-record-bytes",
            "明文会在模块生命周期内缓存",
            "VMP",
            "allvm sync",
            "overlay update",
            "当前仍未完成",
        ),
        "字符串/VMP/CLI 能力、参数、边界和未完成项存在",
    )
    require(
        results,
        "中文加固文档",
        hardening_doc,
        (
            "威胁模型",
            "认证字符串记录",
            "Encrypt-then-MAC",
            "Pass 执行顺序",
            "分块认证",
            "自动化验收",
            "仍需真实环境验证",
            "后续优先级",
        ),
        "威胁模型、实现、验收、边界和路线存在",
    )
    require(
        results,
        "认证字符串专项文档",
        string_doc,
        (
            "目标与非目标",
            "密码结构",
            "记录格式",
            "key share",
            "编译期流程",
            "运行时生命周期",
            "自动化测试",
            "后续路线",
        ),
        "专项威胁模型、格式、生命周期和测试说明存在",
    )


def validate_python(results: list[Result]) -> None:
    targets = [
        ROOT / "tools" / "allvm.py",
        ROOT / "tools" / "allvm-doctor.py",
        ROOT / "tools" / "check-hardening.py",
        ROOT / "tools" / "check-vmp-embed.py",
    ]
    try:
        for target in targets:
            py_compile.compile(str(target), doraise=True)
    except (py_compile.PyCompileError, OSError) as exc:
        add(results, "Python 工具语法", False, str(exc))
        return
    add(results, "Python 工具语法", True, "CLI、doctor、加固和嵌入检查器通过 py_compile")


def compile_secure_random_header(results: list[Result], required: bool) -> None:
    compiler = shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
    if compiler is None:
        add(
            results,
            "SecureRandom.h 编译烟雾测试",
            not required,
            "未找到 C++ 编译器" + ("（当前模式要求）" if required else "，已跳过"),
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
}
#endif
'''
    error_stub = r'''#ifndef LLVM_SUPPORT_ERRORHANDLING_H
#define LLVM_SUPPORT_ERRORHANDLING_H
#include <stdexcept>
namespace llvm {
[[noreturn]] inline void report_fatal_error(const char *Message) {
  throw std::runtime_error(Message);
}
}
#endif
'''
    test_source = r'''#include "llvm/Transforms/Obfuscation/SecureRandom.h"
#include <cstddef>
#include <cstdint>
int main() {
  std::uint8_t Bytes[32] = {};
  if (!llvm::allvm::fillSecureRandom(Bytes, sizeof(Bytes))) return 1;
  llvm::CryptoUtils Engine;
  llvm::allvm::seedCryptoUtils(Engine, "header-smoke");
  if (Engine.LastSeed.size() != 32) return 2;
  llvm::allvm::secureClear(Bytes, sizeof(Bytes));
  for (std::uint8_t Byte : Bytes) if (Byte != 0) return 3;
  return 0;
}
'''

    with tempfile.TemporaryDirectory(prefix="allvm-hardening-") as temporary:
        temp = Path(temporary)
        (temp / "llvm" / "Support").mkdir(parents=True)
        (temp / "llvm" / "CryptoUtils.h").write_text(crypto_stub, encoding="utf-8")
        (temp / "llvm" / "Support" / "ErrorHandling.h").write_text(error_stub, encoding="utf-8")
        source = temp / "secure_random_smoke.cpp"
        binary = temp / "secure_random_smoke"
        source.write_text(test_source, encoding="utf-8")
        completed = subprocess.run(
            [
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
            ],
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
    parser.add_argument("--compile-header", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    results: list[Result] = []
    try:
        static_checks(results)
        validate_python(results)
        compile_secure_random_header(results, required=args.compile_header)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        add(results, "检查器执行", False, str(exc))

    if args.json:
        print(json.dumps({"results": [asdict(item) for item in results]}, ensure_ascii=False, indent=2))
    else:
        width = max((len(item.name) for item in results), default=0)
        for item in results:
            print(f"[{item.status:4}] {item.name:<{width}}  {item.detail}")

    return 1 if any(item.status == "FAIL" for item in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
