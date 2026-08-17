#!/usr/bin/env python3
"""Verify that vm.h embeds aVMPInterpreter.bc byte-for-byte.

The checker uses only Python's standard library.  LLVM symbol inspection is
performed separately in CI with llvm-dis so this script remains portable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BITCODE = ROOT / "aVMPInterpreter" / "aVMPInterpreter.bc"
DEFAULT_HEADER = (
    ROOT / "llvm" / "include" / "llvm" / "Transforms" / "Obfuscation" / "vm.h"
)


@dataclass
class Result:
    name: str
    status: str
    detail: str


def add(results: list[Result], name: str, ok: bool, detail: str) -> None:
    results.append(Result(name=name, status="PASS" if ok else "FAIL", detail=detail))


def decode_header(header_text: str) -> tuple[int | None, bytes | None, str | None]:
    length_match = re.search(r"binary_ir_length\s*=\s*(\d+)\s*;", header_text)
    if not length_match:
        return None, None, "missing binary_ir_length"

    marker = "static const char binary_ir_data[] ="
    if marker not in header_text:
        return int(length_match.group(1)), None, "missing binary_ir_data"

    block = header_text.split(marker, 1)[1].split(";", 1)[0]
    values = re.findall(r"\\x([0-9a-fA-F]{2})", block)
    if not values:
        return int(length_match.group(1)), None, "binary_ir_data has no hexadecimal bytes"

    return int(length_match.group(1)), bytes(int(value, 16) for value in values), None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcode", type=Path, default=DEFAULT_BITCODE)
    parser.add_argument("--header", type=Path, default=DEFAULT_HEADER)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    results: list[Result] = []
    try:
        bitcode = args.bitcode.resolve().read_bytes()
        header_text = args.header.resolve().read_text(encoding="utf-8")
    except OSError as exc:
        add(results, "读取嵌入产物", False, str(exc))
    else:
        add(
            results,
            "LLVM bitcode magic",
            bitcode.startswith(b"BC\xc0\xde"),
            "BC c0 de" if bitcode.startswith(b"BC\xc0\xde") else "invalid bitcode magic",
        )

        declared_length, embedded, error = decode_header(header_text)
        add(
            results,
            "vm.h 结构",
            error is None,
            "找到长度与十六进制数据" if error is None else str(error),
        )

        if declared_length is not None:
            add(
                results,
                "声明长度",
                declared_length == len(bitcode),
                f"declared={declared_length}, actual={len(bitcode)}",
            )

        if embedded is not None:
            add(
                results,
                "嵌入字节",
                embedded == bitcode,
                "vm.h 与 .bc 逐字节一致"
                if embedded == bitcode
                else f"embedded={len(embedded)}, actual={len(bitcode)}",
            )

        include_guard_ok = (
            "#ifndef ALLVM_EMBEDDED_VMP_IR_H" in header_text
            and "#define ALLVM_EMBEDDED_VMP_IR_H" in header_text
            and "#endif // ALLVM_EMBEDDED_VMP_IR_H" in header_text
        )
        add(
            results,
            "vm.h include guard",
            include_guard_ok,
            "include guard present" if include_guard_ok else "include guard missing",
        )

        digest = hashlib.sha256(bitcode).hexdigest()
        add(results, "bitcode SHA-256", True, digest)

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
