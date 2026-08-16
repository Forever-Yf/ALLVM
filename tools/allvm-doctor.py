#!/usr/bin/env python3
"""Diagnose an ALLVM/Android NDK build environment.

The script uses only Python's standard library.  It discovers the NDK without
modifying it, verifies the host toolchain, and can inspect ELF LOAD-segment
alignment for Android 16 KiB page-size readiness.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional


@dataclass
class Check:
    name: str
    status: str
    detail: str


def add(checks: list[Check], name: str, ok: bool, detail: str, *, warn: bool = False) -> None:
    status = "PASS" if ok else ("WARN" if warn else "FAIL")
    checks.append(Check(name=name, status=status, detail=detail))


def executable(name: str) -> Optional[Path]:
    found = shutil.which(name)
    return Path(found).resolve() if found else None


def ndk_candidates(explicit: Optional[str]) -> Iterable[Path]:
    seen: set[Path] = set()

    def emit(value: Optional[str]) -> Iterable[Path]:
        if not value:
            return ()
        path = Path(value).expanduser().resolve()
        if path in seen:
            return ()
        seen.add(path)
        return (path,)

    yield from emit(explicit)
    yield from emit(os.environ.get("ANDROID_NDK_HOME"))
    yield from emit(os.environ.get("ANDROID_NDK_ROOT"))

    sdk_roots = [
        os.environ.get("ANDROID_SDK_ROOT"),
        os.environ.get("ANDROID_HOME"),
    ]
    if platform.system() == "Windows":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            sdk_roots.append(str(Path(local_app_data) / "Android" / "Sdk"))
    else:
        sdk_roots.extend(
            [
                str(Path.home() / "Android" / "Sdk"),
                str(Path.home() / "Library" / "Android" / "sdk"),
            ]
        )

    for root_text in sdk_roots:
        if not root_text:
            continue
        root = Path(root_text).expanduser().resolve()
        ndk_root = root / "ndk"
        if ndk_root.is_dir():
            versions = sorted(
                (entry for entry in ndk_root.iterdir() if entry.is_dir()),
                key=lambda entry: entry.name,
                reverse=True,
            )
            for version in versions:
                yield from emit(str(version))
        yield from emit(str(root / "ndk-bundle"))


def resolve_ndk(explicit: Optional[str]) -> Optional[Path]:
    for candidate in ndk_candidates(explicit):
        if (candidate / "source.properties").is_file() and (
            candidate / "toolchains" / "llvm" / "prebuilt"
        ).is_dir():
            return candidate
    return None


def read_ndk_revision(ndk: Path) -> str:
    properties = ndk / "source.properties"
    for line in properties.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("Pkg.Revision"):
            return line.partition("=")[2].strip()
    return "unknown"


def host_tag() -> Optional[str]:
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Windows":
        return "windows-x86_64"
    if system == "Linux":
        return "linux-x86_64"
    if system == "Darwin":
        return "darwin-arm64" if machine in {"arm64", "aarch64"} else "darwin-x86_64"
    return None


def locate_toolchain_bin(ndk: Path) -> Optional[Path]:
    prebuilt = ndk / "toolchains" / "llvm" / "prebuilt"
    preferred = host_tag()
    if preferred and (prebuilt / preferred / "bin").is_dir():
        return prebuilt / preferred / "bin"

    bins = sorted(path / "bin" for path in prebuilt.iterdir() if (path / "bin").is_dir())
    return bins[0] if bins else None


def tool_in(directory: Path, name: str) -> Optional[Path]:
    suffixes = [".exe", ""] if platform.system() == "Windows" else [""]
    for suffix in suffixes:
        candidate = directory / f"{name}{suffix}"
        if candidate.is_file():
            return candidate
    return None


def run_version(path: Path) -> str:
    try:
        completed = subprocess.run(
            [str(path), "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable: {exc}"
    first = completed.stdout.splitlines()
    return first[0].strip() if first else f"exit {completed.returncode}"


def find_readelf(toolchain_bin: Optional[Path]) -> Optional[Path]:
    if toolchain_bin:
        candidate = tool_in(toolchain_bin, "llvm-readelf")
        if candidate:
            return candidate
    return executable("llvm-readelf") or executable("readelf")


def inspect_elf(path: Path, readelf: Optional[Path], checks: list[Check]) -> None:
    if not path.is_file():
        add(checks, "ELF input", False, f"file not found: {path}")
        return

    try:
        with path.open("rb") as stream:
            magic = stream.read(5)
    except OSError as exc:
        add(checks, "ELF input", False, f"cannot read {path}: {exc}")
        return

    if len(magic) < 5 or magic[:4] != b"\x7fELF":
        add(checks, "ELF input", False, f"not an ELF file: {path}")
        return

    elf_class = {1: "ELF32", 2: "ELF64"}.get(magic[4], f"unknown class {magic[4]}")
    add(checks, "ELF input", True, f"{path} ({elf_class})")

    if readelf is None:
        add(
            checks,
            "16 KiB ELF alignment",
            False,
            "llvm-readelf/readelf not found; alignment inspection skipped",
            warn=True,
        )
        return

    try:
        completed = subprocess.run(
            [str(readelf), "-lW", str(path)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        add(checks, "16 KiB ELF alignment", False, str(exc))
        return

    if completed.returncode != 0:
        add(
            checks,
            "16 KiB ELF alignment",
            False,
            f"{readelf.name} exited with {completed.returncode}: {completed.stdout.strip()}",
        )
        return

    alignments: list[int] = []
    for line in completed.stdout.splitlines():
        if not re.match(r"^\s*LOAD\s+", line):
            continue
        last_token = line.split()[-1]
        try:
            alignments.append(int(last_token, 0))
        except ValueError:
            continue

    if not alignments:
        add(checks, "16 KiB ELF alignment", False, "no LOAD program headers were parsed")
        return

    minimum = min(alignments)
    detail = "LOAD p_align values: " + ", ".join(f"0x{value:x}" for value in alignments)
    add(checks, "16 KiB ELF alignment", minimum >= 0x4000, detail)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", help="explicit Android NDK directory")
    parser.add_argument("--elf", type=Path, help="optional ELF file to inspect")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()

    checks: list[Check] = []
    add(checks, "Python", sys.version_info >= (3, 9), sys.version.split()[0])

    for name in ("cmake", "ninja", "java", "adb"):
        found = executable(name)
        add(
            checks,
            name,
            found is not None,
            str(found) if found else "not found on PATH",
            warn=name in {"java", "adb"},
        )

    ndk = resolve_ndk(args.ndk)
    add(
        checks,
        "Android NDK",
        ndk is not None,
        f"{ndk} (revision {read_ndk_revision(ndk)})" if ndk else "not found",
    )

    toolchain_bin: Optional[Path] = None
    if ndk:
        toolchain_bin = locate_toolchain_bin(ndk)
        add(
            checks,
            "NDK host toolchain",
            toolchain_bin is not None,
            str(toolchain_bin) if toolchain_bin else "no compatible prebuilt host directory",
        )
        if toolchain_bin:
            for name in ("clang", "clang++", "ld.lld"):
                found = tool_in(toolchain_bin, name)
                detail = f"{found}: {run_version(found)}" if found else f"missing from {toolchain_bin}"
                add(checks, f"NDK {name}", found is not None, detail)

    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        add(checks, "Host page size", True, f"{page_size} bytes")
    except (AttributeError, OSError, ValueError):
        add(checks, "Host page size", False, "not available on this host", warn=True)

    if args.elf:
        inspect_elf(args.elf.resolve(), find_readelf(toolchain_bin), checks)

    if args.json:
        print(json.dumps({"checks": [asdict(check) for check in checks]}, ensure_ascii=False, indent=2))
    else:
        width = max(len(check.name) for check in checks)
        for check in checks:
            print(f"[{check.status:4}] {check.name:<{width}}  {check.detail}")

    return 1 if any(check.status == "FAIL" for check in checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())
