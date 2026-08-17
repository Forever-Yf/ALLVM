#!/usr/bin/env python3
"""ALLVM cross-platform command line entrypoint.

The CLI uses only Python's standard library. It centralizes environment
inspection, protection profiles, build-system snippets, project initialization,
and creation of an isolated Android NDK copy containing the ALLVM compiler.
The source NDK is never modified.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence


VERSION = "0.2.0"
ROOT = Path(__file__).resolve().parents[1]
PROFILES_DIR = ROOT / "configs" / "profiles"
OVERLAY_MANIFEST = ".allvm-overlay.json"
PROJECT_CONFIG = "allvm.json"


class CliError(RuntimeError):
    """A user-facing command failure."""


@dataclass(frozen=True)
class Profile:
    schema: int
    name: str
    title: str
    description: str
    compile_options: tuple[str, ...]
    cxx_options: tuple[str, ...]
    link_options: tuple[str, ...]
    notes: tuple[str, ...]
    source: Path

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "compile_options": list(self.compile_options),
            "cxx_options": list(self.cxx_options),
            "link_options": list(self.link_options),
            "notes": list(self.notes),
            "source": str(self.source),
        }


@dataclass(frozen=True)
class EffectiveOptions:
    profile: Profile
    compile_options: tuple[str, ...]
    cxx_options: tuple[str, ...]
    link_options: tuple[str, ...]
    config: Optional[Path]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": 1,
            "profile": self.profile.name,
            "title": self.profile.title,
            "description": self.profile.description,
            "compile_options": list(self.compile_options),
            "cxx_options": list(self.cxx_options),
            "link_options": list(self.link_options),
            "notes": list(self.profile.notes),
            "profile_source": str(self.profile.source),
            "config": str(self.config) if self.config else None,
        }


@dataclass(frozen=True)
class Verification:
    name: str
    ok: bool
    detail: str


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def eprint(*values: object) -> None:
    print(*values, file=sys.stderr)


def load_json(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CliError(f"文件不存在：{path}") from exc
    except OSError as exc:
        raise CliError(f"无法读取 {path}：{exc}") from exc
    except json.JSONDecodeError as exc:
        raise CliError(
            f"JSON 格式错误：{path}:{exc.lineno}:{exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(value, dict):
        raise CliError(f"JSON 根节点必须是对象：{path}")
    return value


def string_list(value: Any, *, field: str, source: Path) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise CliError(f"{source} 的 {field} 必须是字符串数组")
    if any("\x00" in item for item in value):
        raise CliError(f"{source} 的 {field} 不能包含 NUL 字符")
    return tuple(value)


def write_text(path: Path, text: str, *, force: bool) -> None:
    path = path.expanduser().resolve()
    if path.exists() and not force:
        raise CliError(f"输出已存在；使用 --force 覆盖：{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        newline="\n",
        dir=str(path.parent),
        prefix=f".{path.name}.",
        delete=False,
    ) as stream:
        temporary = Path(stream.name)
        stream.write(text)
    try:
        os.replace(temporary, path)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise


def write_json(path: Path, value: Mapping[str, Any], *, force: bool) -> None:
    write_text(
        path,
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        force=force,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def executable(name: str) -> Optional[Path]:
    result = shutil.which(name)
    return Path(result).resolve() if result else None


# ---------------------------------------------------------------------------
# Protection profiles and project configuration
# ---------------------------------------------------------------------------


def profile_path(name_or_path: str) -> Path:
    explicit = Path(name_or_path).expanduser()
    if explicit.is_file():
        return explicit.resolve()
    if any(separator in name_or_path for separator in ("/", "\\")) or name_or_path.endswith(
        ".json"
    ):
        raise CliError(f"找不到配置文件：{explicit}")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name_or_path):
        raise CliError(f"非法预设名称：{name_or_path!r}")
    result = PROFILES_DIR / f"{name_or_path}.json"
    if not result.is_file():
        available = ", ".join(available_profile_names()) or "无"
        raise CliError(f"未知预设 {name_or_path!r}；可用预设：{available}")
    return result.resolve()


def available_profile_names() -> list[str]:
    if not PROFILES_DIR.is_dir():
        return []
    return sorted(path.stem for path in PROFILES_DIR.glob("*.json") if path.is_file())


def load_profile(name_or_path: str) -> Profile:
    path = profile_path(name_or_path)
    value = load_json(path)
    schema = value.get("schema")
    if schema != 1:
        raise CliError(f"不支持的预设 schema：{path} 中为 {schema!r}，期望 1")

    required_text = ("name", "title", "description")
    for field in required_text:
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise CliError(f"{path} 缺少非空字符串字段 {field}")

    compile_options = string_list(value.get("compile_options"), field="compile_options", source=path)
    cxx_options = string_list(value.get("cxx_options"), field="cxx_options", source=path)
    link_options = string_list(value.get("link_options"), field="link_options", source=path)
    notes = string_list(value.get("notes"), field="notes", source=path)

    index = 0
    while index < len(compile_options):
        if compile_options[index] == "-mllvm":
            if index + 1 >= len(compile_options):
                raise CliError(f"{path} 的 compile_options 以孤立的 -mllvm 结尾")
            index += 2
        else:
            index += 1

    return Profile(
        schema=1,
        name=value["name"],
        title=value["title"],
        description=value["description"],
        compile_options=compile_options,
        cxx_options=cxx_options,
        link_options=link_options,
        notes=notes,
        source=path,
    )


def option_groups(options: Sequence[str]) -> list[tuple[str, ...]]:
    groups: list[tuple[str, ...]] = []
    index = 0
    while index < len(options):
        if options[index] == "-mllvm" and index + 1 < len(options):
            groups.append((options[index], options[index + 1]))
            index += 2
        else:
            groups.append((options[index],))
            index += 1
    return groups


def merge_options(
    base: Sequence[str],
    additions: Sequence[str],
    removals: Sequence[str],
) -> tuple[str, ...]:
    removal_set = {item.strip() for item in removals if item.strip()}
    if "-mllvm" in removal_set:
        raise CliError("remove_*_options 不能单独移除 -mllvm；请写具体参数")

    result: list[str] = []
    for group in option_groups(base):
        joined = " ".join(group)
        if joined in removal_set or any(token in removal_set for token in group):
            continue
        result.extend(group)
    result.extend(additions)
    return tuple(result)


def load_effective_options(
    *, profile_name: Optional[str], config_path: Optional[Path]
) -> EffectiveOptions:
    config: Mapping[str, Any] = {}
    resolved_config: Optional[Path] = None
    if config_path:
        resolved_config = config_path.expanduser().resolve()
        config = load_json(resolved_config)
        if config.get("schema") != 1:
            raise CliError(
                f"不支持的项目配置 schema：{resolved_config} 中为 {config.get('schema')!r}"
            )

    selected = profile_name or config.get("profile") or "balanced"
    if not isinstance(selected, str):
        raise CliError("项目配置 profile 必须是字符串")
    profile = load_profile(selected)

    def config_list(field: str) -> tuple[str, ...]:
        return string_list(config.get(field), field=field, source=resolved_config or Path("<config>"))

    compile_options = merge_options(
        profile.compile_options,
        config_list("extra_compile_options"),
        config_list("remove_compile_options"),
    )
    cxx_options = merge_options(
        profile.cxx_options,
        config_list("extra_cxx_options"),
        config_list("remove_cxx_options"),
    )
    link_options = merge_options(
        profile.link_options,
        config_list("extra_link_options"),
        config_list("remove_link_options"),
    )
    return EffectiveOptions(
        profile=profile,
        compile_options=compile_options,
        cxx_options=cxx_options,
        link_options=link_options,
        config=resolved_config,
    )


def cmake_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace(";", "\\;")


def cmake_set(name: str, values: Sequence[str]) -> list[str]:
    lines = [f"set({name}"]
    lines.extend(f'  "{cmake_escape(value)}"' for value in values)
    lines.append(")")
    return lines


def render_cmake(options: EffectiveOptions) -> str:
    lines = [
        "# Generated by tools/allvm.py. Regenerate instead of editing by hand.",
        f'set(ALLVM_PROFILE "{cmake_escape(options.profile.name)}")',
        "",
    ]
    lines.extend(cmake_set("ALLVM_COMPILE_OPTIONS", options.compile_options))
    lines.append("")
    lines.extend(cmake_set("ALLVM_CXX_OPTIONS", options.cxx_options))
    lines.append("")
    lines.extend(cmake_set("ALLVM_LINK_OPTIONS", options.link_options))
    lines.extend(
        [
            "",
            "function(allvm_apply target)",
            "  if(NOT TARGET \"${target}\")",
            "    message(FATAL_ERROR \"allvm_apply: target does not exist: ${target}\")",
            "  endif()",
            "  target_compile_options(\"${target}\" PRIVATE ${ALLVM_COMPILE_OPTIONS})",
            "  foreach(_allvm_cxx_option IN LISTS ALLVM_CXX_OPTIONS)",
            "    target_compile_options(\"${target}\" PRIVATE",
            "      \"$<$<COMPILE_LANGUAGE:CXX>:${_allvm_cxx_option}>\")",
            "  endforeach()",
            "  if(ALLVM_LINK_OPTIONS)",
            "    target_link_options(\"${target}\" PRIVATE ${ALLVM_LINK_OPTIONS})",
            "  endif()",
            "endfunction()",
            "",
        ]
    )
    return "\n".join(lines)


def make_escape(value: str) -> str:
    return value.replace("$", "$$").replace("#", "\\#")


def make_assignment(name: str, values: Sequence[str]) -> list[str]:
    if not values:
        return [f"# {name}: 当前预设没有额外参数"]
    lines = [f"{name} += \\"]
    for index, value in enumerate(values):
        suffix = " \\" if index + 1 < len(values) else ""
        lines.append(f"  {make_escape(value)}{suffix}")
    return lines


def render_ndk_build(options: EffectiveOptions) -> str:
    lines = [
        "# Generated by tools/allvm.py. Include after CLEAR_VARS and before BUILD_*.",
        f"ALLVM_PROFILE := {make_escape(options.profile.name)}",
        "",
    ]
    lines.extend(make_assignment("LOCAL_CFLAGS", options.compile_options))
    lines.append("")
    lines.extend(make_assignment("LOCAL_CPPFLAGS", options.cxx_options))
    lines.append("")
    lines.extend(make_assignment("LOCAL_LDFLAGS", options.link_options))
    lines.append("")
    return "\n".join(lines)


def powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def scoped_options(options: EffectiveOptions, scope: str) -> tuple[str, ...]:
    if scope == "compile":
        return options.compile_options
    if scope == "cxx":
        return options.cxx_options
    if scope == "link":
        return options.link_options
    return options.compile_options + options.cxx_options + options.link_options


def render_options(options: EffectiveOptions, output_format: str, scope: str) -> str:
    values = scoped_options(options, scope)
    if output_format == "json":
        return json.dumps(options.as_dict(), ensure_ascii=False, indent=2) + "\n"
    if output_format == "cmake":
        return render_cmake(options)
    if output_format == "ndk-build":
        return render_ndk_build(options)
    if output_format == "shell":
        return shlex.join(values) + "\n"
    if output_format == "powershell":
        return " ".join(powershell_quote(value) for value in values) + "\n"
    if output_format == "rsp":
        return "\n".join(subprocess.list2cmdline([value]) for value in values) + "\n"
    if output_format == "lines":
        return "\n".join(values) + "\n"
    raise CliError(f"未知输出格式：{output_format}")


# ---------------------------------------------------------------------------
# NDK discovery and isolated overlay copy
# ---------------------------------------------------------------------------


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
    yield from emit(os.environ.get("ALLVM_NDK"))
    yield from emit(os.environ.get("ANDROID_NDK_HOME"))
    yield from emit(os.environ.get("ANDROID_NDK_ROOT"))

    sdk_roots = [os.environ.get("ANDROID_SDK_ROOT"), os.environ.get("ANDROID_HOME")]
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
        versions = root / "ndk"
        if versions.is_dir():
            for candidate in sorted(versions.iterdir(), key=lambda item: item.name, reverse=True):
                if candidate.is_dir():
                    yield from emit(str(candidate))
        yield from emit(str(root / "ndk-bundle"))


def resolve_ndk(explicit: Optional[str]) -> Path:
    for candidate in ndk_candidates(explicit):
        if (candidate / "source.properties").is_file() and (
            candidate / "toolchains" / "llvm" / "prebuilt"
        ).is_dir():
            return candidate
    raise CliError("未找到 Android NDK；请使用 --ndk 或设置 ANDROID_NDK_HOME")


def read_ndk_revision(ndk: Path) -> str:
    try:
        lines = (ndk / "source.properties").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        return "unknown"
    for line in lines:
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


def locate_prebuilt(ndk: Path) -> Path:
    root = ndk / "toolchains" / "llvm" / "prebuilt"
    preferred = host_tag()
    if preferred and (root / preferred / "bin").is_dir():
        return root / preferred
    choices = sorted(path for path in root.iterdir() if (path / "bin").is_dir())
    if not choices:
        raise CliError(f"NDK 中没有可用的 LLVM prebuilt：{root}")
    return choices[0]


def host_tool_name(name: str) -> str:
    return f"{name}.exe" if platform.system() == "Windows" else name


def find_tool(directory: Path, name: str) -> Optional[Path]:
    candidates = [directory / host_tool_name(name), directory / name]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def clone_ndk(source: Path, destination: Path, requested_mode: str) -> str:
    if requested_mode in {"auto", "reflink"} and platform.system() == "Linux":
        cp = executable("cp")
        if cp:
            destination.mkdir(parents=True)
            completed = subprocess.run(
                [str(cp), "-a", "--reflink=auto", f"{source}{os.sep}.", str(destination)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            if completed.returncode == 0:
                return "reflink-or-copy"
            shutil.rmtree(destination, ignore_errors=True)
            if requested_mode == "reflink":
                raise CliError(f"写时复制失败：{completed.stdout.strip()}")
    elif requested_mode == "reflink":
        raise CliError("--mode reflink 当前仅在 Linux 主机上受支持")

    try:
        shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2)
    except OSError as exc:
        shutil.rmtree(destination, ignore_errors=True)
        raise CliError(f"复制 NDK 失败：{exc}") from exc
    return "copy"


def manifest_path(overlay: Path) -> Path:
    return overlay / OVERLAY_MANIFEST


def load_overlay_manifest(overlay: Path) -> Mapping[str, Any]:
    marker = manifest_path(overlay)
    value = load_json(marker)
    if value.get("schema") != 1 or value.get("type") != "allvm-ndk-overlay":
        raise CliError(f"不是受支持的 ALLVM overlay：{marker}")
    return value


def overlay_verifications(overlay: Path) -> list[Verification]:
    manifest = load_overlay_manifest(overlay)
    checks: list[Verification] = []
    source = Path(str(manifest.get("source_ndk", ""))).expanduser().resolve()

    checks.append(
        Verification(
            "overlay 与源目录隔离",
            overlay.resolve() != source,
            f"overlay={overlay.resolve()}, source={source}",
        )
    )
    checks.append(
        Verification(
            "overlay source.properties",
            (overlay / "source.properties").is_file(),
            str(overlay / "source.properties"),
        )
    )

    for item in manifest.get("installed_tools", []):
        relative = Path(str(item.get("path", "")))
        path = overlay / relative
        expected = str(item.get("sha256", ""))
        actual = sha256_file(path) if path.is_file() else "missing"
        checks.append(
            Verification(
                f"ALLVM 工具 {relative.name}",
                actual == expected,
                f"expected={expected}, actual={actual}",
            )
        )

    for item in manifest.get("source_tools", []):
        relative = Path(str(item.get("path", "")))
        path = source / relative
        expected = str(item.get("sha256", ""))
        actual = sha256_file(path) if path.is_file() else "missing"
        checks.append(
            Verification(
                f"源 NDK 未变 {relative.name}",
                actual == expected,
                f"expected={expected}, actual={actual}",
            )
        )
    return checks


def print_verifications(checks: Sequence[Verification], *, as_json: bool) -> None:
    if as_json:
        print(
            json.dumps(
                {
                    "checks": [
                        {"name": check.name, "status": "PASS" if check.ok else "FAIL", "detail": check.detail}
                        for check in checks
                    ]
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    width = max((len(check.name) for check in checks), default=0)
    for check in checks:
        print(f"[{'PASS' if check.ok else 'FAIL':4}] {check.name:<{width}}  {check.detail}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def command_profile_list(args: argparse.Namespace) -> int:
    profiles = [load_profile(name) for name in available_profile_names()]
    if args.json:
        print(json.dumps({"profiles": [profile.as_dict() for profile in profiles]}, ensure_ascii=False, indent=2))
    else:
        width = max((len(profile.name) for profile in profiles), default=0)
        for profile in profiles:
            print(f"{profile.name:<{width}}  {profile.title} — {profile.description}")
    return 0


def command_profile_show(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile)
    print(json.dumps(profile.as_dict(), ensure_ascii=False, indent=2))
    return 0


def command_render(args: argparse.Namespace) -> int:
    options = load_effective_options(profile_name=args.profile, config_path=args.config)
    rendered = render_options(options, args.format, args.scope)
    if args.output:
        write_text(args.output, rendered, force=args.force)
        print(args.output.expanduser().resolve())
    else:
        print(rendered, end="")
    return 0


def project_readme(profile: Profile, build_system: str) -> str:
    sections = [
        "# ALLVM 项目配置",
        "",
        f"当前预设：`{profile.name}`（{profile.title}）",
        "",
        "配置文件 `allvm.json` 可以追加或移除参数。修改后重新运行 `tools/allvm.py init --force`，或使用 `render` 单独生成片段。",
        "",
    ]
    if build_system in {"cmake", "both"}:
        sections.extend(
            [
                "## CMake",
                "",
                "```cmake",
                "include(${CMAKE_SOURCE_DIR}/.allvm/allvm-options.cmake)",
                "allvm_apply(your_native_target)",
                "```",
                "",
            ]
        )
    if build_system in {"ndk-build", "both"}:
        sections.extend(
            [
                "## ndk-build",
                "",
                "在 `Android.mk` 中，`include $(CLEAR_VARS)` 之后、`include $(BUILD_SHARED_LIBRARY)` 或 `$(BUILD_EXECUTABLE)` 之前加入：",
                "",
                "```makefile",
                "include $(LOCAL_PATH)/../.allvm/allvm.mk",
                "```",
                "",
            ]
        )
    sections.extend(
        [
            "不要把生产 `ALLVM_BUILD_SEED` 写入此目录或提交到 Git。",
            "",
        ]
    )
    return "\n".join(sections)


def command_init(args: argparse.Namespace) -> int:
    directory = args.directory.expanduser().resolve()
    if not directory.exists():
        directory.mkdir(parents=True)
    if not directory.is_dir():
        raise CliError(f"项目路径不是目录：{directory}")

    output = directory / args.output_dir
    if output.exists() and not args.force and any(output.iterdir()):
        raise CliError(f"项目配置目录已存在；使用 --force 刷新：{output}")
    output.mkdir(parents=True, exist_ok=True)

    profile = load_profile(args.profile)
    config = {
        "schema": 1,
        "profile": profile.name,
        "extra_compile_options": [],
        "remove_compile_options": [],
        "extra_cxx_options": [],
        "remove_cxx_options": [],
        "extra_link_options": [],
        "remove_link_options": [],
    }
    config_path = output / PROJECT_CONFIG
    write_json(config_path, config, force=args.force)
    effective = load_effective_options(profile_name=None, config_path=config_path)

    created = [config_path]
    if args.build_system in {"cmake", "both"}:
        cmake_path = output / "allvm-options.cmake"
        write_text(cmake_path, render_cmake(effective), force=args.force)
        created.append(cmake_path)
    if args.build_system in {"ndk-build", "both"}:
        make_path = output / "allvm.mk"
        write_text(make_path, render_ndk_build(effective), force=args.force)
        created.append(make_path)
    guide = output / "README.md"
    write_text(guide, project_readme(profile, args.build_system), force=args.force)
    created.append(guide)

    print(f"已初始化 {profile.title}：")
    for path in created:
        print(f"  {path}")
    return 0


def command_doctor(args: argparse.Namespace) -> int:
    script = ROOT / "tools" / "allvm-doctor.py"
    command = [sys.executable, str(script)]
    if args.ndk:
        command.extend(["--ndk", args.ndk])
    if args.elf:
        command.extend(["--elf", str(args.elf)])
    if args.json:
        command.append("--json")
    return subprocess.run(command, check=False).returncode


def command_overlay_create(args: argparse.Namespace) -> int:
    source = resolve_ndk(args.ndk)
    allvm_bin = args.allvm_bin.expanduser().resolve()
    destination = args.output.expanduser().resolve()

    if not allvm_bin.is_dir():
        raise CliError(f"ALLVM 工具目录不存在：{allvm_bin}")
    if destination == source or is_relative_to(destination, source):
        raise CliError("overlay 不能等于或位于源 NDK 内部")
    if is_relative_to(source, destination):
        raise CliError("源 NDK 不能位于 overlay 输出目录内部")

    if destination.exists():
        if not args.force:
            raise CliError(f"overlay 已存在；使用 --force 重建：{destination}")
        if not manifest_path(destination).is_file():
            raise CliError(
                f"拒绝删除没有 {OVERLAY_MANIFEST} 标记的目录：{destination}"
            )
        shutil.rmtree(destination)

    source_prebuilt = locate_prebuilt(source)
    source_bin = source_prebuilt / "bin"
    relative_prebuilt = source_prebuilt.relative_to(source)

    source_tools: list[dict[str, str]] = []
    for name in ("clang", "clang++", "ld.lld", "lld"):
        tool = find_tool(source_bin, name)
        if tool:
            source_tools.append(
                {
                    "name": name,
                    "path": str(tool.relative_to(source)),
                    "sha256": sha256_file(tool),
                }
            )

    required = {"clang", "clang++"}
    allvm_tools: dict[str, Path] = {}
    for name in ("clang", "clang++", "ld.lld", "lld"):
        tool = find_tool(allvm_bin, name)
        if tool:
            allvm_tools[name] = tool
    missing = sorted(required - set(allvm_tools))
    if missing:
        raise CliError(f"ALLVM 工具目录缺少：{', '.join(missing)}")

    mode = clone_ndk(source, destination, args.mode)
    destination_bin = destination / relative_prebuilt / "bin"
    installed: list[dict[str, str]] = []
    try:
        for name, source_tool in allvm_tools.items():
            target = destination_bin / host_tool_name(name)
            if not target.exists() and not target.is_symlink():
                fallback = destination_bin / name
                target = fallback if fallback.exists() or fallback.is_symlink() else target
            if target.exists() or target.is_symlink():
                target.unlink()
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_tool, target)
            installed.append(
                {
                    "name": name,
                    "path": str(target.relative_to(destination)),
                    "source": str(source_tool),
                    "sha256": sha256_file(target),
                }
            )

        manifest = {
            "schema": 1,
            "type": "allvm-ndk-overlay",
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "source_ndk": str(source),
            "source_revision": read_ndk_revision(source),
            "allvm_bin": str(allvm_bin),
            "overlay": str(destination),
            "host_prebuilt": str(relative_prebuilt),
            "copy_mode": mode,
            "installed_tools": installed,
            "source_tools": source_tools,
        }
        write_json(manifest_path(destination), manifest, force=True)
        checks = overlay_verifications(destination)
        if not all(check.ok for check in checks):
            print_verifications(checks, as_json=False)
            raise CliError("overlay 创建后校验失败")
    except Exception:
        if args.keep_failed:
            eprint(f"overlay 校验失败，按 --keep-failed 保留：{destination}")
        else:
            shutil.rmtree(destination, ignore_errors=True)
        raise

    if args.json:
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
    else:
        print(f"已创建独立 NDK：{destination}")
        print(f"源 NDK 未修改：{source}")
        print(f"复制模式：{mode}")
        if platform.system() == "Windows":
            print(f'$env:ANDROID_NDK_HOME = "{destination}"')
        else:
            print(f"export ANDROID_NDK_HOME={shlex.quote(str(destination))}")
    return 0


def command_overlay_verify(args: argparse.Namespace) -> int:
    overlay = args.path.expanduser().resolve()
    checks = overlay_verifications(overlay)
    print_verifications(checks, as_json=args.json)
    return 0 if all(check.ok for check in checks) else 1


def command_overlay_info(args: argparse.Namespace) -> int:
    overlay = args.path.expanduser().resolve()
    print(json.dumps(load_overlay_manifest(overlay), ensure_ascii=False, indent=2))
    return 0


def command_overlay_remove(args: argparse.Namespace) -> int:
    overlay = args.path.expanduser().resolve()
    manifest = load_overlay_manifest(overlay)
    source = Path(str(manifest.get("source_ndk", ""))).expanduser().resolve()
    if overlay == source:
        raise CliError("拒绝删除源 NDK")
    if not args.yes:
        raise CliError("删除独立 NDK 需要显式传入 --yes")
    shutil.rmtree(overlay)
    print(f"已删除：{overlay}")
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="allvm",
        description="ALLVM 统一命令行：诊断、预设、项目初始化和无侵入 NDK overlay。",
    )
    parser.add_argument("--version", action="version", version=f"ALLVM CLI {VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)

    profile = commands.add_parser("profile", help="查看保护预设")
    profile_commands = profile.add_subparsers(dest="profile_command", required=True)
    profile_list = profile_commands.add_parser("list", help="列出内置预设")
    profile_list.add_argument("--json", action="store_true")
    profile_list.set_defaults(handler=command_profile_list)
    profile_show = profile_commands.add_parser("show", help="显示一个预设")
    profile_show.add_argument("profile")
    profile_show.set_defaults(handler=command_profile_show)

    render = commands.add_parser("render", help="把预设渲染为构建系统参数")
    render.add_argument("--profile", help="内置预设名或自定义 JSON 文件")
    render.add_argument("--config", type=Path, help="项目 allvm.json")
    render.add_argument(
        "--format",
        choices=("json", "cmake", "ndk-build", "shell", "powershell", "rsp", "lines"),
        default="shell",
    )
    render.add_argument(
        "--scope", choices=("compile", "cxx", "link", "all"), default="compile"
    )
    render.add_argument("--output", type=Path)
    render.add_argument("--force", action="store_true")
    render.set_defaults(handler=command_render)

    initialize = commands.add_parser("init", help="初始化项目内的 .allvm 配置")
    initialize.add_argument("--directory", type=Path, default=Path.cwd())
    initialize.add_argument("--output-dir", default=".allvm")
    initialize.add_argument("--profile", default="balanced")
    initialize.add_argument(
        "--build-system", choices=("cmake", "ndk-build", "both"), default="both"
    )
    initialize.add_argument("--force", action="store_true")
    initialize.set_defaults(handler=command_init)

    doctor = commands.add_parser("doctor", help="诊断 NDK 和构建环境")
    doctor.add_argument("--ndk")
    doctor.add_argument("--elf", type=Path)
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(handler=command_doctor)

    overlay = commands.add_parser("overlay", help="管理不修改源 NDK 的独立工具链副本")
    overlay_commands = overlay.add_subparsers(dest="overlay_command", required=True)

    overlay_create = overlay_commands.add_parser("create", help="创建独立 NDK 副本并注入 ALLVM")
    overlay_create.add_argument("--ndk", help="源 Android NDK；省略时自动发现")
    overlay_create.add_argument("--allvm-bin", type=Path, required=True)
    overlay_create.add_argument("--output", type=Path, required=True)
    overlay_create.add_argument("--mode", choices=("auto", "copy", "reflink"), default="auto")
    overlay_create.add_argument("--force", action="store_true")
    overlay_create.add_argument("--keep-failed", action="store_true")
    overlay_create.add_argument("--json", action="store_true")
    overlay_create.set_defaults(handler=command_overlay_create)

    overlay_verify = overlay_commands.add_parser("verify", help="校验 overlay 和源 NDK 未被修改")
    overlay_verify.add_argument("--path", type=Path, required=True)
    overlay_verify.add_argument("--json", action="store_true")
    overlay_verify.set_defaults(handler=command_overlay_verify)

    overlay_info = overlay_commands.add_parser("info", help="显示 overlay manifest")
    overlay_info.add_argument("--path", type=Path, required=True)
    overlay_info.set_defaults(handler=command_overlay_info)

    overlay_remove = overlay_commands.add_parser("remove", help="删除带 manifest 的独立 NDK")
    overlay_remove.add_argument("--path", type=Path, required=True)
    overlay_remove.add_argument("--yes", action="store_true")
    overlay_remove.set_defaults(handler=command_overlay_remove)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except CliError as exc:
        eprint(f"allvm: {exc}")
        return 2
    except KeyboardInterrupt:
        eprint("allvm: 已取消")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
