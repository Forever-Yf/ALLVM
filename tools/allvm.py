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


VERSION = "0.3.0"
ROOT = Path(__file__).resolve().parents[1]
PROFILES_DIR = ROOT / "configs" / "profiles"
OVERLAY_MANIFEST = ".allvm-overlay.json"
PROJECT_CONFIG = "allvm.json"
PROJECT_LOCK = "allvm.lock.json"


def configure_utf8_stdio() -> None:
    """Use deterministic UTF-8 for redirected Windows and POSIX output."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="backslashreplace")
        except (LookupError, OSError):
            pass


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




def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def directory_logical_stats(path: Path) -> dict[str, int]:
    files = 0
    directories = 0
    logical_bytes = 0
    for root, directory_names, file_names in os.walk(path, followlinks=False):
        directories += len(directory_names)
        root_path = Path(root)
        for file_name in file_names:
            candidate = root_path / file_name
            try:
                logical_bytes += candidate.stat(follow_symlinks=False).st_size
                files += 1
            except OSError:
                continue
    return {
        "files": files,
        "directories": directories,
        "logical_bytes": logical_bytes,
    }


def atomic_copy_file(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, target)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


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




def gradle_kotlin_escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("\n", "\\n")
    )


def gradle_groovy_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")


def render_gradle_kts(options: EffectiveOptions) -> str:
    profile = gradle_kotlin_escape(options.profile.name)
    return f'''// Generated by tools/allvm.py. Regenerate instead of editing by hand.
// Apply from an Android module build.gradle.kts after its plugins block:
// apply(from = rootProject.file(".allvm/allvm.gradle.kts"))

val allvmProfile = "{profile}"
val allvmNdkPath = providers.gradleProperty("allvm.ndkPath")
    .orElse(providers.environmentVariable("ALLVM_NDK_HOME"))
    .orElse(providers.environmentVariable("ANDROID_NDK_HOME"))
    .orElse(providers.environmentVariable("ANDROID_NDK_ROOT"))
    .orNull

fun Any.allvmSetNdkPath(path: String) {{
    val setter = javaClass.methods.firstOrNull {{ method ->
        method.name == "setNdkPath" && method.parameterCount == 1
    }}
    checkNotNull(setter) {{
        "ALLVM: Android Gradle Plugin does not expose ndkPath on ${{javaClass.name}}"
    }}
    setter.invoke(this, path)
}}

listOf(
    "com.android.application",
    "com.android.library",
    "com.android.dynamic-feature",
    "com.android.test",
).forEach {{ pluginId ->
    plugins.withId(pluginId) {{
        extensions.extraProperties.set("allvm.profile", allvmProfile)
        if (!allvmNdkPath.isNullOrBlank()) {{
            extensions.getByName("android").allvmSetNdkPath(allvmNdkPath)
            logger.lifecycle("ALLVM: profile=$allvmProfile, ndkPath=$allvmNdkPath")
        }} else {{
            logger.warn(
                "ALLVM: no custom NDK path; set -Pallvm.ndkPath or ALLVM_NDK_HOME"
            )
        }}
    }}
}}
'''


def render_gradle_groovy(options: EffectiveOptions) -> str:
    profile = gradle_groovy_escape(options.profile.name)
    return f'''// Generated by tools/allvm.py. Regenerate instead of editing by hand.
// Apply from an Android module build.gradle after its plugins block:
// apply from: rootProject.file('.allvm/allvm.gradle')

def allvmProfile = '{profile}'
def allvmNdkPath = providers.gradleProperty('allvm.ndkPath')
    .orElse(providers.environmentVariable('ALLVM_NDK_HOME'))
    .orElse(providers.environmentVariable('ANDROID_NDK_HOME'))
    .orElse(providers.environmentVariable('ANDROID_NDK_ROOT'))
    .orNull

[
    'com.android.application',
    'com.android.library',
    'com.android.dynamic-feature',
    'com.android.test',
].each {{ pluginId ->
    plugins.withId(pluginId) {{
        extensions.extraProperties.set('allvm.profile', allvmProfile)
        if (allvmNdkPath) {{
            extensions.getByName('android').ndkPath = allvmNdkPath
            logger.lifecycle("ALLVM: profile=${{allvmProfile}}, ndkPath=${{allvmNdkPath}}")
        }} else {{
            logger.warn(
                'ALLVM: no custom NDK path; set -Pallvm.ndkPath or ALLVM_NDK_HOME'
            )
        }}
    }}
}}
'''


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
    if output_format == "gradle-kts":
        return render_gradle_kts(options)
    if output_format == "gradle-groovy":
        return render_gradle_groovy(options)
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




def collect_allvm_tools(
    directory: Path, *, require_compilers: bool = True
) -> dict[str, Path]:
    if not directory.is_dir():
        if require_compilers:
            raise CliError(f"ALLVM 工具目录不存在：{directory}")
        return {}
    tools: dict[str, Path] = {}
    for name in ("clang", "clang++", "ld.lld", "lld"):
        tool = find_tool(directory, name)
        if tool:
            tools[name] = tool
    if require_compilers:
        missing = sorted({"clang", "clang++"} - set(tools))
        if missing:
            raise CliError(f"ALLVM 工具目录缺少：{', '.join(missing)}")
    return tools


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


PROJECT_GENERATORS = (
    "cmake",
    "ndk-build",
    "gradle-kts",
    "gradle-groovy",
)
GENERATOR_FILENAMES = {
    "cmake": "allvm-options.cmake",
    "ndk-build": "allvm.mk",
    "gradle-kts": "allvm.gradle.kts",
    "gradle-groovy": "allvm.gradle",
}


def load_generation_settings(config_path: Path) -> tuple[Mapping[str, Any], tuple[str, ...]]:
    config = load_json(config_path)
    if config.get("schema") != 1:
        raise CliError(
            f"不支持的项目配置 schema：{config_path} 中为 {config.get('schema')!r}"
        )
    raw_generators = config.get("generate")
    if raw_generators is None:
        generators = ("cmake", "ndk-build")
    else:
        generators = string_list(raw_generators, field="generate", source=config_path)
    if not generators:
        raise CliError(f"{config_path} 的 generate 至少需要一个生成器")
    if len(set(generators)) != len(generators):
        raise CliError(f"{config_path} 的 generate 不能包含重复项")
    unknown = sorted(set(generators) - set(PROJECT_GENERATORS))
    if unknown:
        raise CliError(
            f"{config_path} 包含未知生成器：{', '.join(unknown)}；"
            f"可用值：{', '.join(PROJECT_GENERATORS)}"
        )
    return config, generators


def selected_generators(build_system: str, gradle: str) -> tuple[str, ...]:
    result: list[str] = []
    if build_system in {"cmake", "both"}:
        result.append("cmake")
    if build_system in {"ndk-build", "both"}:
        result.append("ndk-build")
    if gradle in {"kts", "both"}:
        result.append("gradle-kts")
    if gradle in {"groovy", "both"}:
        result.append("gradle-groovy")
    return tuple(result)


def project_readme(profile: Profile, generators: Sequence[str]) -> str:
    sections = [
        "# ALLVM 项目配置",
        "",
        f"当前预设：`{profile.name}`（{profile.title}）",
        "",
        "`allvm.json` 是唯一手工配置源。修改后从项目根目录运行：",
        "",
        "```bash",
        "python3 /path/to/ALLVM/allvm.py sync --directory .",
        "python3 /path/to/ALLVM/allvm.py sync --directory . --check",
        "```",
        "",
        "`allvm.lock.json` 记录预设、配置和生成文件 SHA-256，可由 CI 检查是否过期。",
        "",
    ]
    if "cmake" in generators:
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
    if "ndk-build" in generators:
        sections.extend(
            [
                "## ndk-build",
                "",
                "在 `Android.mk` 中，`include $(CLEAR_VARS)` 之后、`BUILD_*` 之前加入：",
                "",
                "```makefile",
                "include $(LOCAL_PATH)/../.allvm/allvm.mk",
                "```",
                "",
            ]
        )
    if "gradle-kts" in generators:
        sections.extend(
            [
                "## Gradle Kotlin DSL",
                "",
                "在 Android 模块 `build.gradle.kts` 的 plugins 块之后加入：",
                "",
                "```kotlin",
                "apply(from = rootProject.file(\".allvm/allvm.gradle.kts\"))",
                "```",
                "",
            ]
        )
    if "gradle-groovy" in generators:
        sections.extend(
            [
                "## Gradle Groovy DSL",
                "",
                "在 Android 模块 `build.gradle` 的 plugins 块之后加入：",
                "",
                "```groovy",
                "apply from: rootProject.file('.allvm/allvm.gradle')",
                "```",
                "",
            ]
        )
    sections.extend(
        [
            "Gradle 片段按顺序读取 `-Pallvm.ndkPath`、`ALLVM_NDK_HOME`、",
            "`ANDROID_NDK_HOME` 和 `ANDROID_NDK_ROOT`，不会写入个人绝对路径。",
            "CMake/ndk-build 的保护参数仍由对应生成文件负责。",
            "",
            "不要把生产 `ALLVM_BUILD_SEED` 写入此目录或提交到 Git。",
            "",
        ]
    )
    return "\n".join(sections)


def generated_project_files(
    options: EffectiveOptions, generators: Sequence[str]
) -> dict[str, str]:
    files: dict[str, str] = {
        "README.md": project_readme(options.profile, generators),
    }
    for generator in generators:
        name = GENERATOR_FILENAMES[generator]
        if generator == "cmake":
            files[name] = render_cmake(options)
        elif generator == "ndk-build":
            files[name] = render_ndk_build(options)
        elif generator == "gradle-kts":
            files[name] = render_gradle_kts(options)
        elif generator == "gradle-groovy":
            files[name] = render_gradle_groovy(options)
    return files


def project_lock_payload(
    config_path: Path,
    options: EffectiveOptions,
    generators: Sequence[str],
    generated: Mapping[str, str],
) -> dict[str, Any]:
    effective = {
        "profile": options.profile.name,
        "compile_options": list(options.compile_options),
        "cxx_options": list(options.cxx_options),
        "link_options": list(options.link_options),
    }
    return {
        "schema": 1,
        "type": "allvm-project-lock",
        "cli_version": VERSION,
        "profile": options.profile.name,
        "profile_sha256": sha256_file(options.profile.source),
        "config_sha256": sha256_file(config_path),
        "effective_options_sha256": sha256_text(
            json.dumps(effective, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        ),
        "generate": list(generators),
        "generated_files": {
            name: sha256_text(content) for name, content in sorted(generated.items())
        },
    }


def synchronize_project(config_path: Path, *, check: bool) -> dict[str, Any]:
    config_path = config_path.expanduser().resolve()
    _, generators = load_generation_settings(config_path)
    options = load_effective_options(profile_name=None, config_path=config_path)
    output = config_path.parent
    generated = generated_project_files(options, generators)
    lock_payload = project_lock_payload(config_path, options, generators, generated)
    lock_text = json.dumps(lock_payload, ensure_ascii=False, indent=2) + "\n"
    expected = dict(generated)
    expected[PROJECT_LOCK] = lock_text

    previous_files: Mapping[str, Any] = {}
    lock_path = output / PROJECT_LOCK
    if lock_path.is_file():
        try:
            previous_lock = load_json(lock_path)
            if previous_lock.get("type") == "allvm-project-lock":
                candidate = previous_lock.get("generated_files", {})
                if isinstance(candidate, dict):
                    previous_files = candidate
        except CliError:
            previous_files = {}

    statuses: list[dict[str, Any]] = []
    obsolete_modified: list[Path] = []
    for name, recorded_hash in sorted(previous_files.items()):
        if name in generated:
            continue
        candidate = output / name
        if not candidate.exists():
            continue
        actual_hash = sha256_file(candidate) if candidate.is_file() else "not-a-file"
        if actual_hash == str(recorded_hash):
            statuses.append({"path": name, "state": "obsolete"})
            if not check:
                candidate.unlink()
        else:
            statuses.append(
                {
                    "path": name,
                    "state": "obsolete-modified",
                    "expected_sha256": str(recorded_hash),
                    "actual_sha256": actual_hash,
                }
            )
            obsolete_modified.append(candidate)

    if obsolete_modified and not check:
        joined = ", ".join(str(path) for path in obsolete_modified)
        raise CliError(f"拒绝删除已修改的过期生成文件：{joined}")

    all_current = not obsolete_modified and not any(
        item["state"] == "obsolete" for item in statuses
    )
    for name, content in expected.items():
        destination = output / name
        if not destination.exists():
            state = "missing"
        elif not destination.is_file():
            state = "not-a-file"
        else:
            try:
                state = (
                    "current"
                    if destination.read_text(encoding="utf-8") == content
                    else "stale"
                )
            except (OSError, UnicodeError):
                state = "stale"

        original_state = state
        if not check and state != "current":
            write_text(destination, content, force=True)
            state = "created" if original_state == "missing" else "updated"
        elif state != "current":
            all_current = False
        statuses.append(
            {
                "path": name,
                "state": state,
                "sha256": sha256_text(content),
            }
        )

    return {
        "schema": 1,
        "mode": "check" if check else "write",
        "ok": all_current if check else True,
        "profile": options.profile.name,
        "config": str(config_path),
        "output": str(output),
        "generate": list(generators),
        "files": statuses,
    }


def print_sync_summary(summary: Mapping[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return
    print(f"ALLVM profile: {summary['profile']}")
    for item in summary["files"]:
        state = str(item["state"])
        label = {
            "current": "OK",
            "created": "CREATE",
            "updated": "UPDATE",
            "missing": "MISS",
            "stale": "STALE",
            "obsolete": "REMOVE" if summary["mode"] == "write" else "OLD",
            "obsolete-modified": "KEEP",
            "not-a-file": "ERROR",
        }.get(state, state.upper())
        print(f"[{label:6}] {item['path']}")


def resolve_project_config(directory: Path, explicit: Optional[Path]) -> Path:
    root = directory.expanduser().resolve()
    if explicit is None:
        return root / ".allvm" / PROJECT_CONFIG
    candidate = explicit.expanduser()
    return candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()


def command_sync(args: argparse.Namespace) -> int:
    config_path = resolve_project_config(args.directory, args.config)
    summary = synchronize_project(config_path, check=args.check)
    print_sync_summary(summary, as_json=args.json)
    return 0 if summary["ok"] else 1


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
    generators = selected_generators(args.build_system, args.gradle)
    config = {
        "schema": 1,
        "profile": profile.name,
        "generate": list(generators),
        "extra_compile_options": [],
        "remove_compile_options": [],
        "extra_cxx_options": [],
        "remove_cxx_options": [],
        "extra_link_options": [],
        "remove_link_options": [],
    }
    config_path = output / PROJECT_CONFIG
    write_json(config_path, config, force=args.force)
    summary = synchronize_project(config_path, check=False)

    print(f"已初始化 {profile.title}：")
    print(f"  {config_path}")
    for item in summary["files"]:
        print(f"  {output / str(item['path'])}")
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

    allvm_tools = collect_allvm_tools(allvm_bin)

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


def overlay_status_payload(overlay: Path, *, include_size: bool) -> dict[str, Any]:
    overlay = overlay.expanduser().resolve()
    manifest = load_overlay_manifest(overlay)
    checks = overlay_verifications(overlay)
    allvm_bin = Path(str(manifest.get("allvm_bin", ""))).expanduser().resolve()
    available_tools = collect_allvm_tools(allvm_bin, require_compilers=False)

    updates: list[dict[str, Any]] = []
    for item in manifest.get("installed_tools", []):
        name = str(item.get("name", ""))
        current_source = available_tools.get(name)
        installed_sha = str(item.get("sha256", ""))
        if current_source is None:
            updates.append(
                {
                    "name": name,
                    "source": "missing",
                    "installed_sha256": installed_sha,
                    "source_sha256": None,
                    "update_available": False,
                }
            )
            continue
        source_sha = sha256_file(current_source)
        updates.append(
            {
                "name": name,
                "source": str(current_source),
                "installed_sha256": installed_sha,
                "source_sha256": source_sha,
                "update_available": source_sha != installed_sha,
            }
        )

    payload: dict[str, Any] = {
        "schema": 1,
        "overlay": str(overlay),
        "source_ndk": manifest.get("source_ndk"),
        "source_revision": manifest.get("source_revision"),
        "allvm_bin": str(allvm_bin),
        "verified": all(check.ok for check in checks),
        "update_available": any(item["update_available"] for item in updates),
        "checks": [
            {
                "name": check.name,
                "status": "PASS" if check.ok else "FAIL",
                "detail": check.detail,
            }
            for check in checks
        ],
        "tools": updates,
    }
    if include_size:
        payload["logical_size"] = directory_logical_stats(overlay)
    return payload


def print_overlay_status(payload: Mapping[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    print(f"overlay: {payload['overlay']}")
    print(f"source : {payload['source_ndk']} ({payload['source_revision']})")
    print(f"tools  : {payload['allvm_bin']}")
    print(f"verify : {'PASS' if payload['verified'] else 'FAIL'}")
    print(f"update : {'available' if payload['update_available'] else 'current'}")
    if "logical_size" in payload:
        size = payload["logical_size"]
        print(
            "logical: "
            f"{size['logical_bytes']} bytes, {size['files']} files, "
            f"{size['directories']} directories"
        )
    for item in payload["tools"]:
        state = "UPDATE" if item["update_available"] else "OK"
        if item["source"] == "missing":
            state = "NO-SOURCE"
        print(f"[{state:9}] {item['name']}")


def command_overlay_status(args: argparse.Namespace) -> int:
    payload = overlay_status_payload(args.path, include_size=args.size)
    print_overlay_status(payload, as_json=args.json)
    return 0 if payload["verified"] else 1


def command_overlay_update(args: argparse.Namespace) -> int:
    overlay = args.path.expanduser().resolve()
    manifest = dict(load_overlay_manifest(overlay))
    checks = overlay_verifications(overlay)
    source_checks = [
        check
        for check in checks
        if check.name in {"overlay 与源目录隔离", "overlay source.properties"}
        or check.name.startswith("源 NDK 未变")
    ]
    failed_source = [check for check in source_checks if not check.ok]
    if failed_source:
        details = "; ".join(f"{check.name}: {check.detail}" for check in failed_source)
        raise CliError(f"源 NDK 校验失败，拒绝更新 overlay：{details}")

    if args.allvm_bin:
        allvm_bin = args.allvm_bin.expanduser().resolve()
    else:
        allvm_bin = Path(str(manifest.get("allvm_bin", ""))).expanduser().resolve()
    tools = collect_allvm_tools(allvm_bin)
    relative_prebuilt = Path(str(manifest.get("host_prebuilt", "")))
    if not relative_prebuilt.parts:
        raise CliError("overlay manifest 缺少 host_prebuilt")

    installed_by_name = {
        str(item.get("name", "")): dict(item)
        for item in manifest.get("installed_tools", [])
        if isinstance(item, dict) and item.get("name")
    }
    planned: list[dict[str, Any]] = []
    for name, source_tool in tools.items():
        existing = installed_by_name.get(name)
        if existing and existing.get("path"):
            relative = Path(str(existing["path"]))
        else:
            relative = relative_prebuilt / "bin" / host_tool_name(name)
        target = overlay / relative
        source_sha = sha256_file(source_tool)
        target_sha = sha256_file(target) if target.is_file() else "missing"
        planned.append(
            {
                "name": name,
                "source": str(source_tool),
                "target": str(target),
                "path": str(relative),
                "source_sha256": source_sha,
                "target_sha256": target_sha,
                "changed": source_sha != target_sha,
            }
        )

    changed = [item for item in planned if item["changed"]]
    if not args.dry_run:
        for item in changed:
            atomic_copy_file(Path(item["source"]), Path(item["target"]))

        for item in planned:
            installed_by_name[item["name"]] = {
                "name": item["name"],
                "path": item["path"],
                "source": item["source"],
                "sha256": item["source_sha256"],
            }
        manifest["allvm_bin"] = str(allvm_bin)
        manifest["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        order = ("clang", "clang++", "ld.lld", "lld")
        manifest["installed_tools"] = [
            installed_by_name[name] for name in order if name in installed_by_name
        ]
        write_json(manifest_path(overlay), manifest, force=True)
        final_checks = overlay_verifications(overlay)
        if not all(check.ok for check in final_checks):
            print_verifications(final_checks, as_json=False)
            raise CliError("overlay 更新后校验失败")

    result = {
        "schema": 1,
        "overlay": str(overlay),
        "allvm_bin": str(allvm_bin),
        "dry_run": bool(args.dry_run),
        "changed": [item["name"] for item in changed],
        "tools": planned,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        action = "将更新" if args.dry_run else "已更新"
        print(f"{action} {len(changed)} 个工具：{overlay}")
        for item in planned:
            state = "CHANGE" if item["changed"] else "CURRENT"
            print(f"[{state:7}] {item['name']}")
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
        description="ALLVM 统一命令行：诊断、预设、项目同步、Gradle 辅助和 NDK overlay。",
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
        choices=("json", "cmake", "ndk-build", "gradle-kts", "gradle-groovy", "shell", "powershell", "rsp", "lines"),
        default="shell",
    )
    render.add_argument(
        "--scope", choices=("compile", "cxx", "link", "all"), default="compile"
    )
    render.add_argument("--output", type=Path)
    render.add_argument("--force", action="store_true")
    render.set_defaults(handler=command_render)

    sync = commands.add_parser("sync", help="从 allvm.json 刷新全部项目生成文件")
    sync.add_argument("--directory", type=Path, default=Path.cwd())
    sync.add_argument("--config", type=Path, help="默认是 <directory>/.allvm/allvm.json")
    sync.add_argument("--check", action="store_true", help="只检查是否过期，不写文件")
    sync.add_argument("--json", action="store_true")
    sync.set_defaults(handler=command_sync)

    initialize = commands.add_parser("init", help="初始化项目内的 .allvm 配置")
    initialize.add_argument("--directory", type=Path, default=Path.cwd())
    initialize.add_argument("--output-dir", default=".allvm")
    initialize.add_argument("--profile", default="balanced")
    initialize.add_argument(
        "--build-system", choices=("cmake", "ndk-build", "both"), default="both"
    )
    initialize.add_argument(
        "--gradle", choices=("none", "kts", "groovy", "both"), default="none",
        help="同时生成可 apply 的 Gradle NDK 选择片段",
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

    overlay_status = overlay_commands.add_parser("status", help="汇总校验、更新可用性和可选逻辑大小")
    overlay_status.add_argument("--path", type=Path, required=True)
    overlay_status.add_argument("--size", action="store_true", help="遍历目录并统计逻辑字节数")
    overlay_status.add_argument("--json", action="store_true")
    overlay_status.set_defaults(handler=command_overlay_status)

    overlay_update = overlay_commands.add_parser("update", help="只更新 overlay 中的 ALLVM 主机工具")
    overlay_update.add_argument("--path", type=Path, required=True)
    overlay_update.add_argument("--allvm-bin", type=Path, help="省略时使用 manifest 中的目录")
    overlay_update.add_argument("--dry-run", action="store_true")
    overlay_update.add_argument("--json", action="store_true")
    overlay_update.set_defaults(handler=command_overlay_update)

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
    configure_utf8_stdio()
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
