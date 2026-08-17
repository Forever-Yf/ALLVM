#!/usr/bin/env python3
"""One-time fail-fast hardening for overlay manifest path handling."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"{path}: expected one marker, found {count}: {old[:140]!r}"
        )
    write(path, text.replace(old, new, 1))


PATH_HELPERS = r'''

def manifest_relative_path(value: Any, *, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise CliError(f"overlay manifest 的 {field} 必须是非空字符串")
    relative = Path(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise CliError(f"overlay manifest 的 {field} 不是安全相对路径：{value!r}")
    return relative


def confined_manifest_path(root: Path, value: Any, *, field: str) -> Path:
    root = root.expanduser().resolve()
    relative = manifest_relative_path(value, field=field)
    candidate = root / relative
    try:
        resolved_parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise CliError(
            f"overlay manifest 的 {field} 父目录不可访问：{candidate.parent}: {exc}"
        ) from exc
    if not is_relative_to(resolved_parent, root):
        raise CliError(f"overlay manifest 的 {field} 逃逸出受管目录：{value!r}")
    if candidate.is_symlink():
        try:
            resolved_target = candidate.resolve(strict=True)
        except OSError as exc:
            raise CliError(
                f"overlay manifest 的 {field} 是损坏的符号链接：{candidate}: {exc}"
            ) from exc
        if not is_relative_to(resolved_target, root):
            raise CliError(
                f"overlay manifest 的 {field} 符号链接逃逸出受管目录：{value!r}"
            )
    return candidate


def manifest_object_list(value: Mapping[str, Any], field: str) -> list[Mapping[str, Any]]:
    items = value.get(field, [])
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        raise CliError(f"overlay manifest 的 {field} 必须是对象数组")
    return items
'''


LOAD_MANIFEST = r'''def load_overlay_manifest(overlay: Path) -> Mapping[str, Any]:
    overlay = overlay.expanduser().resolve()
    marker = manifest_path(overlay)
    value = load_json(marker)
    if value.get("schema") != 1 or value.get("type") != "allvm-ndk-overlay":
        raise CliError(f"不是受支持的 ALLVM overlay：{marker}")

    recorded_overlay = value.get("overlay")
    if not isinstance(recorded_overlay, str) or not recorded_overlay.strip():
        raise CliError(f"overlay manifest 缺少 overlay 路径：{marker}")
    if Path(recorded_overlay).expanduser().resolve() != overlay:
        raise CliError(
            f"overlay manifest 路径与当前目录不一致：{recorded_overlay!r} != {overlay}"
        )

    source_value = value.get("source_ndk")
    if not isinstance(source_value, str) or not source_value.strip():
        raise CliError(f"overlay manifest 缺少 source_ndk：{marker}")
    source = Path(source_value).expanduser().resolve()
    if source == overlay:
        raise CliError("overlay manifest 把源 NDK 指向了 overlay 自身")

    host_prebuilt = manifest_relative_path(
        value.get("host_prebuilt"), field="host_prebuilt"
    )
    confined_manifest_path(overlay, str(host_prebuilt), field="host_prebuilt")
    manifest_object_list(value, "installed_tools")
    manifest_object_list(value, "source_tools")
    return value
'''


VERIFICATIONS = r'''def overlay_verifications(overlay: Path) -> list[Verification]:
    overlay = overlay.expanduser().resolve()
    manifest = load_overlay_manifest(overlay)
    checks: list[Verification] = []
    source = Path(str(manifest["source_ndk"])).expanduser().resolve()

    checks.append(
        Verification(
            "overlay 与源目录隔离",
            overlay != source,
            f"overlay={overlay}, source={source}",
        )
    )
    checks.append(
        Verification(
            "manifest overlay 路径",
            Path(str(manifest["overlay"])).expanduser().resolve() == overlay,
            str(manifest["overlay"]),
        )
    )
    checks.append(
        Verification(
            "overlay source.properties",
            (overlay / "source.properties").is_file(),
            str(overlay / "source.properties"),
        )
    )

    for index, item in enumerate(manifest_object_list(manifest, "installed_tools")):
        relative = manifest_relative_path(
            item.get("path"), field=f"installed_tools[{index}].path"
        )
        path = confined_manifest_path(
            overlay, str(relative), field=f"installed_tools[{index}].path"
        )
        expected = str(item.get("sha256", ""))
        actual = sha256_file(path) if path.is_file() else "missing"
        checks.append(
            Verification(
                f"ALLVM 工具 {relative.name}",
                actual == expected,
                f"expected={expected}, actual={actual}",
            )
        )

    for index, item in enumerate(manifest_object_list(manifest, "source_tools")):
        relative = manifest_relative_path(
            item.get("path"), field=f"source_tools[{index}].path"
        )
        path = confined_manifest_path(
            source, str(relative), field=f"source_tools[{index}].path"
        )
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
'''


STATUS_LOOP = r'''    installed_items = manifest_object_list(manifest, "installed_tools")
    installed_by_name = {
        str(item.get("name", "")): item
        for item in installed_items
        if isinstance(item.get("name"), str) and str(item.get("name")).strip()
    }
    names = sorted(
        set(installed_by_name) | set(available_tools),
        key=lambda name: (("clang", "clang++", "ld.lld", "lld").index(name)
                          if name in ("clang", "clang++", "ld.lld", "lld") else 99,
                          name),
    )

    updates: list[dict[str, Any]] = []
    for name in names:
        item = installed_by_name.get(name)
        current_source = available_tools.get(name)
        installed_sha = str(item.get("sha256", "")) if item else None
        if current_source is None:
            updates.append(
                {
                    "name": name,
                    "source": "missing",
                    "installed_sha256": installed_sha,
                    "source_sha256": None,
                    "update_available": False,
                    "new_tool": False,
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
                "update_available": installed_sha != source_sha,
                "new_tool": item is None,
            }
        )
'''


TEST_METHOD = r'''    def test_overlay_rejects_manifest_path_escape_and_detects_new_tool(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ndk, allvm_bin, _ = self.make_fake_ndk(root)
            optional_lld = allvm_bin / tool_name("lld")
            optional_lld.unlink()
            overlay = root / "overlay"

            self.run_cli(
                "overlay",
                "create",
                "--ndk",
                str(ndk),
                "--allvm-bin",
                str(allvm_bin),
                "--output",
                str(overlay),
                "--mode",
                "copy",
            )

            optional_lld.write_text("allvm-lld-new\n", encoding="utf-8")
            status = self.run_cli(
                "overlay", "status", "--path", str(overlay), "--json"
            )
            payload = json.loads(status.stdout)
            lld = next(item for item in payload["tools"] if item["name"] == "lld")
            self.assertTrue(lld["new_tool"])
            self.assertTrue(lld["update_available"])
            self.run_cli("overlay", "update", "--path", str(overlay))

            manifest_path = overlay / ".allvm-overlay.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["installed_tools"][0]["path"] = "../outside-tool"
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

            refused = self.run_cli(
                "overlay", "update", "--path", str(overlay), expected=2
            )
            self.assertIn("安全相对路径", refused.stderr)
            self.assertFalse((root / "outside-tool").exists())

'''


def patch_cli() -> None:
    path = "tools/allvm.py"
    replace_once(
        path,
        '''def manifest_path(overlay: Path) -> Path:
    return overlay / OVERLAY_MANIFEST


def load_overlay_manifest(overlay: Path) -> Mapping[str, Any]:
    marker = manifest_path(overlay)
    value = load_json(marker)
    if value.get("schema") != 1 or value.get("type") != "allvm-ndk-overlay":
        raise CliError(f"不是受支持的 ALLVM overlay：{marker}")
    return value
''',
        '''def manifest_path(overlay: Path) -> Path:
    return overlay / OVERLAY_MANIFEST
''' + PATH_HELPERS + "\n" + LOAD_MANIFEST,
    )
    start = read(path).index("def overlay_verifications(overlay: Path) -> list[Verification]:")
    end = read(path).index("\n\ndef print_verifications", start)
    text = read(path)
    write(path, text[:start] + VERIFICATIONS + text[end:])
    replace_once(
        path,
        '''    updates: list[dict[str, Any]] = []
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
''',
        STATUS_LOOP,
    )
    replace_once(
        path,
        '''    relative_prebuilt = Path(str(manifest.get("host_prebuilt", "")))
    if not relative_prebuilt.parts:
        raise CliError("overlay manifest 缺少 host_prebuilt")

    installed_by_name = {
        str(item.get("name", "")): dict(item)
        for item in manifest.get("installed_tools", [])
        if isinstance(item, dict) and item.get("name")
    }
''',
        '''    relative_prebuilt = manifest_relative_path(
        manifest.get("host_prebuilt"), field="host_prebuilt"
    )
    confined_manifest_path(overlay, str(relative_prebuilt), field="host_prebuilt")

    installed_by_name = {
        str(item.get("name", "")): dict(item)
        for item in manifest_object_list(manifest, "installed_tools")
        if isinstance(item.get("name"), str) and str(item.get("name")).strip()
    }
''',
    )
    replace_once(
        path,
        '''        if existing and existing.get("path"):
            relative = Path(str(existing["path"]))
        else:
            relative = relative_prebuilt / "bin" / host_tool_name(name)
        target = overlay / relative
''',
        '''        if existing and existing.get("path"):
            relative = manifest_relative_path(
                existing["path"], field=f"installed_tools[{name}].path"
            )
        else:
            relative = relative_prebuilt / "bin" / host_tool_name(name)
        target = confined_manifest_path(
            overlay, str(relative), field=f"installed_tools[{name}].path"
        )
''',
    )


def patch_tests() -> None:
    path = "tools/test-allvm-cli.py"
    replace_once(
        path,
        '''    def test_overlay_force_refuses_unmarked_directory(self) -> None:
''',
        TEST_METHOD + '''    def test_overlay_force_refuses_unmarked_directory(self) -> None:
''',
    )


def patch_docs() -> None:
    path = "docs/ALLVM_USAGE_CN.md"
    replace_once(
        path,
        '''`update` 会先验证源 NDK 哈希；源工具发生变化时拒绝更新。省略 `--allvm-bin` 时使用 manifest 中记录的目录。查看原始 manifest：
''',
        '''`update` 会先验证源 NDK 哈希；源工具发生变化时拒绝更新。manifest 中的工具和 prebuilt 路径必须是受限相对路径，绝对路径、`..` 和逃逸到 overlay/源 NDK 外部的符号链接都会被拒绝。新出现的可选 `lld` 也会在 `status` 中显示为可更新。省略 `--allvm-bin` 时使用 manifest 中记录的目录。查看原始 manifest：
''',
    )


def main() -> int:
    patch_cli()
    patch_tests()
    patch_docs()
    print("overlay manifest path hardening applied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
