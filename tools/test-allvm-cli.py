#!/usr/bin/env python3
"""Standard-library regression tests for tools/allvm.py."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "tools" / "allvm.py"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def host_tag() -> str:
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Windows":
        return "windows-x86_64"
    if system == "Darwin":
        return "darwin-arm64" if machine in {"arm64", "aarch64"} else "darwin-x86_64"
    return "linux-x86_64"


def tool_name(name: str) -> str:
    return f"{name}.exe" if platform.system() == "Windows" else name


class AllvmCliTests(unittest.TestCase):
    maxDiff = None

    def run_cli(
        self,
        *arguments: str,
        expected: int = 0,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        if environment:
            env.update(environment)
        completed = subprocess.run(
            [sys.executable, str(CLI), *arguments],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=90,
        )
        self.assertEqual(
            completed.returncode,
            expected,
            msg=(
                f"command failed: {arguments}\n"
                f"stdout:\n{completed.stdout}\n"
                f"stderr:\n{completed.stderr}"
            ),
        )
        return completed

    def test_profile_list_and_strong_runtime_limits(self) -> None:
        listed = self.run_cli("profile", "list", "--json")
        payload = json.loads(listed.stdout)
        names = {profile["name"] for profile in payload["profiles"]}
        self.assertEqual(names, {"compat", "balanced", "strong"})

        shown = self.run_cli("profile", "show", "strong")
        strong = json.loads(shown.stdout)
        options = strong["compile_options"]
        self.assertIn("-irobf-vmp", options)
        self.assertIn("-irobf-vmp-strict", options)
        self.assertIn("-irobf-vmp-max-runtime-steps=10000000", options)
        self.assertIn("-irobf-vmp-max-runtime-calls=65536", options)
        self.assertIn("-irobf-vmp-max-call-depth=64", options)

    def test_render_formats(self) -> None:
        cmake = self.run_cli("render", "--profile", "balanced", "--format", "cmake")
        self.assertIn("function(allvm_apply target)", cmake.stdout)
        self.assertIn('"-irobf-fla"', cmake.stdout)

        make = self.run_cli(
            "render", "--profile", "compat", "--format", "ndk-build"
        )
        self.assertIn("LOCAL_CFLAGS +=", make.stdout)
        self.assertIn("-level-cie=1", make.stdout)
        self.assertNotIn("-irobf-fla", make.stdout)

        shell = self.run_cli("render", "--profile", "strong", "--format", "shell")
        self.assertIn("-irobf-vmp", shell.stdout)

        gradle_kts = self.run_cli(
            "render", "--profile", "balanced", "--format", "gradle-kts"
        )
        self.assertIn("setNdkPath", gradle_kts.stdout)
        self.assertIn("ALLVM_NDK_HOME", gradle_kts.stdout)
        self.assertIn('allvmProfile = "balanced"', gradle_kts.stdout)

        gradle_groovy = self.run_cli(
            "render", "--profile", "compat", "--format", "gradle-groovy"
        )
        self.assertIn("ndkPath", gradle_groovy.stdout)
        self.assertIn("allvmProfile = 'compat'", gradle_groovy.stdout)

    def test_project_init_sync_gradle_and_config_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            self.run_cli(
                "init",
                "--directory",
                str(project),
                "--profile",
                "balanced",
                "--build-system",
                "both",
                "--gradle",
                "both",
            )
            output = project / ".allvm"
            config_path = output / "allvm.json"
            cmake_path = output / "allvm-options.cmake"
            make_path = output / "allvm.mk"
            kts_path = output / "allvm.gradle.kts"
            groovy_path = output / "allvm.gradle"
            lock_path = output / "allvm.lock.json"
            for path in (
                config_path,
                cmake_path,
                make_path,
                kts_path,
                groovy_path,
                lock_path,
            ):
                self.assertTrue(path.is_file(), path)
            self.assertIn("allvm_apply", cmake_path.read_text(encoding="utf-8"))
            self.assertIn("setNdkPath", kts_path.read_text(encoding="utf-8"))
            self.assertIn("ndkPath", groovy_path.read_text(encoding="utf-8"))

            config = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(
                config["generate"],
                ["cmake", "ndk-build", "gradle-kts", "gradle-groovy"],
            )
            config["remove_compile_options"] = ["-irobf-fla"]
            config["extra_compile_options"] = ["-DALLVM_PROJECT_TEST=1"]
            config_path.write_text(
                json.dumps(config, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            self.run_cli("sync", "--directory", str(project))
            self.assertNotIn("-irobf-fla", cmake_path.read_text(encoding="utf-8"))
            self.assertIn(
                "-DALLVM_PROJECT_TEST=1", cmake_path.read_text(encoding="utf-8")
            )
            checked = self.run_cli(
                "sync", "--directory", str(project), "--check", "--json"
            )
            self.assertTrue(json.loads(checked.stdout)["ok"])

            cmake_path.write_text("tampered\n", encoding="utf-8")
            stale = self.run_cli(
                "sync", "--directory", str(project), "--check", expected=1
            )
            self.assertIn("STALE", stale.stdout)
            self.run_cli("sync", "--directory", str(project))
            self.assertIn("allvm_apply", cmake_path.read_text(encoding="utf-8"))

            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["generate"].remove("gradle-groovy")
            config_path.write_text(
                json.dumps(config, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            self.run_cli("sync", "--directory", str(project))
            self.assertFalse(groovy_path.exists())
            self.assertTrue(kts_path.exists())

            rendered = self.run_cli(
                "render", "--config", str(config_path), "--format", "lines"
            )
            self.assertNotIn("-irobf-fla\n", rendered.stdout)
            self.assertIn("-DALLVM_PROJECT_TEST=1", rendered.stdout)

            duplicate = self.run_cli(
                "init",
                "--directory",
                str(project),
                "--profile",
                "compat",
                expected=2,
            )
            self.assertIn("--force", duplicate.stderr)

    def make_fake_ndk(self, root: Path) -> tuple[Path, Path, Path]:
        ndk = root / "ndk"
        prebuilt = ndk / "toolchains" / "llvm" / "prebuilt" / host_tag()
        bin_dir = prebuilt / "bin"
        bin_dir.mkdir(parents=True)
        (ndk / "source.properties").write_text(
            "Pkg.Desc = Android NDK\nPkg.Revision = 99.0.0-test\n",
            encoding="utf-8",
        )
        (ndk / "build" / "cmake").mkdir(parents=True)
        (ndk / "build" / "cmake" / "android.toolchain.cmake").write_text(
            "# fake NDK toolchain\n", encoding="utf-8"
        )
        for name in ("clang", "clang++", "ld.lld", "lld"):
            (bin_dir / tool_name(name)).write_text(
                f"original-{name}\n", encoding="utf-8"
            )
        (prebuilt / "sysroot").mkdir()
        (prebuilt / "sysroot" / "marker.txt").write_text(
            "sysroot\n", encoding="utf-8"
        )

        allvm_bin = root / "allvm-bin"
        allvm_bin.mkdir()
        for name in ("clang", "clang++", "ld.lld", "lld"):
            (allvm_bin / tool_name(name)).write_text(
                f"allvm-{name}\n", encoding="utf-8"
            )
        return ndk, allvm_bin, bin_dir

    def test_overlay_create_status_update_verify_tamper_and_remove(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ndk, allvm_bin, source_bin = self.make_fake_ndk(root)
            overlay = root / "overlay"
            source_hashes = {
                name: digest(source_bin / tool_name(name))
                for name in ("clang", "clang++", "ld.lld", "lld")
            }

            created = self.run_cli(
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
                "--json",
            )
            manifest = json.loads(created.stdout)
            self.assertEqual(manifest["type"], "allvm-ndk-overlay")
            self.assertEqual(manifest["copy_mode"], "copy")
            self.assertTrue((overlay / ".allvm-overlay.json").is_file())

            overlay_bin = (
                overlay / "toolchains" / "llvm" / "prebuilt" / host_tag() / "bin"
            )
            for name in ("clang", "clang++", "ld.lld", "lld"):
                self.assertEqual(
                    (overlay_bin / tool_name(name)).read_text(encoding="utf-8"),
                    f"allvm-{name}\n",
                )
                self.assertEqual(digest(source_bin / tool_name(name)), source_hashes[name])

            status = self.run_cli(
                "overlay", "status", "--path", str(overlay), "--size", "--json"
            )
            status_payload = json.loads(status.stdout)
            self.assertTrue(status_payload["verified"])
            self.assertFalse(status_payload["update_available"])
            self.assertGreater(status_payload["logical_size"]["logical_bytes"], 0)

            new_clang = allvm_bin / tool_name("clang")
            new_clang.write_text("allvm-clang-v2\n", encoding="utf-8")
            status = self.run_cli(
                "overlay", "status", "--path", str(overlay), "--json"
            )
            self.assertTrue(json.loads(status.stdout)["update_available"])

            dry_run = self.run_cli(
                "overlay",
                "update",
                "--path",
                str(overlay),
                "--dry-run",
                "--json",
            )
            self.assertIn("clang", json.loads(dry_run.stdout)["changed"])
            self.assertEqual(
                (overlay_bin / tool_name("clang")).read_text(encoding="utf-8"),
                "allvm-clang\n",
            )

            updated = self.run_cli(
                "overlay", "update", "--path", str(overlay), "--json"
            )
            self.assertIn("clang", json.loads(updated.stdout)["changed"])
            self.assertEqual(
                (overlay_bin / tool_name("clang")).read_text(encoding="utf-8"),
                "allvm-clang-v2\n",
            )
            self.run_cli("overlay", "verify", "--path", str(overlay))
            for name in ("clang", "clang++", "ld.lld", "lld"):
                self.assertEqual(digest(source_bin / tool_name(name)), source_hashes[name])

            (overlay_bin / tool_name("clang")).write_text(
                "tampered\n", encoding="utf-8"
            )
            failed = self.run_cli(
                "overlay", "verify", "--path", str(overlay), expected=1
            )
            self.assertIn("FAIL", failed.stdout)

            no_confirmation = self.run_cli(
                "overlay", "remove", "--path", str(overlay), expected=2
            )
            self.assertIn("--yes", no_confirmation.stderr)
            self.run_cli("overlay", "remove", "--path", str(overlay), "--yes")
            self.assertFalse(overlay.exists())

    def test_overlay_rejects_manifest_path_escape_and_detects_new_tool(self) -> None:
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

    def test_overlay_force_refuses_unmarked_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ndk, allvm_bin, _ = self.make_fake_ndk(root)
            output = root / "not-an-overlay"
            output.mkdir()
            (output / "user-file.txt").write_text("keep\n", encoding="utf-8")
            refused = self.run_cli(
                "overlay",
                "create",
                "--ndk",
                str(ndk),
                "--allvm-bin",
                str(allvm_bin),
                "--output",
                str(output),
                "--mode",
                "copy",
                "--force",
                expected=2,
            )
            self.assertIn("拒绝删除", refused.stderr)
            self.assertEqual(
                (output / "user-file.txt").read_text(encoding="utf-8"), "keep\n"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
