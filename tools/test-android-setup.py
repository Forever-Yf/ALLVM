#!/usr/bin/env python3

import json
import tempfile
from pathlib import Path
import subprocess
import sys


with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    (root / "settings.gradle.kts").write_text("", encoding="utf-8")
    (root / "build.gradle.kts").write_text("", encoding="utf-8")
    (root / "CMakeLists.txt").write_text("", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "tools/allvm_android_setup.py", str(root), "--json"],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)
    assert payload["detection"]["gradle"] is True
    assert payload["detection"]["gradle_dsl"] == "kotlin"
    assert payload["detection"]["native"] is True
    assert "cmake" in payload["detection"]["build_systems"]

print("android setup discovery ok")
