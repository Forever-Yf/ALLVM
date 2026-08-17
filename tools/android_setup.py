#!/usr/bin/env python3
"""ALLVM Android project discovery foundation.

This module intentionally only discovers projects and produces a plan. It does
not edit user build files unless an explicit future apply operation is added.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


FILES = (
    "settings.gradle",
    "settings.gradle.kts",
    "build.gradle",
    "build.gradle.kts",
    "gradle.properties",
    "local.properties",
    "CMakeLists.txt",
    "Android.mk",
    "Application.mk",
)


def discover(root: Path) -> dict:
    root = root.resolve()
    found = [name for name in FILES if (root / name).exists()]
    gradle = [x for x in found if x.startswith("build.gradle") or x.startswith("settings.gradle")]
    native = any((root / x).exists() for x in ("CMakeLists.txt", "Android.mk"))
    dsl = "kotlin" if (root / "build.gradle.kts").exists() or (root / "settings.gradle.kts").exists() else "groovy"
    return {
        "schema": 1,
        "project": str(root),
        "files": found,
        "gradle": bool(gradle),
        "gradle_dsl": dsl,
        "native": native,
        "suggested_profile": "balanced",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover Android projects for ALLVM")
    parser.add_argument("project", nargs="?", default=".")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = discover(Path(args.project))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("ALLVM Android discovery")
        print("project:", result["project"])
        print("gradle:", result["gradle"], result["gradle_dsl"])
        print("native:", result["native"])
        print("files:", ", ".join(result["files"]) or "none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
