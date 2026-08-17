#!/usr/bin/env python3
"""ALLVM Android setup orchestration.

This module intentionally separates detection from mutation. The first stages
produce a plan; later stages can apply overlay/Gradle/CMake changes only after
explicit confirmation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


BUILD_FILES = {
    "gradle_kts": "build.gradle.kts",
    "gradle_groovy": "build.gradle",
    "settings_kts": "settings.gradle.kts",
    "settings_groovy": "settings.gradle",
    "cmake": "CMakeLists.txt",
    "ndk_make": "Android.mk",
    "ndk_application": "Application.mk",
}


def detect_project(root: Path) -> dict[str, Any]:
    root = root.resolve()
    found = {}
    for key, name in BUILD_FILES.items():
        found[key] = (root / name).exists()

    native = bool(found["cmake"] or found["ndk_make"])
    gradle = bool(
        found["gradle_kts"]
        or found["gradle_groovy"]
        or found["settings_kts"]
        or found["settings_groovy"]
    )

    if found["gradle_kts"]:
        dsl = "kotlin"
    elif found["gradle_groovy"]:
        dsl = "groovy"
    else:
        dsl = None

    systems = []
    if gradle:
        systems.append("gradle")
    if found["cmake"]:
        systems.append("cmake")
    if found["ndk_make"]:
        systems.append("ndk-build")

    return {
        "project": str(root),
        "android": gradle or native,
        "gradle": gradle,
        "gradle_dsl": dsl,
        "native": native,
        "build_systems": systems,
        "profile": "balanced",
        "files": {
            key: str(root / value) if exists else None
            for key, (value, exists) in {
                k: (n, found[k]) for k, n in BUILD_FILES.items()
            }.items()
        },
    }


def create_plan(info: dict[str, Any]) -> dict[str, Any]:
    actions = [
        "create .allvm/allvm.json",
        "create .allvm/allvm.lock.json",
    ]
    if "gradle" in info["build_systems"]:
        actions.append("generate Gradle integration fragment")
    if "cmake" in info["build_systems"]:
        actions.append("generate CMake integration fragment")
    if "ndk-build" in info["build_systems"]:
        actions.append("generate ndk-build integration fragment")

    return {
        "project": info["project"],
        "profile": info["profile"],
        "actions": actions,
        "requires_confirmation": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project", nargs="?", default=".")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    info = detect_project(Path(args.project))
    result = {
        "detection": info,
        "plan": create_plan(info),
    }

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("ALLVM Android setup plan")
        print("Project:", info["project"])
        print("Build:", ", ".join(info["build_systems"]) or "unknown")
        for item in result["plan"]["actions"]:
            print(" -", item)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
