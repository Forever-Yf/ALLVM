#!/usr/bin/env python3
"""Generate an ALLVM protection report.

The report format is intentionally stable. Current data comes from project
metadata; LLVM passes can later add detailed counters without changing users'
workflows.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SCHEMA = 1


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def build_report(project: Path) -> dict[str, Any]:
    config = load_json(project / ".allvm" / "allvm.json")
    lock = load_json(project / ".allvm" / "allvm.lock.json")
    generated = lock.get("generated_files", {})
    if not isinstance(generated, dict):
        generated = {}

    return {
        "schema": SCHEMA,
        "project": str(project),
        "profile": config.get("profile", "unknown"),
        "configuration": {
            "generators": config.get("generate", []),
            "lock_available": bool(lock),
        },
        "protection": {
            "strings": {
                "status": "configured",
                "encrypted": None,
                "skipped": None,
                "note": "LLVM pass counters will populate runtime statistics",
            },
            "vmp": {
                "status": "configured",
                "protected": None,
                "skipped": None,
                "note": "LLVM pass counters will populate function statistics",
            },
        },
        "artifacts": {
            "generated_files": len(generated),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate ALLVM protection report")
    parser.add_argument("project", nargs="?", default=".")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = build_report(Path(args.project).resolve())
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    print("ALLVM Protection Report")
    print("=" * 24)
    print(f"Project : {report['project']}")
    print(f"Profile : {report['profile']}")
    print()
    print("String Encryption")
    print(f"  Status : {report['protection']['strings']['status']}")
    print("  Counters: pending LLVM instrumentation")
    print()
    print("VMP")
    print(f"  Status : {report['protection']['vmp']['status']}")
    print("  Counters: pending LLVM instrumentation")
    print()
    print(f"Generated files: {report['artifacts']['generated_files']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
