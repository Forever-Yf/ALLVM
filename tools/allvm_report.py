#!/usr/bin/env python3
"""Generate a simple ALLVM project protection report.

This first version intentionally consumes existing ALLVM metadata instead of
re-parsing LLVM IR. It provides a stable report format that later LLVM passes
can populate with detailed protection counters.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path



def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}



def build_report(project: Path) -> dict:
    allvm = load_json(project / ".allvm" / "allvm.json")
    lock = load_json(project / ".allvm" / "allvm.lock.json")

    generated = lock.get("generated_files", {})
    if not isinstance(generated, dict):
        generated = {}

    return {
        "schema": 1,
        "project": str(project),
        "profile": allvm.get("profile", "unknown"),
        "configuration": {
            "generate": allvm.get("generate", []),
            "lock_available": bool(lock),
        },
        "protection": {
            "strings": {
                "status": "configured",
                "details": "LLVM pass counters will populate protected/skipped counts",
            },
            "vmp": {
                "status": "configured",
                "details": "Function-level counters will populate after pass instrumentation",
            },
        },
        "artifacts": {
            "generated_files": len(generated),
        },
        "next": [
            "llvm pass instrumentation",
            "protected function counters",
            "binary size comparison",
            "performance measurements",
        ],
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
    print("Strings : configured")
    print("VMP     : configured")
    print(f"Files   : {report['artifacts']['generated_files']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
