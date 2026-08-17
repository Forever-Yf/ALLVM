#!/usr/bin/env python3
"""Repository-root launcher for tools/allvm.py."""

from pathlib import Path
import runpy


runpy.run_path(str(Path(__file__).resolve().parent / "tools" / "allvm.py"), run_name="__main__")
