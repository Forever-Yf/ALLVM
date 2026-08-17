#!/usr/bin/env python3
"""Repair the one-time phase-2 migration's nested string delimiter."""

from pathlib import Path


path = Path("tools/apply-usability-p2.py")
text = path.read_text(encoding="utf-8")
start = "GRADLE_RENDERERS = r'''"
end = "'''\n\n\nPROJECT_REGION = r'''"
if text.count(start) != 1:
    raise SystemExit("unexpected GRADLE_RENDERERS start marker")
if text.count(end) != 1:
    raise SystemExit("unexpected GRADLE_RENDERERS end marker")
text = text.replace(start, 'GRADLE_RENDERERS = r"""', 1)
text = text.replace(end, '"""\n\n\nPROJECT_REGION = r\'\'\'', 1)
path.write_text(text, encoding="utf-8")
