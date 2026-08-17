#!/usr/bin/env python3
"""Apply the one-time Windows redirected-output UTF-8 fix."""

from pathlib import Path


cli = Path("tools/allvm.py")
text = cli.read_text(encoding="utf-8")
marker = 'PROJECT_CONFIG = "allvm.json"\n\n\nclass CliError'
replacement = '''PROJECT_CONFIG = "allvm.json"


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


class CliError'''
if text.count(marker) != 1:
    raise SystemExit("unexpected allvm.py constant marker")
text = text.replace(marker, replacement, 1)

main_marker = '''def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
'''
main_replacement = '''def main(argv: Optional[Sequence[str]] = None) -> int:
    configure_utf8_stdio()
    parser = build_parser()
'''
if text.count(main_marker) != 1:
    raise SystemExit("unexpected allvm.py main marker")
cli.write_text(text.replace(main_marker, main_replacement, 1), encoding="utf-8")

tests = Path("tools/test-allvm-cli.py")
test_text = tests.read_text(encoding="utf-8")
old = '''            text=True,
            check=False,
            timeout=90,
'''
new = '''            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=90,
'''
if test_text.count(old) != 1:
    raise SystemExit("unexpected subprocess marker in CLI tests")
tests.write_text(test_text.replace(old, new, 1), encoding="utf-8")
