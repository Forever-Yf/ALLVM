#!/usr/bin/env python3
"""Regression checks for the ALLVM protection report statistics schema."""

from protection_stats import ProtectionStats


def main() -> int:
    stats = ProtectionStats()
    stats.strings.protected = 12
    stats.strings.add_skip("external linkage")
    stats.strings.add_skip("external linkage")
    stats.vmp.protected = 3

    payload = stats.to_dict()
    assert payload["schema"] == 1
    assert payload["strings"]["protected"] == 12
    assert payload["strings"]["skipped"] == 2
    assert payload["strings"]["skip_reasons"][0]["count"] == 2
    assert payload["vmp"]["protected"] == 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
