#!/usr/bin/env python3
"""Shared schema helpers for ALLVM protection statistics.

This module defines the stable report contract used by CLI/report tooling.
LLVM passes can later emit the same fields directly without changing the
consumer format.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class SkipReason:
    reason: str
    count: int = 0


@dataclass
class PassStats:
    protected: int = 0
    skipped: int = 0
    skip_reasons: list[SkipReason] = field(default_factory=list)

    def add_skip(self, reason: str) -> None:
        self.skipped += 1
        for item in self.skip_reasons:
            if item.reason == reason:
                item.count += 1
                return
        self.skip_reasons.append(SkipReason(reason=reason, count=1))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProtectionStats:
    schema: int = 1
    strings: PassStats = field(default_factory=PassStats)
    vmp: PassStats = field(default_factory=PassStats)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "strings": self.strings.to_dict(),
            "vmp": self.vmp.to_dict(),
        }


__all__ = ["ProtectionStats", "PassStats", "SkipReason"]
