"""Severity levels and helpers for scanner policy decisions."""
from __future__ import annotations

from enum import IntEnum
from typing import Iterable


class Severity(IntEnum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        normalized = value.strip().upper()
        try:
            return cls[normalized]
        except KeyError as exc:
            raise ValueError(f"Unknown severity: {value}") from exc

    @classmethod
    def ordering(cls) -> Iterable["Severity"]:
        return (cls.CRITICAL, cls.HIGH, cls.MEDIUM, cls.LOW, cls.INFO)


SEVERITY_ORDER = {severity: index for index, severity in enumerate(Severity.ordering())}


__all__ = ["Severity", "SEVERITY_ORDER"]
