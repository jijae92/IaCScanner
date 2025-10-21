"""Baseline and allowlist management."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Literal, Sequence

from .schemas.finding import Finding

FilterMode = Literal["strict", "lenient"]


@dataclass
class BaselineEntry:
    fingerprint: str
    expires: datetime | None
    reason: str | None = None

    @classmethod
    def from_dict(cls, payload: dict) -> "BaselineEntry":
        expires_str = payload.get("expires")
        expires = None
        if expires_str:
            try:
                expires = datetime.fromisoformat(expires_str)
            except ValueError:
                expires = None
        return cls(
            fingerprint=str(payload.get("fingerprint", "")),
            expires=expires,
            reason=payload.get("reason"),
        )

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "expires": self.expires.isoformat() if self.expires else None,
            "reason": self.reason,
        }


@dataclass
class BaselineResult:
    fresh: List[Finding]
    suppressed: List[Finding]


class BaselineManager:
    """Load and evaluate baseline/allowlist state."""

    def __init__(self, *, baseline_path: Path, allowlist_path: Path) -> None:
        self.baseline_path = baseline_path
        self.allowlist_path = allowlist_path
        self._baseline_entries: List[BaselineEntry] = []
        self._allow_entries: List[BaselineEntry] = []

    def load(self) -> None:
        self._baseline_entries = self._load_entries(self.baseline_path)
        self._allow_entries = self._load_entries(self.allowlist_path)

    def apply(
        self,
        *,
        findings: Sequence[Finding],
        mode: FilterMode = "strict",
        update: bool = False,
    ) -> BaselineResult:
        active_baseline = self._active_map(self._baseline_entries, mode)
        active_allow = self._active_map(self._allow_entries, mode)

        fresh: List[Finding] = []
        suppressed: List[Finding] = []

        for finding in findings:
            fingerprint = finding.fingerprint
            if fingerprint in active_allow:
                suppressed.append(finding)
                continue
            if fingerprint in active_baseline:
                suppressed.append(finding)
                continue
            fresh.append(finding)

        if update and fresh:
            for finding in fresh:
                self._baseline_entries.append(
                    BaselineEntry(fingerprint=finding.fingerprint, expires=None, reason="auto-captured")
                )
            self._write_entries(self.baseline_path, self._baseline_entries)

        return BaselineResult(fresh=fresh, suppressed=suppressed)

    def _active_map(self, entries: Iterable[BaselineEntry], mode: FilterMode) -> dict[str, BaselineEntry]:
        result: dict[str, BaselineEntry] = {}
        now = datetime.utcnow()
        ignore_expiry = mode == "lenient"
        for entry in entries:
            if not entry.fingerprint:
                continue
            if not ignore_expiry and entry.expires and entry.expires < now:
                continue
            result[entry.fingerprint] = entry
        return result

    def _load_entries(self, path: Path) -> List[BaselineEntry]:
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

        if not isinstance(data, list):
            return []

        entries: List[BaselineEntry] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            entries.append(BaselineEntry.from_dict(item))
        return entries

    def _write_entries(self, path: Path, entries: Sequence[BaselineEntry]) -> None:
        serialized = [entry.to_dict() for entry in entries]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(serialized, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def to_json(self) -> dict:
        return {
            "baseline": [entry.to_dict() for entry in self._baseline_entries],
            "allow": [entry.to_dict() for entry in self._allow_entries],
        }


__all__ = ["BaselineManager", "BaselineResult", "BaselineEntry"]
