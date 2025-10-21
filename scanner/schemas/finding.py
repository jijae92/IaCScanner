"""Finding schema and helpers for unified IaC scanning results."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ..severity import Severity


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def compute_fingerprint(
    finding_id: str,
    file_path: str,
    start: Optional[int],
    resource: Optional[str],
    provider: Optional[str],
) -> str:
    """Generate a stable fingerprint for a finding using SHA-1."""
    payload = "|".join(
        [
            _normalize_text(finding_id),
            _normalize_text(file_path),
            _normalize_text(start or 0),
            _normalize_text(resource),
            _normalize_text(provider),
        ]
    )
    return hashlib.sha1(payload.encode("utf-8"), usedforsecurity=False).hexdigest()


@dataclass
class Finding:
    tool: str
    finding_id: str
    title: str
    severity: Severity
    file_path: str
    start: Optional[int]
    end: Optional[int]
    resource: Optional[str]
    provider: Optional[str]
    category: str
    description: str
    recommendation: Optional[str]
    link: Optional[str]
    fingerprint: str = field(default_factory=str)
    tool_version: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = compute_fingerprint(
                self.finding_id,
                self.file_path,
                self.start,
                self.resource,
                self.provider,
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "id": self.finding_id,
            "title": self.title,
            "severity": self.severity.name,
            "file": self.file_path,
            "start": self.start,
            "end": self.end,
            "resource": self.resource,
            "provider": self.provider,
            "category": self.category,
            "description": self.description,
            "recommendation": self.recommendation,
            "link": self.link,
            "fingerprint": self.fingerprint,
            "tool_version": self.tool_version,
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "Finding":
        return cls(
            tool=str(payload.get("tool", "")),
            finding_id=str(payload.get("id", "")),
            title=str(payload.get("title", "")),
            severity=Severity.from_string(str(payload.get("severity", "LOW"))),
            file_path=str(payload.get("file", "")),
            start=payload.get("start"),
            end=payload.get("end"),
            resource=payload.get("resource"),
            provider=payload.get("provider"),
            category=str(payload.get("category", "misc")),
            description=str(payload.get("description", "")),
            recommendation=payload.get("recommendation"),
            link=payload.get("link"),
            fingerprint=str(payload.get("fingerprint", "")),
            tool_version=payload.get("tool_version"),
        )


__all__ = ["Finding", "compute_fingerprint"]
