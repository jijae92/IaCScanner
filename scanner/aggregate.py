"""Finding aggregation helpers."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List, Sequence

from .schemas.finding import Finding
from .severity import Severity


def merge(*finding_groups: Sequence[Finding]) -> List[Finding]:
    """Deduplicate findings across tools, preserving the highest severity entry."""
    merged: Dict[str, Finding] = {}
    for group in finding_groups:
        for finding in group:
            existing = merged.get(finding.fingerprint)
            if existing is None or finding.severity > existing.severity:
                merged[finding.fingerprint] = finding
    return list(merged.values())


def summarize(findings: Iterable[Finding]) -> Dict[str, Dict[str, int]]:
    """Produce severity and tool breakdowns."""
    severity_counts: Dict[str, int] = {s.name: 0 for s in Severity.ordering()}
    tool_counts: Dict[str, int] = defaultdict(int)
    total = 0

    for finding in findings:
        severity_counts[finding.severity.name] += 1
        tool_counts[finding.tool] += 1
        total += 1

    return {"severity": severity_counts, "tool": dict(tool_counts), "total": total}


__all__ = ["merge", "summarize"]
