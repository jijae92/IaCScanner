from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

from scanner.baseline import BaselineManager
from scanner.schemas.finding import Finding
from scanner.severity import Severity


def _make_finding(identifier: str, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        tool="tfsec",
        finding_id=identifier,
        title=identifier,
        severity=severity,
        file_path="iac/terraform/insecure/main.tf",
        start=10,
        end=20,
        resource="demo",
        provider="aws",
        category="network",
        description="demo",
        recommendation=None,
        link=None,
    )


def _write_entries(path: Path, entries: list[dict]) -> None:
    path.write_text(json.dumps(entries), encoding="utf-8")


def test_allowlist_takes_precedence(tmp_path: Path) -> None:
    finding = _make_finding("AWS001")
    allow = tmp_path / "allow.json"
    baseline = tmp_path / "baseline.json"
    expires = (datetime.utcnow() + timedelta(days=1)).isoformat()
    _write_entries(allow, [{"fingerprint": finding.fingerprint, "expires": expires, "reason": "temp"}])
    _write_entries(baseline, [])

    manager = BaselineManager(baseline_path=baseline, allowlist_path=allow)
    manager.load()
    result = manager.apply(findings=[finding], mode="strict")
    assert result.fresh == []
    assert len(result.suppressed) == 1


def test_expired_entry_respected_in_strict(tmp_path: Path) -> None:
    finding = _make_finding("AWS002", severity=Severity.HIGH)
    allow = tmp_path / "allow.json"
    baseline = tmp_path / "baseline.json"
    expired = (datetime.utcnow() - timedelta(days=1)).isoformat()
    _write_entries(allow, [{"fingerprint": finding.fingerprint, "expires": expired, "reason": "expired"}])
    _write_entries(baseline, [])

    manager = BaselineManager(baseline_path=baseline, allowlist_path=allow)
    manager.load()

    strict_result = manager.apply(findings=[finding], mode="strict")
    assert len(strict_result.fresh) == 1

    lenient_result = manager.apply(findings=[finding], mode="lenient")
    assert len(lenient_result.fresh) == 0
    assert len(lenient_result.suppressed) == 1


def test_baseline_suppresses_when_allow_absent(tmp_path: Path) -> None:
    finding = _make_finding("AWS003")
    allow = tmp_path / "allow.json"
    baseline = tmp_path / "baseline.json"
    _write_entries(allow, [])
    _write_entries(baseline, [{"fingerprint": finding.fingerprint, "expires": None, "reason": "approved"}])

    manager = BaselineManager(baseline_path=baseline, allowlist_path=allow)
    manager.load()
    result = manager.apply(findings=[finding])
    assert result.fresh == []
    assert len(result.suppressed) == 1
