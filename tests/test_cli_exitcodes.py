from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner import cli
from scanner.schemas.finding import Finding
from scanner.severity import Severity


def _make_finding(severity: Severity) -> Finding:
    return Finding(
        tool="tfsec",
        finding_id=f"RULE_{severity.name}",
        title=f"Rule {severity.name}",
        severity=severity,
        file_path="iac/terraform/insecure/main.tf",
        start=5,
        end=6,
        resource="demo",
        provider="aws",
        category="network",
        description="demo",
        recommendation=None,
        link=None,
    )


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("FAIL_ON", raising=False)
    monkeypatch.delenv("COMMENT_TARGET", raising=False)
    monkeypatch.delenv("BASELINE_MODE", raising=False)


def test_cli_insecure_returns_failure(tmp_path: Path, monkeypatch) -> None:
    allow = tmp_path / "allow.json"
    baseline = tmp_path / "baseline.json"
    allow.write_text("[]", encoding="utf-8")
    baseline.write_text("[]", encoding="utf-8")

    def fake_run(self, target_path: Path):  # type: ignore[override]
        return {
            "tfsec": [_make_finding(Severity.MEDIUM)],
            "checkov": [_make_finding(Severity.HIGH)],
        }

    monkeypatch.setattr(cli.ScannerService, "run", fake_run)

    args = [
        "--path",
        "iac/terraform/insecure",
        "--format",
        "json",
        "--out",
        str(tmp_path / "out.json"),
        "--allow",
        str(allow),
        "--baseline",
        str(baseline),
        "--update-baseline",
        "false",
        "--tools",
        "tfsec,checkov",
    ]
    exit_code = cli.main(args)
    assert exit_code in (1, 2)


def test_cli_secure_returns_success(tmp_path: Path, monkeypatch) -> None:
    allow = tmp_path / "allow.json"
    baseline = tmp_path / "baseline.json"
    allow.write_text("[]", encoding="utf-8")
    baseline.write_text("[]", encoding="utf-8")

    def fake_run(self, target_path: Path):  # type: ignore[override]
        return {
            "tfsec": [_make_finding(Severity.LOW)],
            "checkov": [],
        }

    monkeypatch.setattr(cli.ScannerService, "run", fake_run)

    args = [
        "--path",
        "iac/terraform/secure",
        "--format",
        "json",
        "--allow",
        str(allow),
        "--baseline",
        str(baseline),
        "--update-baseline",
        "false",
    ]
    exit_code = cli.main(args)
    assert exit_code == 0
