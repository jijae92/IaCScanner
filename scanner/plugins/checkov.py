"""Checkov integration."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, List

from ..schemas.finding import Finding
from ..severity import Severity
from ..utils import shell
from ..utils.shell import ShellCommandError


class CheckovScanner:
    """Run Checkov and translate output into Finding objects."""

    def __init__(self) -> None:
        self._tool_version: str | None = None

    def scan(self, *, target_dir: Path, dry_run: bool = False) -> List[Finding]:
        if dry_run:
            logging.debug("Checkov dry-run mode enabled; returning synthetic finding.")
            return self._synthetic_findings(target_dir=target_dir)

        version = self._ensure_tool_version()

        command = [
            "checkov",
            "-d",
            str(target_dir),
            "-o",
            "json",
            "--quiet",
        ]
        rc, stdout, stderr = shell.run(command)
        if rc not in (0, 1):
            raise ShellCommandError(
                command=command,
                message=f"checkov exited with status {rc}. {stderr.strip() or stdout.strip() or 'No additional output.'}",
                returncode=rc,
                stdout=stdout,
                stderr=stderr,
            )

        if not stdout.strip():
            logging.warning("checkov returned an empty payload for %s", target_dir)
            return []

        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            logging.error("Unable to parse checkov JSON output: %s", exc)
            return []

        return self._convert(payload, tool_version=version)

    def _ensure_tool_version(self) -> str:
        if self._tool_version is not None:
            return self._tool_version

        command = ["checkov", "--version"]
        rc, stdout, stderr = shell.run(command)
        if rc != 0:
            raise ShellCommandError(
                command=command,
                message=f"Unable to determine checkov version (exit code {rc}). {stderr.strip() or stdout.strip() or 'Install checkov and retry.'}",
                returncode=rc,
                stdout=stdout,
                stderr=stderr,
            )
        version = (stdout or stderr).strip().splitlines()[0] if (stdout or stderr) else "unknown"
        self._tool_version = version
        return version

    def _convert(self, payload: dict[str, Any], *, tool_version: str) -> List[Finding]:
        findings: List[Finding] = []
        results = payload.get("results") or {}
        for check in results.get("failed_checks", []):
            file_path = str(
                check.get("file_path")
                or check.get("repo_file_path")
                or check.get("file_abs_path")
                or ""
            )
            normalized_path = self._normalize_path(file_path)
            line_range = check.get("file_line_range") or []
            start_line = line_range[0] if line_range else None
            end_line = line_range[1] if len(line_range) > 1 else None
            rule_id = str(check.get("check_id") or "unknown")
            severity = self._coerce_severity(check.get("severity"))
            description = str(
                check.get("description")
                or check.get("check_name")
                or "Checkov finding"
            )
            resource = str(check.get("resource") or "").strip() or None
            guideline = check.get("guideline") or check.get("url") or check.get("documentation")
            provider = str(check.get("provider") or check.get("framework") or "").strip() or None
            category = self._normalize_category(check.get("category") or check.get("check_type"))
            title = str(check.get("check_name") or check.get("check_id") or "Checkov finding")
            link = str(guideline) if guideline else None

            finding = Finding(
                tool="checkov",
                finding_id=rule_id,
                title=title,
                severity=severity,
                file_path=normalized_path,
                start=start_line,
                end=end_line,
                resource=resource,
                provider=provider,
                category=category,
                description=description,
                recommendation=None,
                link=link,
                fingerprint="",
                tool_version=tool_version,
            )
            findings.append(finding)
        return findings

    @staticmethod
    def _coerce_severity(value: Any) -> Severity:
        if not value:
            return Severity.LOW
        try:
            return Severity.from_string(str(value))
        except ValueError:
            return Severity.LOW

    @staticmethod
    def _synthetic_findings(*, target_dir: Path) -> List[Finding]:
        file_path = CheckovScanner._normalize_path(str(target_dir / "main.tf"))
        return [
            Finding(
                tool="checkov",
                finding_id="CKV_AWS_20",
                title="CKV_AWS_20",
                severity=Severity.HIGH,
                file_path=file_path,
                start=5,
                end=6,
                resource="aws_s3_bucket.example",
                provider="aws",
                category="storage",
                description="Example Checkov finding (dry-run).",
                recommendation=None,
                link="https://www.checkov.io",
                tool_version="dry-run",
            )
        ]

    @staticmethod
    def _normalize_category(raw: Any) -> str:
        mapping = {
            "network": "network",
            "networking": "network",
            "firewall": "network",
            "storage": "storage",
            "s3": "storage",
            "iam": "iam",
            "identity": "iam",
            "permissions": "iam",
            "encryption": "encryption",
            "crypto": "encryption",
        }
        value = str(raw or "").strip().lower()
        return mapping.get(value, "misc")

    @staticmethod
    def _normalize_path(path_str: str) -> str:
        if not path_str:
            return "unknown"
        candidate = Path(path_str)
        try:
            resolved = candidate.resolve(strict=False)
        except OSError:
            resolved = candidate
        try:
            relative = resolved.relative_to(Path.cwd())
            return relative.as_posix()
        except ValueError:
            return resolved.as_posix()


__all__ = ["CheckovScanner"]
