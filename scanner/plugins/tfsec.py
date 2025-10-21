"""tfsec integration."""
from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Any, List

from ..schemas.finding import Finding
from ..severity import Severity
from ..utils import shell
from ..utils.shell import ShellCommandError


class TfsecScanner:
    """Run tfsec and translate output into Finding objects."""

    def __init__(self) -> None:
        self._tool_version: str | None = None

    def scan(self, *, target_dir: Path, dry_run: bool = False) -> List[Finding]:
        if dry_run:
            logging.debug("tfsec dry-run mode enabled; returning synthetic finding.")
            return self._synthetic_findings(target_dir=target_dir)

        version = self._ensure_tool_version()

        with tempfile.TemporaryDirectory(prefix="tfsec-") as workdir:
            output_path = Path(workdir) / "tfsec-output.json"
            command = [
                "tfsec",
                "--format",
                "json",
                "--out",
                str(output_path),
                str(target_dir),
            ]
            rc, stdout, stderr = shell.run(command)
            if rc not in (0, 1):
                raise ShellCommandError(
                    command=command,
                    message=f"tfsec exited with status {rc}. {stderr.strip() or stdout.strip() or 'No additional output.'}",
                    returncode=rc,
                    stdout=stdout,
                    stderr=stderr,
                )

            if not output_path.exists():
                logging.error("tfsec completed without producing output file at %s", output_path)
                return []
            try:
                payload = json.loads(output_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                logging.error("Unable to parse tfsec JSON output: %s", exc)
                return []

        return self._convert(payload, tool_version=version)

    def _ensure_tool_version(self) -> str:
        if self._tool_version is not None:
            return self._tool_version

        command = ["tfsec", "--version"]
        rc, stdout, stderr = shell.run(command)
        if rc != 0:
            raise ShellCommandError(
                command=command,
                message=f"Unable to determine tfsec version (exit code {rc}). {stderr.strip() or stdout.strip() or 'Install tfsec and retry.'}",
                returncode=rc,
                stdout=stdout,
                stderr=stderr,
            )
        version = (stdout or stderr).strip().splitlines()[0] if (stdout or stderr) else "unknown"
        self._tool_version = version
        return version

    def _convert(self, payload: dict[str, Any], *, tool_version: str) -> List[Finding]:
        findings: List[Finding] = []
        for issue in payload.get("results", []):
            location = issue.get("location") or {}
            file_path = str(location.get("filename") or issue.get("filename") or "")
            normalized_path = self._normalize_path(file_path)
            start_line = location.get("start_line") or issue.get("start_line")
            end_line = location.get("end_line") or issue.get("end_line")
            rule_id = str(issue.get("rule_id") or issue.get("id") or "unknown")
            severity = self._coerce_severity(issue.get("severity"))
            description = str(
                issue.get("description")
                or issue.get("summary")
                or issue.get("rule_description")
                or "tfsec finding"
            )
            resource = str(issue.get("resource") or "").strip() or None
            recommendation = issue.get("resolution")
            provider = issue.get("provider")
            title = str(issue.get("title") or issue.get("rule_id") or "tfsec finding")
            category = self._normalize_category(issue.get("category"))
            link = None
            links = issue.get("links")
            if isinstance(links, list) and links:
                link = str(links[0])

            finding = Finding(
                tool="tfsec",
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
                recommendation=str(recommendation) if recommendation else None,
                link=link,
                fingerprint="",  # computed in __post_init__
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
        file_path = TfsecScanner._normalize_path(str(target_dir / "main.tf"))
        return [
            Finding(
                tool="tfsec",
                finding_id="AWS053",
                title="AWS053",
                severity=Severity.MEDIUM,
                file_path=file_path,
                start=1,
                end=1,
                resource="aws_s3_bucket.example",
                provider="aws",
                category="storage",
                description="Example tfsec finding (dry-run).",
                recommendation="Simulated resolution",
                link="https://tfsec.dev",
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


__all__ = ["TfsecScanner"]
