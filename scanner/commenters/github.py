"""GitHub PR commenting integration."""
from __future__ import annotations

import logging
import os
from typing import Iterable, List, Optional

from ..schemas.finding import Finding
from ..severity import Severity

LOGGER = logging.getLogger(__name__)
HEADER = "## IaC Scanner Report"


class GitHubCommenter:
    """Posts or updates IaC scanner summaries on GitHub pull requests."""

    def __init__(self) -> None:
        self._token = os.environ.get("GITHUB_TOKEN")
        if not self._token:
            LOGGER.debug("GITHUB_TOKEN not set; GitHub comments will be skipped.")

    def post_summary(
        self,
        *,
        owner: str,
        repo: str,
        pr_number: Optional[str],
        findings: Iterable[Finding],
        summary: dict,
    ) -> None:
        if not self._token:
            LOGGER.warning("Skipping GitHub comment; GITHUB_TOKEN not provided.")
            return
        if not pr_number:
            LOGGER.warning("GitHub commenter requires pr_number; skipping comment.")
            return

        findings_list = list(findings)
        body = self._render_comment(findings_list, summary)

        try:
            from github import Github
        except ImportError:
            LOGGER.error("PyGithub is not installed; unable to post GitHub comments.")
            return

        gh = Github(self._token)
        repository = gh.get_repo(f"{owner}/{repo}")
        pull = repository.get_pull(int(pr_number))

        existing = self._find_existing_comment(pull)
        if existing:
            existing.edit(body)
            LOGGER.info("Updated existing GitHub PR comment (id=%s).", existing.id)
        else:
            pull.create_issue_comment(body)
            LOGGER.info("Created new GitHub PR comment for #%s.", pr_number)

    def _find_existing_comment(self, pull) -> Optional[object]:  # type: ignore[override]
        for comment in pull.get_issue_comments():
            if comment.body and comment.body.startswith(HEADER):
                return comment
        return None

    def _render_comment(self, findings: List[Finding], summary: dict) -> str:
        summary_table = self._format_summary_table(summary)
        top_block = self._format_top_findings(findings)
        guidance_links = self._format_guidance_links(findings)
        return f"{HEADER}\n\n{summary_table}\n\n{top_block}\n\n{guidance_links}".strip()

    @staticmethod
    def _format_summary_table(summary: dict) -> str:
        severity = summary.get("severity", {})
        tool = summary.get("tool", {})
        lines = ["| Severity | Count |", "| --- | ---: |"]
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for level in order:
            lines.append(f"| {level} | {severity.get(level, 0)} |")
        lines.extend(["", "| Tool | Count |", "| --- | ---: |"])
        for name, count in tool.items():
            lines.append(f"| {name} | {count} |")
        return "\n".join(lines)

    @staticmethod
    def _format_top_findings(findings: List[Finding], limit: int = 10) -> str:
        if not findings:
            return "No fresh findings detected. Great job!"
        sorted_findings = sorted(
            findings,
            key=lambda f: (f.severity, f.tool, f.file_path),
            reverse=True,
        )
        rows = ["| Severity | Rule | Resource | Location |", "| --- | --- | --- | --- |"]
        for finding in sorted_findings[:limit]:
            location = f"{finding.file_path}:{finding.start or '-'}"
            rows.append(
                f"| {finding.severity.name} | {finding.finding_id} | {finding.resource or '-'} | {location} |"
            )
        remaining = len(findings) - min(len(findings), limit)
        extra = f"\n\n…and {remaining} more findings." if remaining > 0 else ""
        return "\n".join(rows) + extra

    @staticmethod
    def _format_guidance_links(findings: List[Finding]) -> str:
        links = {finding.link for finding in findings if finding.link}
        if not links:
            return "Review the project IaC security guidelines for remediation steps."
        lines = ["**Remediation references**:"]
        for link in sorted(links):
            lines.append(f"- {link}")
        return "\n".join(lines)


__all__ = ["GitHubCommenter"]
