"""AWS CodeCommit PR commenting utilities."""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Iterable, List, Optional

from ..schemas.finding import Finding
from ..severity import Severity

LOGGER = logging.getLogger(__name__)
HEADER = "## IaC Scanner Report"


@dataclass
class _PullRequestContext:
    pull_request_id: str
    repository_name: str
    before_commit_id: str
    after_commit_id: str


class CodeCommitCommenter:
    """Posts or updates IaC scan summaries on AWS CodeCommit pull requests."""

    def __init__(self, *, client: Optional[object] = None) -> None:
        self._client = client

    def post_summary(
        self,
        *,
        repo_name: str,
        pr_id: Optional[str],
        findings: Iterable[Finding],
        summary: dict,
        artifact_url: Optional[str] = None,
    ) -> None:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError

        if not pr_id:
            LOGGER.warning("CodeCommit commenter invoked without pr_id; skipping comment.")
            return

        client = self._client or boto3.client("codecommit")
        try:
            context = self._describe_pull_request(client, repo_name, pr_id)
        except (ClientError, BotoCoreError) as exc:
            LOGGER.error("Failed to describe pull request %s: %s", pr_id, exc)
            return
        if not context:
            LOGGER.warning("Unable to resolve pull request context for %s", pr_id)
            return

        findings_list = list(findings)
        body = self._render_comment_body(findings_list, summary, artifact_url)

        try:
            existing = self._find_existing_comment(client, context)
            if existing:
                client.update_comment(commentId=existing["commentId"], content=body)
                LOGGER.info("Updated existing CodeCommit summary comment (commentId=%s).", existing["commentId"])
            else:
                client.post_comment_for_pull_request(
                    pullRequestId=context.pull_request_id,
                    repositoryName=context.repository_name,
                    beforeCommitId=context.before_commit_id,
                    afterCommitId=context.after_commit_id,
                    content=body,
                )
                LOGGER.info("Posted new CodeCommit summary comment for PR %s.", pr_id)

            self._maybe_post_inline_comments(client, context, findings_list)
        except (ClientError, BotoCoreError) as exc:
            LOGGER.error("Failed to post CodeCommit comment: %s", exc)

    def _describe_pull_request(self, client: object, repo_name: str, pr_id: str) -> Optional[_PullRequestContext]:
        pull = client.get_pull_request(pullRequestId=pr_id)["pullRequest"]
        targets = pull.get("pullRequestTargets", [])
        target = next((t for t in targets if t.get("repositoryName") == repo_name), None)
        if not target and targets:
            target = targets[0]
        if not target:
            return None
        before_commit = target.get("destinationCommit") or target.get("destinationCommitId")
        after_commit = target.get("sourceCommit") or target.get("sourceCommitId")
        if not before_commit or not after_commit:
            LOGGER.warning("Pull request target missing commit IDs; skipping comment.")
            return None
        return _PullRequestContext(
            pull_request_id=pull["pullRequestId"],
            repository_name=target.get("repositoryName", repo_name),
            before_commit_id=before_commit,
            after_commit_id=after_commit,
        )

    def _find_existing_comment(self, client: object, context: _PullRequestContext) -> Optional[dict]:
        token: Optional[str] = None
        while True:
            kwargs = {
                "pullRequestId": context.pull_request_id,
                "repositoryName": context.repository_name,
            }
            if token:
                kwargs["nextToken"] = token
            response = client.get_comments_for_pull_request(**kwargs)
            for comment in response.get("commentsForPullRequestData", []):
                for entry in comment.get("comments", []):
                    content = entry.get("content") or ""
                    if content.startswith(HEADER):
                        return entry
            token = response.get("nextToken")
            if not token:
                break
        return None

    def _render_comment_body(self, findings: List[Finding], summary: dict, artifact_url: Optional[str]) -> str:
        top = self._format_top_findings(findings)
        summary_table = self._format_summary_table(summary)
        artifact_line = f"\n[View full results]({artifact_url})" if artifact_url else ""
        return f"{HEADER}\n\n{summary_table}\n\n{top}{artifact_line}"

    @staticmethod
    def _format_summary_table(summary: dict) -> str:
        severity = summary.get("severity", {})
        tool = summary.get("tool", {})
        lines = ["| Severity | Count |", "| --- | ---: |"]
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for key in order:
            lines.append(f"| {key} | {severity.get(key, 0)} |")
        lines.append("\n| Tool | Count |")
        lines.append("| --- | ---: |")
        for name, count in tool.items():
            lines.append(f"| {name} | {count} |")
        return "\n".join(lines)

    @staticmethod
    def _format_top_findings(findings: List[Finding], limit: int = 10) -> str:
        if not findings:
            return "No fresh findings detected."
        sorted_findings = sorted(
            findings,
            key=lambda f: (f.severity, f.tool, f.file_path),
            reverse=True,
        )
        rows = [
            "| Severity | Rule | Resource | Location |",
            "| --- | --- | --- | --- |",
        ]
        mapping = {
            Severity.CRITICAL: "CRITICAL",
            Severity.HIGH: "HIGH",
            Severity.MEDIUM: "MEDIUM",
            Severity.LOW: "LOW",
            Severity.INFO: "INFO",
        }
        for finding in sorted_findings[:limit]:
            location = f"{finding.file_path}:{finding.start or '-'}"
            rows.append(
                f"| {mapping[finding.severity]} | {finding.finding_id} | {finding.resource or '-'} | {location} |"
            )
        remaining = len(findings) - min(len(findings), limit)
        footer = f"\n…and {remaining} more." if remaining > 0 else ""
        guidance = "\n\nPlease review the resources above and remediate according to project policy."
        return "\n".join(rows) + footer + guidance

    def _maybe_post_inline_comments(
        self,
        client: object,
        context: _PullRequestContext,
        findings: List[Finding],
    ) -> None:
        from botocore.exceptions import BotoCoreError, ClientError

        high_impact = [f for f in findings if f.severity >= Severity.HIGH and f.file_path not in {None, "unknown"}]
        for finding in high_impact[:5]:
            location = {
                "filePath": finding.file_path,
                "filePosition": int(finding.start or 1),
            }
            body = (
                f"[{finding.severity.name}] {finding.title}\n"
                f"Resource: {finding.resource or 'n/a'}\n"
                f"Rule: {finding.finding_id}\n"
                f"Recommendation: {finding.recommendation or 'Review policy guidance.'}"
            )
            try:
                client.post_comment_for_pull_request(
                    pullRequestId=context.pull_request_id,
                    repositoryName=context.repository_name,
                    beforeCommitId=context.before_commit_id,
                    afterCommitId=context.after_commit_id,
                    content=body,
                    location=location,
                )
            except (ClientError, BotoCoreError) as exc:
                LOGGER.debug("Failed to post inline comment for %s: %s", finding.file_path, exc)


__all__ = ["CodeCommitCommenter"]
