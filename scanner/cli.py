"""Command line interface for the IaC security scanner."""
from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from . import __version__
from .aggregate import merge, summarize
from .baseline import BaselineManager
from .commenters.codecommit import CodeCommitCommenter
from .commenters.github import GitHubCommenter
from .plugins.checkov import CheckovScanner
from .plugins.tfsec import TfsecScanner
from .schemas.finding import Finding
from .severity import Severity
from .utils import fileio

DEFAULT_TARGET_PATH = Path("iac")
DEFAULT_ALLOW_PATH = Path("config/.iac-allow.json")
DEFAULT_BASELINE_PATH = Path("config/.iac-baseline.json")
DEFAULT_TOOLS = ("tfsec", "checkov")


def _env_default(name: str, fallback: str) -> str:
    return os.environ.get(name, fallback)


def str_to_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"true", "t", "yes", "y", "1"}:
        return True
    if normalized in {"false", "f", "no", "n", "0"}:
        return False
    raise argparse.ArgumentTypeError(f"Invalid boolean value: {value}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iac-scanner",
        description="IaC security scanner wrapper for tfsec and Checkov.",
    )
    parser.add_argument("--path", default=str(DEFAULT_TARGET_PATH), help="Path to scan recursively for IaC templates.")
    parser.add_argument(
        "--format",
        choices=["json", "sarif"],
        default="json",
        help="Output format for persisted results (default: %(default)s).",
    )
    parser.add_argument("--out", type=str, default=None, help="File path to write formatted results.")
    parser.add_argument(
        "--fail-on",
        default=_env_default("FAIL_ON", "MEDIUM"),
        choices=[s.name for s in Severity.ordering()],
        help="Minimum severity that triggers a non-zero exit code (default from FAIL_ON env).",
    )
    parser.add_argument(
        "--allow",
        default=str(DEFAULT_ALLOW_PATH),
        help="Allowlist file containing temporary suppressions.",
    )
    parser.add_argument(
        "--baseline",
        default=str(DEFAULT_BASELINE_PATH),
        help="Baseline file containing approved historic findings.",
    )
    parser.add_argument(
        "--baseline-mode",
        default=_env_default("BASELINE_MODE", "strict"),
        choices=["strict", "lenient"],
        help="Baseline filter behaviour (default from BASELINE_MODE env).",
    )
    parser.add_argument(
        "--update-baseline",
        default="false",
        type=str_to_bool,
        help="Whether to append fresh findings to the baseline file (default: false).",
    )
    parser.add_argument(
        "--tools",
        default=",".join(DEFAULT_TOOLS),
        help="Comma-separated list of scanners to run (tfsec, checkov).",
    )
    parser.add_argument(
        "--comment",
        default=_env_default("COMMENT_TARGET", "none"),
        choices=["none", "codecommit", "github"],
        help="Post scan summary comment to PR target (default from COMMENT_TARGET env).",
    )
    parser.add_argument("--repo", type=str, default=None, help="Repository identifier for commenter integrations.")
    parser.add_argument("--pr", type=str, default=None, help="Pull request identifier for commenter integrations.")
    parser.add_argument("--artifact-url", type=str, default=None, help="Optional artifact URL to include in comments.")
    parser.add_argument(
        "--repo-uri",
        type=str,
        default=None,
        help="Repository URI for SARIF location mapping (optional).",
    )
    parser.add_argument("--verbose", action="store_true", help="Increase logging verbosity for debugging.")
    parser.add_argument("--dry-run", action="store_true", help="Return synthetic findings instead of executing tools.")
    parser.add_argument("--version", action="version", version=f"iac-scanner {__version__}")
    return parser


class ScannerService:
    """Coordinates tool execution for selected IaC security scanners."""

    def __init__(self, *, dry_run: bool, tools: Iterable[str]) -> None:
        self.dry_run = dry_run
        self.available_plugins: Dict[str, object] = {
            "tfsec": TfsecScanner(),
            "checkov": CheckovScanner(),
        }
        self.selected_tools = tuple(tool.strip() for tool in tools if tool.strip())

    def run(self, target_path: Path) -> Dict[str, List[Finding]]:
        results: Dict[str, List[Finding]] = {}
        for tool in self.selected_tools:
            plugin = self.available_plugins.get(tool)
            if not plugin:
                logging.warning("Skipping unknown tool '%s'", tool)
                continue
            logging.debug("Executing %s against %s", tool, target_path)
            findings = plugin.scan(target_dir=target_path, dry_run=self.dry_run)  # type: ignore[arg-type]
            results[tool] = findings
        return results


def discover_iac_files(root: Path) -> List[Path]:
    extensions = {".tf", ".tf.json", ".json", ".yaml", ".yml", ".template"}
    matches: List[Path] = []
    for candidate in root.rglob("*"):
        if not candidate.is_file():
            continue
        suffix = candidate.suffix.lower()
        if suffix in extensions or candidate.name.lower().endswith(".template.json"):
            matches.append(candidate)
    return matches


def render_table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    columns = len(headers)
    widths = [len(headers[i]) for i in range(columns)]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(str(cell)))

    def _line(sep: str = "-", junction: str = "+") -> str:
        parts = [junction]
        for width in widths:
            parts.append(sep * (width + 2))
            parts.append(junction)
        return "".join(parts)

    result_lines = [_line()]
    header_cells = "|".join(f" {headers[i].ljust(widths[i])} " for i in range(columns))
    result_lines.append(f"|{header_cells}|")
    result_lines.append(_line("="))
    for row in rows:
        line = "|".join(f" {str(row[i]).ljust(widths[i])} " for i in range(columns))
        result_lines.append(f"|{line}|")
    result_lines.append(_line())
    return "\n".join(result_lines)


def emit_summary(*, summary: Dict[str, Dict[str, int]], fresh: Sequence[Finding]) -> None:
    severity_rows = [(name, summary["severity"][name]) for name in summary["severity"].keys()]
    tool_rows = list(summary["tool"].items()) or [("n/a", 0)]
    logging.info("Scan summary:\n%s", render_table(["Severity", "Count"], severity_rows))
    logging.info("Tool breakdown:\n%s", render_table(["Tool", "Count"], tool_rows))

    if fresh:
        logging.warning("Fresh findings (%s):", len(fresh))
        for finding in fresh:
            logging.warning("[%s] %s:%s %s", finding.severity.name, finding.file_path, finding.start or "-", finding.title)
    else:
        logging.info("No fresh findings above baseline/allowlist.")
    print("Scan completed successfully.")


def calculate_exit_code(fresh_findings: Sequence[Finding], threshold: Severity) -> int:
    if not fresh_findings:
        return 0
    highest = max(finding.severity for finding in fresh_findings)
    if highest >= Severity.HIGH:
        return 2
    if highest >= Severity.MEDIUM:
        return 1 if threshold <= Severity.MEDIUM else 0
    return 0


def build_report_payload(
    *,
    summary: Dict[str, Dict[str, int]],
    findings: Sequence[Finding],
    fresh: Sequence[Finding],
    suppressed: Sequence[Finding],
) -> Dict[str, object]:
    return {
        "summary": summary,
        "findings": [finding.to_dict() for finding in findings],
        "fresh_findings": [finding.to_dict() for finding in fresh],
        "suppressed_findings": [finding.to_dict() for finding in suppressed],
    }


def dump_outputs(
    *,
    output_format: str,
    payload: Dict[str, object],
    findings: Sequence[Finding],
    out_path: Path | None,
    repo_uri: str | None,
) -> None:
    if output_format == "json":
        if out_path:
            fileio.write_json(out_path, payload)
        else:
            print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        sarif_payload = fileio.to_sarif(findings, repo_uri=repo_uri)
        if out_path:
            fileio.write_sarif(out_path, sarif_payload)
        else:
            print(json.dumps(sarif_payload, indent=2, sort_keys=True))


def maybe_comment(
    target: str,
    fresh_findings: Sequence[Finding],
    summary: Dict[str, Dict[str, int]],
    repo: str | None,
    pr: str | None,
    artifact_url: str | None,
) -> None:
    if target == "none":
        return
    if not fresh_findings:
        logging.info("Skipping comments because there are no fresh findings.")
        return
    if not repo:
        logging.warning("Comment target %s requested but repo not provided; skipping.", target)
        return

    if target == "codecommit":
        repo_name = _extract_repo_component(repo, "codecommit")
        if not repo_name:
            logging.warning("Invalid CodeCommit repo spec '%s'; expected codecommit:RepoName", repo)
            return
        commenter = CodeCommitCommenter()
        commenter.post_summary(
            repo_name=repo_name,
            pr_id=pr,
            findings=fresh_findings,
            summary=summary,
            artifact_url=artifact_url,
        )
    elif target == "github":
        owner_repo = _extract_repo_component(repo, "github")
        if not owner_repo or "/" not in owner_repo:
            logging.warning("Invalid GitHub repo spec '%s'; expected github:owner/repo", repo)
            return
        owner, repo_name = owner_repo.split("/", 1)
        commenter = GitHubCommenter()
        commenter.post_summary(
            owner=owner,
            repo=repo_name,
            pr_number=pr,
            findings=fresh_findings,
            summary=summary,
        )
    else:
        logging.warning("Unknown commenter target '%s'; skipping.", target)


def _extract_repo_component(spec: str, expected: str) -> Optional[str]:
    if not spec:
        return None
    if ":" in spec:
        prefix, value = spec.split(":", 1)
        if prefix != expected:
            return None
        return value
    return spec if expected == "github" else None


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    target_path = Path(args.path).resolve()
    if not target_path.exists():
        logging.error("Target path %s does not exist.", target_path)
        return 1

    discovered = discover_iac_files(target_path)
    logging.info("Discovered %s IaC files under %s.", len(discovered), target_path)

    tools = [tool.strip() for tool in args.tools.split(",") if tool.strip()]
    service = ScannerService(dry_run=args.dry_run, tools=tools)
    per_tool = service.run(target_path)

    all_findings = merge(*per_tool.values())
    summary = summarize(all_findings)

    baseline_manager = BaselineManager(
        baseline_path=Path(args.baseline),
        allowlist_path=Path(args.allow),
    )
    baseline_manager.load()
    baseline_result = baseline_manager.apply(
        findings=all_findings,
        mode=args.baseline_mode,  # type: ignore[arg-type]
        update=args.update_baseline,
    )

    report_payload = build_report_payload(
        summary=summary,
        findings=all_findings,
        fresh=baseline_result.fresh,
        suppressed=baseline_result.suppressed,
    )

    out_path = Path(args.out).resolve() if args.out else None
    if out_path and not out_path.parent.exists():
        out_path.parent.mkdir(parents=True, exist_ok=True)

    dump_outputs(
        output_format=args.format,
        payload=report_payload,
        findings=all_findings,
        out_path=out_path,
        repo_uri=args.repo_uri,
    )

    emit_summary(summary=summary, fresh=baseline_result.fresh)
    maybe_comment(
        args.comment,
        baseline_result.fresh,
        summary,
        args.repo,
        args.pr,
        args.artifact_url,
    )

    fail_threshold = Severity.from_string(args.fail_on)
    exit_code = calculate_exit_code(baseline_result.fresh, threshold=fail_threshold)
    if exit_code:
        logging.error("Scan failed with exit code %s based on fail-on threshold %s.", exit_code, fail_threshold.name)
    return exit_code
