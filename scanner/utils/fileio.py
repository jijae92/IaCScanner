"""JSON and SARIF helpers."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..schemas.finding import Finding
from ..severity import Severity


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def read_json(path: Path) -> Any:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_sarif(path: Path, payload: Any) -> None:
    write_json(path, payload)


def to_sarif(findings: Iterable[Finding], repo_uri: str | None = None) -> Mapping[str, Any]:
    """Convert findings to a SARIF v2.1.0 payload."""
    severity_map = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }

    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.tool].append(finding)

    runs = []
    for tool, tool_findings in grouped.items():
        tool_version = next((f.tool_version for f in tool_findings if f.tool_version), None)
        results = []
        for finding in tool_findings:
            level = severity_map.get(finding.severity, "note")
            location = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file_path,
                    },
                    "region": {
                        "startLine": finding.start or 1,
                    },
                }
            }
            if finding.end:
                location["physicalLocation"]["region"]["endLine"] = finding.end
            if repo_uri:
                location["physicalLocation"]["artifactLocation"]["uriBaseId"] = "REPO_ROOT"

            result = {
                "ruleId": finding.finding_id,
                "level": level,
                "message": {"text": finding.title},
                "locations": [location],
                "properties": {
                    "description": finding.description,
                    "recommendation": finding.recommendation,
                    "resource": finding.resource,
                    "provider": finding.provider,
                    "category": finding.category,
                    "fingerprint": finding.fingerprint,
                },
            }
            if finding.link:
                result["properties"]["link"] = finding.link
                result["helpUri"] = finding.link
            results.append(result)

        run = {
            "tool": {
                "driver": {
                    "name": tool,
                }
            },
            "results": results,
        }
        if tool_version:
            run["tool"]["driver"]["version"] = tool_version
        runs.append(run)

    payload = {"version": "2.1.0", "runs": runs}
    if repo_uri:
        payload["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json"
        for run in payload["runs"]:
            run.setdefault(
                "originalUriBaseIds",
                {
                    "REPO_ROOT": {
                        "uri": repo_uri,
                    }
                },
            )
    return payload


__all__ = ["write_json", "read_json", "write_sarif", "to_sarif"]
