from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner.aggregate import merge, summarize
from scanner.plugins.checkov import CheckovScanner
from scanner.plugins.tfsec import TfsecScanner

TFSEC_SAMPLE = {
    "results": [
        {
            "rule_id": "AWS001",
            "description": "This security group allows SSH from the internet.",
            "severity": "MEDIUM",
            "provider": "aws",
            "resource": "aws_security_group.ssh_everywhere",
            "location": {
                "filename": "iac/terraform/insecure/main.tf",
                "start_line": 12,
                "end_line": 26,
            },
        },
        {
            "rule_id": "AWS999",
            "description": "Public bucket without encryption.",
            "severity": "HIGH",
            "provider": "aws",
            "resource": "aws_s3_bucket.world_readable",
            "location": {
                "filename": "iac/terraform/insecure/main.tf",
                "start_line": 33,
                "end_line": 56,
            },
        },
    ]
}

CHECKOV_SAMPLE = {
    "results": {
        "failed_checks": [
            {
                "check_id": "AWS999",
                "check_name": "Ensure bucket is encrypted",
                "severity": "MEDIUM",
                "resource": "aws_s3_bucket.world_readable",
                "provider": "aws",
                "file_path": "iac/terraform/insecure/main.tf",
                "file_line_range": [33, 56],
                "guideline": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption.html",
            },
            {
                # Deliberate duplicate fingerprint with higher severity than tfsec entry
                "check_id": "AWS001",
                "check_name": "Security group open to world",
                "severity": "HIGH",
                "resource": "aws_security_group.ssh_everywhere",
                "provider": "aws",
                "file_path": "iac/terraform/insecure/main.tf",
                "file_line_range": [12, 26],
            },
            {
                "check_id": "CKV_AWS_050",
                "check_name": "IAM policy should be scoped",
                "severity": "LOW",
                "resource": "aws_iam_policy.allow_everything",
                "provider": "aws",
                "file_path": "iac/terraform/insecure/main.tf",
                "file_line_range": [60, 85],
            },
        ]
    }
}


@pytest.fixture()
def parsed_findings() -> tuple[list, list]:
    tfsec = TfsecScanner()._convert(json.loads(json.dumps(TFSEC_SAMPLE)), tool_version="1.0.0")
    checkov = CheckovScanner()._convert(json.loads(json.dumps(CHECKOV_SAMPLE)), tool_version="3.0.0")
    return tfsec, checkov


def test_merge_deduplicates_by_fingerprint(parsed_findings) -> None:
    tfsec_findings, checkov_findings = parsed_findings
    assert len(tfsec_findings) == 2
    assert len(checkov_findings) == 3

    combined = merge(tfsec_findings, checkov_findings)

    # Expect duplicate SG finding resolved to single HIGH severity entry
    assert len(combined) == 3
    sg_matches = [f for f in combined if f.finding_id in {"AWS001", "AWS001"}]
    assert len(sg_matches) == 1
    assert sg_matches[0].severity.name == "HIGH"



def test_summarize_orders_severities(parsed_findings) -> None:
    tfsec_findings, checkov_findings = parsed_findings
    combined = merge(tfsec_findings, checkov_findings)
    summary = summarize(combined)

    assert summary["severity"]["HIGH"] == 2
    assert summary["severity"]["MEDIUM"] == 0
    assert summary["severity"]["LOW"] == 1
    assert summary["tool"]["tfsec"] == 1
    assert summary["tool"]["checkov"] == 2
    assert summary["total"] == 3
