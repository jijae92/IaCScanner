# Demo Scenario

1. Developer submits a risky Terraform change (open SG, public bucket).
2. CodeBuild executes `tfsec` + `Checkov`, fails, and leaves a detailed PR comment.
3. Reviewer highlights findings; developer adds entries to `.iac-allow.json` or `.iac-baseline.json` once accepted.
4. Re-run pipeline to confirm PASS.

## Screenshot Template

- PR comment snippet showing summary table + top findings.
- CodeBuild console log excerpt noting failure.

## Logs Template

```
2025-10-21 12:00:00 INFO Scan summary:
Severity  Count ...
```

## Customizing Rules

- tfsec: add custom check definitions under `.tfsec/`.
- Checkov: skip rules with `#checkov:skip=<ID>` inline comments.
