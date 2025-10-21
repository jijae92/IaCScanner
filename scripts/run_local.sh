#!/usr/bin/env bash
set -euo pipefail
python -m scanner --path iac/terraform/insecure --format json --out artifacts/scan.json --fail-on "${FAIL_ON:-MEDIUM}" --allow config/.iac-allow.json --baseline config/.iac-baseline.json --update-baseline false --tools tfsec,checkov --comment none
