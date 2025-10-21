.PHONY: venv deps scan demo secure

venv:
	python3 -m venv .venv && . .venv/bin/activate && pip install -U pip

deps:
	pip install -r requirements.txt && pip install checkov==3.*

scan:
	python -m scanner --path iac/terraform/insecure --format json --out artifacts/scan.json --fail-on MEDIUM --tools tfsec,checkov

demo:
	./scripts/run_local.sh

secure:
	python -m scanner --path iac/terraform/secure --format json --out artifacts/scan.json --fail-on MEDIUM --tools tfsec,checkov
