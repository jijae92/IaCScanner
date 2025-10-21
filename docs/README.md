# IaC Scanner Monorepo

```mermaid
graph LR
  dev(Dev) --> pr(PR)
  pr --> cb[CodeBuild(tfsec+Checkov)]
  cb --> review[PR Comment / Artifacts]
```

## Quick Start

- `python -m venv .venv && source .venv/bin/activate`
- `pip install -r requirements.txt`
- `(필수) tfsec 설치` (`curl -sSfL https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash` 등)
- `python -m scanner --path iac/terraform/insecure --format json --out artifacts/scan.json --fail-on MEDIUM --tools tfsec,checkov`

`python -m scanner` 실행 시 `--format`, `--out`, `--fail-on`, `--tools` 값을 조정해 원하는 리포트를 생성할 수 있습니다.

## Baseline & Allowlist

- `config/.iac-baseline.json`: 과거에 승인된 결과를 관리합니다. 각 항목은 `fingerprint`, `reason`, `expires`(YYYY-MM-DD) 가 필수입니다.
- `config/.iac-allow.json`: 신규 이슈에 대한 예외 목록입니다. 모든 항목은 `expires`를 반드시 포함해야 하며 만료 후 재검토합니다.
- `expires`가 지난 항목은 스캔 시 실패로 처리됩니다. 조사 목적으로 무시하려면 `--update-baseline true` 또는 `--baseline-mode lenient` 옵션을 사용하세요.

## Failure Policy

| 발견된 최고 심각도 | 기본 종료 코드 | 설명 |
| --- | --- | --- |
| CRITICAL / HIGH | 2 | 항상 실패 처리, 파이프라인 중단 |
| MEDIUM | 1 | `--fail-on`이 MEDIUM 이하일 경우 실패 |
| LOW / INFO | 0 | 파이프라인 통과, 리포트만 남김 |

스캐너는 실패 시 표준 오류에 요약을 출력하고, 성공 시 한 줄 메시지를 남깁니다.

## CodeBuild 통합

- `pipeline/buildspec.yml`을 CodeBuild 프로젝트에 설정합니다.
- 환경 변수 예시:
  - `FAIL_ON=MEDIUM`
  - `COMMENT_TARGET=codebuild` (PR 코멘트 비활성화 시 `none`)
  - `BASELINE_MODE=strict`
- IAM 역할 최소 권한:
  - 소스 리포지토리 읽기 (`codecommit:GitPull` 또는 GitHub 토큰 사용)
  - 결과 업로드용 S3 버킷 RW
  - `codecommit:PostCommentForPullRequest` (PR 코멘트 사용 시)
  - CloudWatch Logs 쓰기
- CodeBuild 아티팩트 설정에 `artifacts/` 디렉터리를 포함하여 SARIF/JSON 결과를 보존합니다.

## GitHub PR 코멘트 (옵션)

- CodeBuild에서 `COMMENT_TARGET=github`로 설정하고, `GITHUB_TOKEN`을 AWS Secrets Manager 또는 Parameter Store로 전달합니다.
- 실행 명령에 `--comment github --pr <PR_NUMBER> --repo github:owner/repo`를 추가하면 스캔 요약과 상위 취약점이 PR 코멘트로 게시됩니다.
- 토큰은 최소 `repo:status` + `pull_request:write` 권한만 부여하세요.
