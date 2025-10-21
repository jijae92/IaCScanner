# IaCScanner — Shift-Left Policy Scanner for Infrastructure-as-Code

“문제가 **배포 전에** 걸리도록.” IaCScanner는 Terraform / Terragrunt / CloudFormation / Kubernetes(Helm/YAML) 등 **인프라 코드**를 정적 분석해 **보안·컴플라이언스 위반을 차단**하는 경량 스캐너입니다. 로컬 개발 단계부터 CI/CD까지 같은 규칙과 임계값으로 동작하도록 설계되었습니다.

---

## 주요 목적 · 문제 정의 · 핵심 기능

* **목적**: 공개 네트워크(0.0.0.0/0), 암호화 미적용, 과도한 IAM 권한, 시크릿 평문 노출 등 **위험 구성을 조기 탐지**합니다.
* **문제**: 런타임 탐지 후 대응은 비용이 큽니다. PR 단계에서 **정책 위반을 실패 처리**하고, 필요한 경우에만 **만료가 있는 예외**(waiver)를 허용해야 합니다.
* **핵심 기능**

  * 멀티 타겟: Terraform(+Terragrunt), CloudFormation, Kubernetes YAML/Helm 차트
  * 룰 세트: over-permissive IAM, 공개 SG/NSG, S3/Blob 퍼블릭, EBS/DB/KMS 암호화 누락, 로깅/버전 관리 미설정, 태그/라벨 정책, 모듈·프로바이더 버전 고정, 시크릿 평문/하드코딩
  * 출력 형식: **콘솔 표**, **JSON**, **SARIF**(GitHub Code Scanning), **JUnit XML**
  * 종료 코드: **2=CRITICAL/HIGH 존재**, **1=MEDIUM만 존재**, **0=LOW/INFO만 존재**
  * **예외(waiver) 파일**: `.iacscanner-allow.json` — 항목·사유·**만료일 필수**

---

## 빠른 시작(Quick Start)

### 1) 로컬 실행

```bash
# 가상환경
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 기본 스캔(현재 디렉터리)
python -m iacscanner scan . --format table

# JSON 리포트 저장
python -m iacscanner scan ./infra --format json --out artifacts/scan.json

# 실패 임계값: CRITICAL/HIGH 존재 시 종료코드 2
echo $?
```

### 2) Docker(옵션)

```bash
docker build -t iacscanner .
docker run --rm -v "$PWD":/work iacscanner scan /work --format table
```

### 3) Pre-commit 훅(옵션)

```bash
pip install pre-commit
pre-commit install
# staged 파일에 대해 빠른 스캔
```

---

## 설정(Configurations)

### 파일 위치 및 우선순위

* 루트의 **`.iacscanner.yml`** → 환경변수 → CLI 옵션 순으로 병합
* 예외 목록은 **`.iacscanner-allow.json`** 에서만 로드(필수 필드 포함)

### `.iacscanner.yml` 예시

```yaml
targets:
  - path: infra/terraform
    kind: terraform
  - path: k8s/
    kind: kubernetes
  - path: cfn/
    kind: cloudformation

severity_threshold: medium        # medium 이상 발견 시 종료코드>=1
exclude_paths:
  - "**/.terraform/**"
  - "k8s/vendor/**"

rules:
  # 카테고리 단위 on/off 또는 개별 규칙 ID 단위 세분화
  categories:
    secrets: true
    iam_least_privilege: true
    network_public_access: true
    encryption_at_rest: true
    logging_audit: true
  disabled:
    - K8S_IMAGE_LATEST
    - TF_OPEN_SECURITY_GROUP_OUTBOUND

outputs:
  - type: table
  - type: json
    path: artifacts/scan.json
  - type: sarif
    path: artifacts/scan.sarif

concurrency: 8
cache:
  enabled: true
  ttl_minutes: 10
```

### `.iacscanner-allow.json`(예외 · 필수: 만료일)

```json
{
  "metadata": {
    "owner": "platform-security",
    "updated_at": "2025-10-20"
  },
  "waivers": [
    {
      "id": "TF_S3_PUBLIC_READ",
      "resource": "aws_s3_bucket.legacy_assets",
      "reason": "파트너 IP 화이트리스트 전환 대기",
      "expires_at": "2025-12-31T23:59:59Z"
    }
  ]
}
```

> 만료일 경과 시 자동 무효가 되어 다시 실패 처리됩니다.

---

## 사용 방법(Examples)

### Terraform

```bash
python -m iacscanner scan infra/terraform --kind terraform
```

* 감지 예: `aws_security_group` 의 `0.0.0.0/0` 인바운드, `aws_s3_bucket` 의 퍼블릭 ACL, `aws_ebs_volume` 암호화 누락, `aws_iam_policy` 의 `Action:"*"` 와일드카드

### Kubernetes/Helm

```bash
python -m iacscanner scan k8s/ --kind kubernetes
```

* 감지 예: `securityContext.privileged: true`, `runAsRoot`, `hostPath` 사용, `image: *:latest`, `readOnlyRootFilesystem: false`, 리소스 리밋/리퀘스트 미설정

### CloudFormation

```bash
python -m iacscanner scan cfn/ --kind cloudformation
```

* 감지 예: S3 버킷 퍼블릭 액세스, CloudTrail/Config 비활성, KMS 미사용, RDS/ElastiCache 암호화 누락

---

## 출력 형식 · 종료 코드

* **table**: 사람이 읽기 좋은 요약(기본)
* **json**: 상세 결과(파이프라인 아티팩트로 적합)
* **sarif**: GitHub Code Scanning 업로드용
* **junit**: 테스트 리포트 통합용

종료 코드:

* **2**: CRITICAL/HIGH 1건 이상
* **1**: MEDIUM만 존재(critical/high 없음)
* **0**: LOW/INFO만 존재 또는 무위반

---

## CI/CD 통합

### GitHub Actions

```yaml
name: iacscan
on:
  pull_request:
    paths: ["infra/**", "k8s/**", "cfn/**", ".iacscanner.yml", ".iacscanner-allow.json"]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -r requirements.txt
      - run: python -m iacscanner scan . --format sarif --out artifacts/scan.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: artifacts/scan.sarif
```

### GitLab CI

```yaml
iacscan:
  image: python:3.11-slim
  script:
    - pip install -r requirements.txt
    - python -m iacscanner scan . --format json --out artifacts/scan.json
  artifacts:
    when: always
    paths: [artifacts/scan.json]
  allow_failure: false
```

### AWS CodeBuild(예시)

```yaml
version: 0.2
phases:
  install:
    commands:
      - pip install -r requirements.txt
  build:
    commands:
      - python -m iacscanner scan . --format json --out build/scan.json
artifacts:
  files:
    - build/scan.json
```

---

## 아키텍처 개요

```
[Parsers] -> [Rule Engine] -> [Evaluator] -> [Reporters]
 Terraform      Core Rules      Severity Map     table/json/sarif/junit
 K8s/Helm       Ext. Rules      Waiver Merge     exit code
 CloudFormation
```

* **Parsers**: IaC별 AST/리소스 모델 생성(주요 필드 정규화)
* **Rule Engine**: 카테고리/규칙 ID 기반 평가, **waiver** 병합 후 최종 심각도 판단
* **Reporters**: 포맷별 출력, CI 친화적 종료 코드 제공
* **성능**: 경로 단위 캐시(TTL), I/O 바운드 동시성(기본 8스레드)

---

## 운영 · SRE 팁

* **로그**: 기본 INFO. `--verbose` 로 규칙 평가 이유 표시, 민감값 마스킹
* **성능**: 모듈 캐시/벤더 디렉터리 제외(`exclude_paths`)로 가속
* **안전**: 네트워크 접근이 필요 없는 **완전 오프라인 스캔** 가능
* **런북 요약**: “PR 실패 → artifacts/scan.json 확인 → 필요한 경우 `.iacscanner-allow.json`에 만료 예외 추가 → 리뷰 승인 후 재시도”

---

## 보안 · 컴플라이언스

* **비밀 관리**: 시크릿은 코드/리포에 포함하지 않습니다. 예시는 `FOO=***` 마스킹 또는 `.env.example` 로 대체
* **최소 권한**: 파이프라인 토큰/키는 읽기 전용 범위로 제한
* **데이터 보존**: 스캔 결과 아티팩트는 조직 표준(예: 90일) 보관
* **표준 라벨**(간략): 접근/권한(ISO 27001 A.5.15, NIST CSF PR.AC), 데이터 보호(GDPR Art.32, NIST CSF PR.DS), 로깅(NIST CSF DE.CM)

---

## 폴더 구조(예시)

```
.
├─ iacscanner/           # 패키지(모듈)
│  ├─ parsers/           # terraform/k8s/cfn 파서
│  ├─ rules/             # 코어 규칙(카테고리/ID)
│  ├─ reporters/         # table/json/sarif/junit
│  └─ cli.py             # 엔트리포인트
├─ tests/                # pytest
├─ examples/             # 샘플 IaC
├─ artifacts/            # 리포트 출력(생성됨)
├─ requirements.txt
└─ README.md
```

> 실제 디렉터리/파일은 본 리포지토리를 기준으로 확인하세요.

---

## 기여(Contributing)

* 브랜치: `main` 보호 / 기능은 `feat/*`, 수정은 `fix/*`
* 커밋: Conventional Commits(`feat:`, `fix:`, `docs:` …)
* PR 체크: `pytest --cov ... --cov-fail-under=80` + 스캐너 실행 필수
* 예외(waiver)는 사유·만료 필수, PR 설명에 기재

---

## 라이선스

* `<LICENSE>`(예: Apache-2.0)를 리포 루트에 두고 본 README에 명시하세요.

---

## 변경 이력

* `CHANGELOG.md` 또는 GitHub Releases를 사용해 버전/주요 변경을 기록하세요.

---

## 빠른 데모(3줄 요약)

```bash
pip install -r requirements.txt
python -m iacscanner scan . --format table
python -m iacscanner scan . --format json --out artifacts/scan.json
```

