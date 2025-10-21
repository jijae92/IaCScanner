# 데모 시나리오

1. 개발자가 `iac/terraform/insecure` 에 보안 취약 구성을 추가해 PR을 생성합니다.
2. CodeBuild가 `tfsec`과 `Checkov`를 실행하고, MEDIUM 이상 결과가 존재해 빌드가 실패합니다.
3. 파이프라인이 PR에 요약 코멘트와 상위 취약 항목을 남겨 리뷰어가 하이라이트합니다.
4. 합의된 항목은 `config/.iac-allow.json` 또는 `config/.iac-baseline.json`에 `expires`와 `reason`을 포함해 등록합니다.
5. 개발자가 PR을 갱신하고 CodeBuild를 재실행하면 스캔이 통과하며 아티팩트가 보존됩니다.

## 스크린샷 / 로그 템플릿

- PR 코멘트: 총괄 요약 표 + 상위 3개 취약점 스니펫.
- CodeBuild 콘솔: 실패 시 `Exit code: 1/2`와 근거 메시지.

```
| Severity | Count |
|----------|-------|
| HIGH     | 1     |
| MEDIUM   | 2     |

2025-10-21T12:00:00Z ERROR Scan failed: MEDIUM findings remain (set --fail-on HIGH to bypass)
```

## 규칙 커스터마이징 가이드

- tfsec: `.tfsec/custom/` 등에 `*.yaml` 파일을 추가하고 `TFSEC_CONFIG_FILE` 환경 변수로 경로를 지정합니다.
- tfsec 예외: 특정 리소스에서 경고를 무시하려면 `#tfsec:ignore:<RULE_ID> <reason>` 주석을 사용하고, 만료 날짜는 `.iac-allow.json`으로 관리합니다.
- Checkov: 리소스 블록 상단에 `#checkov:skip=<RULE_ID> justified reason`를 추가하거나, `checkov.yml`에서 rule enforcement를 조절합니다.
- 공통: 커스텀 규칙 또는 skip 사유는 PR 설명에 링크해 리뷰어가 추적할 수 있도록 합니다.
