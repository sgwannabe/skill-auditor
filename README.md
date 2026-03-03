# Skill-Auditor

OpenClaw 스킬/도구 정의를 빠르게 스캔해서 보안 위험 신호를 잡아내는 로컬 CLI입니다.

## 주요 기능

- **정적 패턴 스캔**: 명령 주입, 파괴적 명령, 외부 전송 위험 탐지
- **프롬프트 인젝션 의심 문구 감지**
- **위험도 점수화 (0-100)**: 심각도, 실행 컨텍스트, 실행 가능성, 카테고리 기반
- **자동 수정 제안**: 지원되는 패턴에 대한 구체적인 수정 방안 제공
- **결과 등급**: `SAFE` / `WARNING` / `DANGER`
- **JSON/텍스트 리포트 출력** (`--json`, `--out`)
- **베이스라인 비교**: 이전 스캔과의 차이 분석 (`--baseline`)
- **제외 패턴 지원** (`--exclude`)
- **문서 예시 문자열 완화 모드** (`--strict-docs` 미사용 시)
- **실행 가능 컨텍스트 표시** (`EXEC`/`DOC`) + actionable 태깅
- **신뢰 도메인 allowlist** (`--allow-domains`)로 오탐 완화
- **CI 연동용 종료 코드 제어** (`--fail-on danger|warning|never`)
- **GitLab MR 연동**: 위험도 요약, 상위 5개 고위험 항목, 수정 제안, 통과/실패 권장

## 빠른 시작

```bash
python3 auditor.py --target ~/.openclaw/workspace/skills
python3 auditor.py --target ~/.bun/install/global/node_modules/openclaw/skills --json
```

## 새로운 기능: 위험도 점수화

각 finding은 이제 0-100 사이의 위험도 점수를 가집니다. 점수는 다음 요소를 고려합니다:

| 요소 | 가중치 | 설명 |
|------|--------|------|
| 심각도 (danger/warning) | 50/25 | 기본 위험 수준 |
| 실행 컨텍스트 | 20 | 실행 가능한 코드인지 여부 |
| 실행 가능성 (actionable) | 15 | 실제로 조치가 필요한지 |
| 카테고리 | 5-15 | destructive-command, credential-exfil 등 |

### 보고서 수준 메트릭

```json
{
  "risk_metrics": {
    "average_risk": 42.5,
    "max_risk": 95,
    "high_risk_count": 3,
    "total_risk_score": 850
  }
}
```

## 새로운 기능: 자동 수정 제안

지원되는 패턴에 대해 구체적인 수정 제안을 제공합니다:

| 패턴 | 제안 예시 |
|------|-----------|
| `subprocess shell=True` | `shell=False`로 변경, 명령어를 리스트로 전달 |
| `exec/eval` | `ast.literal_eval()`, `JSON.parse()` 등 안전한 대안 사용 |
| `http://` URL | `https://`로 변경 (서버 지원 확인 필요) |
| 프롬프트 인젝션 | 입력 검증, 프롬프트 경계 구현 |
| 파괴적 명령 | 확인 프롬프트, dry-run 모드 추가 |

## 새로운 기능: 베이스라인 비교

이전 스캔 결과와 비교하여 변화량을 분석합니다:

```bash
# 첫 번째 스캔을 베이스라인으로 저장
python3 auditor.py --target ./skills --out baseline.json

# 이후 스캔과 비교
python3 auditor.py --target ./skills --baseline baseline.json --out current.json
```

출력 예시:
```
Baseline Delta: actionable=+2, high_risk=+1, max_risk=+15
```

## 새로운 기능: GitLab MR 연동

MR 코멘트에 다음 정보를 포함합니다:
- 위험도 요약 테이블
- 상위 5개 고위험 actionable finding
- 접을 수 있는 수정 제안 섹션
- 통과/조건부/실패 권장

```bash
python3 scripts/gitlab_mr_comment.py --report report.json --summary audit-summary.md
```

## 옵션

```bash
python3 auditor.py \
  --target <scan path> \
  [--target <scan path2> ...] \
  [--json] \
  [--out latest-report.json] \
  [--max-file-kb 256] \
  [--include "*.md,*.py,*.js,*.ts,*.json,*.yaml,*.yml,*.sh"] \
  [--exclude ".git/*,node_modules/*,__pycache__/*,*.min.js,report.json,*/references/*,*/assets/*"] \
  [--baseline <previous-report.json>] \
  [--fail-on danger|warning|never] \
  [--strict-docs] \
  [--allow-domains "www.w3.org,example.com"]
```

### 새로운 옵션

| 옵션 | 설명 |
|------|------|
| `--baseline <file>` | 이전 보고서와 비교하여 델타 메트릭 계산 |
| `--fail-on danger|warning|never` | 위험도 점수도 고려하여 종료 코드 결정 |

## 유틸리티 스크립트

### generate_fixes_md.py

보고서 JSON에서 마크다운 수정 제안 문서를 생성합니다:

```bash
python3 scripts/generate_fixes_md.py --report report.json --out fixes.md
python3 scripts/generate_fixes_md.py --report report.json --stdout  # 터미널 출력
```

### gitlab_mr_comment.py

GitLab MR에 보안 검토 코멘트를 게시합니다:

```bash
# GitLab CI 환경에서
python3 scripts/gitlab_mr_comment.py --report report.json

# 로컬 테스트 (게시하지 않음)
python3 scripts/gitlab_mr_comment.py --report report.json --no-post
```

## 테스트

```bash
python3 -m unittest -v tests/test_auditor.py
```

## 등급 기준

| 등급 | 조건 |
|------|------|
| **DANGER** | 최고 위험도 >= 90 또는 고위험 항목 >= 3개 |
| **WARNING** | 최고 위험도 >= 70 또는 고위험 항목 >= 1개 또는 평균 위험도 >= 50 |
| **SAFE** | 위험 신호 없음 |

## 이 도구가 단순 정규식보다 강력한 이유

1. **컨텍스트 인식**: 코드가 실제로 실행 가능한지 여부를 판단
2. **위험도 점수화**: 단순 true/false가 아닌 0-100 스케일로 우선순위 부여
3. **실행 가능성 태깅**: allowlist 도메인 등을 고려하여 실제 조치 필요 여부 판단
4. **자동 수정 제안**: 패턴을 넘어 구체적인 해결책 제공
5. **베이스라인 비교**: 시간에 따른 변화 추적
6. **다중 요소 분석**: 심각도 + 컨텍스트 + 카테고리 + 실행 가능성 종합 평가

## 주의

- 이 도구는 **정적 스캔 기반**입니다. 오탐/미탐 가능성이 있어요.
- 실제 실행 권한 판단은 사람이 최종 검토해야 합니다.
- 교육/예시 문서에 포함된 위험 키워드도 탐지되므로, `--exclude`로 스코프를 조정하세요.

## 예시 보고서

```bash
$ python3 auditor.py --target ./tests/fixtures --baseline baseline.json

Grade: DANGER
Scanned files: 3
Findings: 5 (danger=2, warning=3, executable=4, actionable=3)
Risk Metrics: avg=72.5, max=95, high_risk=2
Estimated review time saved: ~21 minutes
Baseline Delta: actionable=+1, high_risk=+1, max_risk=+10

Categories:
  - destructive-command: 2
  - network-call: 2
  - prompt-injection: 1

Top findings:
- [DANGER/EXEC/ACT] Risk=95 [FIXABLE] ./tests/fixtures/danger.sh:2 | destructive-command | rm -rf root
    rm -rf /
    Fix: Ensure destructive commands are properly guarded with confirmation prompts and dry-run modes...
```

## OSS 릴리스 체크리스트

- [x] LICENSE
- [x] CONTRIBUTING
- [x] CI workflow
- [x] changelog
- [x] policy example (`skill-auditor.yml.example`)

## CI 예시

```bash
# 위험 등급 시 실패
python3 auditor.py --target ./skills --fail-on danger

# 고위험 항목 있을 시 실패
python3 auditor.py --target ./skills --fail-on warning

# 베이스라인과 비교하며 스캔
python3 auditor.py --target ./skills --baseline baseline.json --out report.json
python3 scripts/gitlab_mr_comment.py --report report.json
```

## False Positive 대응 팁

- 문서/레퍼런스 폴더는 `--exclude`로 제외
- 정상 도메인은 `--allow-domains`에 추가
- 정책 위반 차단은 `--fail-on danger`부터 시작

## GitLab Duo Hackathon Integration

- CI flow template: `.gitlab-ci.yml`
- MR comment helper: `scripts/gitlab_mr_comment.py`
- Fix suggestions generator: `scripts/generate_fixes_md.py`
- Hackathon docs: `hackathon/HACKATHON_SUBMISSION.md`
- 3-min demo script: `hackathon/DEMO_SCRIPT_3MIN.md`
- Duo flow concept YAML: `hackathon/gitlab-duo-flow-template.yml`
