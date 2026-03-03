# Skill-Auditor (MVP)

OpenClaw 스킬/도구 정의를 빠르게 스캔해서 보안 위험 신호를 잡아내는 로컬 CLI입니다.

## MVP 기능
- 정적 패턴 스캔 (명령 주입/파괴적 명령/외부 전송 위험)
- 프롬프트 인젝션 의심 문구 감지
- 결과 등급: `SAFE` / `WARNING` / `DANGER`
- JSON/텍스트 리포트 출력 (`--json`, `--out`)
- 제외 패턴 지원 (`--exclude`)
- 문서 예시 문자열 완화 모드 (`--strict-docs` 미사용 시 prompt-injection 문구 일부 완화)
- 실행 가능 컨텍스트 표시 (`EXEC`/`DOC`) + actionable 태깅
- 신뢰 도메인 allowlist (`--allow-domains`)로 오탐 완화
- CI 연동용 종료 코드 제어 (`--fail-on danger|warning|never`)

## 빠른 시작
```bash
python3 auditor.py --target ~/.openclaw/workspace/skills
python3 auditor.py --target ~/.bun/install/global/node_modules/openclaw/skills --json
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
  [--exclude ".git/*,node_modules/*,__pycache__/*,*.min.js,report.json,*/references/*,*/assets/*"]
```

## 테스트
```bash
python3 -m unittest -v tests/test_auditor.py
```

## 등급 기준 (초안)
- **DANGER**: 고위험 패턴(예: `rm -rf /`, 인증정보 exfiltration 의심 등)
- **WARNING**: 주의 패턴(외부 네트워크 호출, 프롬프트 인젝션 유도문 등)
- **SAFE**: 스캔 기준에서 위험 신호 없음

## 주의
- 이 도구는 **정적 스캔 기반 MVP**입니다. 오탐/미탐 가능성이 있어요.
- 실제 실행 권한 판단은 사람이 최종 검토해야 합니다.
- 교육/예시 문서에 포함된 위험 키워드도 탐지되므로, `--exclude`로 스코프를 조정하세요.


## OSS 릴리스 체크리스트
- [x] LICENSE
- [x] CONTRIBUTING
- [x] CI workflow
- [x] changelog
- [x] policy example (`skill-auditor.yml.example`)

## CI 예시
```bash
python3 auditor.py --target ./skills --fail-on danger
```

## False Positive 대응 팁
- 문서/레퍼런스 폴더는 `--exclude`로 제외
- 정상 도메인은 `--allow-domains`에 추가
- 정책 위반 차단은 `--fail-on danger`부터 시작


## GitLab Duo Hackathon Integration (WIP)
- CI flow template: `.gitlab-ci.yml`
- MR comment helper: `scripts/gitlab_mr_comment.py`
- Hackathon docs: `hackathon/HACKATHON_SUBMISSION.md`
- 3-min demo script: `hackathon/DEMO_SCRIPT_3MIN.md`
- Duo flow concept YAML: `hackathon/gitlab-duo-flow-template.yml`
