# Skill-Auditor

Skill-Auditor is a local CLI that scans AI skill/tool repositories for security risks, ranks findings by risk score, and generates actionable fix guidance.

## Core Features

- Static pattern scanning (command injection, destructive commands, suspicious network/shell usage)
- Prompt-injection phrase detection
- Per-finding risk scoring (`0-100`)
- Auto-fix suggestions for supported patterns
- Report grades: `SAFE` / `WARNING` / `DANGER`
- JSON + terminal output (`--json`, `--out`)
- Baseline comparison (`--baseline`) with deltas
- Trusted domain allowlist (`--allow-domains`) to reduce false positives
- CI fail gate (`--fail-on danger|warning|never`)
- GitLab MR summary generation (`scripts/gitlab_mr_comment.py`)

## Quick Start

```bash
python3 auditor.py --target ~/.openclaw/workspace/skills
python3 auditor.py --target ~/.bun/install/global/node_modules/openclaw/skills --json
```

## Risk Scoring Model

Each finding gets a score using combined signals:

- Severity (`danger` / `warning`)
- Executable context (`EXEC` vs `DOC`)
- Actionability
- Category weight (destructive-command, credential-exfil, prompt-injection, etc.)

Report-level metrics:

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

## Auto-Fix Suggestions

Skill-Auditor provides deterministic suggestions for common risky patterns, including:

- `subprocess(..., shell=True)`
- `exec` / `eval`
- `http://` usage where `https://` can be safer
- Prompt-injection literals in executable scripts

## Baseline Comparison

Use a previous report to track security drift:

```bash
# save baseline
python3 auditor.py --target ./skills --out baseline.json

# compare current scan against baseline
python3 auditor.py --target ./skills --baseline baseline.json --out current.json
```

Example delta output:

```text
Baseline Delta: actionable=+2, high_risk=+1, max_risk=+15
```

## CLI Options

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

## Utility Scripts

### 1) Markdown fix sheet

```bash
python3 scripts/generate_fixes_md.py --report report.json --out fixes.md
python3 scripts/generate_fixes_md.py --report report.json --stdout
```

### 2) GitLab MR comment generator

```bash
# in GitLab CI
python3 scripts/gitlab_mr_comment.py --report report.json

# local dry-run (no posting)
python3 scripts/gitlab_mr_comment.py --report report.json --no-post
```

### 3) Local GitLab-style demo runner

```bash
bash scripts/run_gitlab_ci_local_demo.sh
```

This generates:
- `demo/audit-report.json`
- `demo/audit-summary.md`
- `demo/fixes.md`

## Grade Logic

| Grade | Condition |
|------|-----------|
| `DANGER` | max risk >= 90 OR high-risk findings >= 3 |
| `WARNING` | max risk >= 70 OR high-risk findings >= 1 OR avg risk >= 50 |
| `SAFE` | no meaningful risk signal |

## Why this is stronger than regex-only scanning

1. Context-aware (`EXEC` vs `DOC`)
2. Multi-signal risk scoring instead of binary match/no-match
3. Actionability tagging to reduce noisy findings
4. Built-in fix recommendations
5. Baseline drift tracking over time
6. CI-ready pass/fail policy control

## Testing

```bash
python3 -m unittest -v tests/test_auditor.py
python3 -m py_compile auditor.py scripts/gitlab_mr_comment.py scripts/generate_fixes_md.py
```

## CI Example

```bash
python3 auditor.py --target ./skills --fail-on danger
python3 auditor.py --target ./skills --baseline baseline.json --out report.json
python3 scripts/gitlab_mr_comment.py --report report.json
```

## False Positive Tuning Tips

- Exclude docs/reference-heavy folders with `--exclude`
- Add known-safe domains to `--allow-domains`
- Start with `--fail-on danger`, then tighten policy gradually

## GitLab Duo Hackathon Assets

- `.gitlab-ci.yml`
- `scripts/gitlab_mr_comment.py`
- `scripts/generate_fixes_md.py`
- `scripts/run_gitlab_ci_local_demo.sh`
- `hackathon/HACKATHON_SUBMISSION.md`
- `hackathon/DEMO_SCRIPT_3MIN.md`
- `hackathon/GITLAB_LIVE_PROOF.md`
- `hackathon/gitlab-duo-flow-template.yml`

## License

MIT
