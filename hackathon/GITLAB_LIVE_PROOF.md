# GitLab Live Proof Runbook

## Goal
Demonstrate real MR trigger -> CI scan -> MR comment flow on GitLab.

## Prerequisites
1. Project created under `https://gitlab.com/gitlab-ai-hackathon/...`
2. CI enabled for the project
3. `GITLAB_TOKEN` configured in project CI variables (or ensure `CI_JOB_TOKEN` can post MR notes)
4. `.gitlab-ci.yml` from this repo committed

## Steps
1. Create branch with intentional risky snippet (e.g., `shell=True`)
2. Open MR to `main`
3. Confirm pipeline job `skill_audit_mr` runs
4. Verify artifacts are generated:
   - `audit-report.json`
   - `audit-summary.md`
5. Verify MR note posted by `scripts/gitlab_mr_comment.py`
6. Push fix commit and verify risk goes down in next run

## Local pre-flight (no GitLab token required)
```bash
bash scripts/run_gitlab_ci_local_demo.sh
```

## Demo capture checklist (3 min)
- Show risky commit in MR
- Show pipeline auto trigger
- Show MR comment with recommendation + top 5 findings + fix suggestions
- Apply fix and rerun
- Show reduced risk metrics / recommendation improvement
