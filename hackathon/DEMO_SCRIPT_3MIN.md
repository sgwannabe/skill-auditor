# 3-Minute Demo Script

## 0:00-0:20
"Teams ship faster with AI, but security review is now a bottleneck. We built Duo Skill Auditor Agent to automate that review in GitLab."

## 0:20-0:50
Show repository + architecture quick view (`.gitlab-ci.yml`, `auditor.py`, `scripts/gitlab_mr_comment.py`).

## 0:50-1:40
Create/update MR with sample risky pattern.
Show pipeline start automatically.

## 1:40-2:20
Show generated `audit-summary.md` and MR note.
Highlight actionable finding with file/line.

## 2:20-2:50
Apply fix commit.
Re-run pipeline.
Show reduced/no actionable findings.

## 2:50-3:00
"This flow reduces manual toil and catches risky automation before merge."
