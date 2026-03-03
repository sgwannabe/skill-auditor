# GitLab AI Hackathon Submission Plan

## Project
Duo Skill Auditor Agent

## Problem
AI-assisted repos and agent skills can introduce prompt-injection and unsafe automation patterns. Manual review is slow and inconsistent.

## Solution
A GitLab Duo-triggered flow that runs Skill-Auditor on every merge request and posts actionable findings as an MR note.

## Trigger -> Action Evidence
1. Trigger: MR updated (`merge_request_event`)
2. Action: `.gitlab-ci.yml` job `skill_audit_mr` runs `auditor.py`
3. Action: `scripts/gitlab_mr_comment.py` writes `audit-summary.md` and posts MR note
4. Optional: apply `security-risk` label

## Required Assets
- Public repo with MIT license
- Setup instructions in README
- 3-minute demo video showing trigger -> action
- GitLab group project URL (`gitlab-ai-hackathon`)

## Demo checklist
- Open MR with intentionally risky snippet
- Show pipeline run
- Show MR comment generated from report
- Show actionable finding and fix commit
