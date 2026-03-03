# Skill-Auditor Final Report (2026-03-03 10:16 KST)

- Overall grade: **DANGER**
- Scanned files: **71**
- Raw findings: **40**
- Actionable findings after triage: **9**

## Actionable Findings
1. `/Users/cortana/.openclaw/workspace/skills/abm-outbound/SKILL.md:55` [warning] network-call - curl invocation
   - `curl -X POST "https://api.apify.com/v2/acts/harvestapi~linkedin-profile-scraper/run-sync-get-dataset-items" \`
2. `/Users/cortana/.openclaw/workspace/skills/abm-outbound/SKILL.md:71` [warning] network-call - curl invocation
   - `curl -X POST "https://api.apollo.io/api/v1/people/bulk_match" \`
3. `/Users/cortana/.openclaw/workspace/skills/abm-outbound/SKILL.md:91` [warning] network-call - curl invocation
   - `curl -X POST "https://api.apify.com/v2/acts/one-api~skip-trace/run-sync-get-dataset-items" \`
4. `/Users/cortana/.openclaw/workspace/skills/abm-outbound/SKILL.md:107` [warning] network-call - curl invocation
   - `curl -X POST "https://api.apollo.io/api/v1/emailer_campaigns/add_contact_ids" \`
5. `/Users/cortana/.openclaw/workspace/skills/abm-outbound/SKILL.md:119` [warning] network-call - curl invocation
   - `curl -X POST "https://api.instantly.ai/api/v1/lead/add" \`
6. `/Users/cortana/.openclaw/workspace/skills/abm-outbound/SKILL.md:149` [warning] network-call - curl invocation
   - `curl -X POST "https://platform.scribeless.co/api/recipients" \`
7. `/Users/cortana/.openclaw/workspace/skills/secucheck/scripts/runtime_check.sh:66` [warning] network-call - curl invocation
   - `external_ip=$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null || curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "")`
8. `/Users/cortana/.openclaw/workspace/skills/secucheck/scripts/gather_agents.sh:134` [warning] network-call - curl invocation
   - `if grep -qiE "api|webhook|http|curl" "$WORKSPACE_DIR/AGENTS.md" 2>/dev/null; then`
9. `/Users/cortana/.openclaw/workspace/skills/secucheck/scenarios/unauthorized-access.md:53` [warning] network-call - curl invocation
   - `curl http://target:18789/`

## Risk Decision
- Immediate quarantine to `archive/danger-skills/`: **Not required**
- Reason: no confirmed malicious execution path found in active skills.

## Recommended Hardening (done/next)
- [x] Added `--strict-docs` mode and `EXEC/DOC` context tagging.
- [x] Added exclude patterns for references/assets/noise.
- [ ] Add allowlist file for known-safe detector patterns.
- [ ] Add CI gate: fail only on confirmed actionable danger.