#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
from urllib import request
from urllib.parse import quote_plus


def make_summary(report: dict) -> str:
    sev = report.get("severity", {})
    findings = report.get("findings", [])
    actionable = [f for f in findings if f.get("actionable")]
    lines = []
    lines.append("## 🔐 Skill-Auditor Report")
    lines.append("")
    lines.append(f"- Grade: **{report.get('grade', 'UNKNOWN')}**")
    lines.append(f"- Scanned files: **{report.get('scanned_files', 0)}**")
    lines.append(f"- Findings: **{report.get('findings_total', 0)}**")
    lines.append(f"- Actionable: **{sev.get('actionable', 0)}**")
    lines.append("")
    if actionable:
        lines.append("### Actionable findings (top 10)")
        for f in actionable[:10]:
            lines.append(f"- `{f['file']}:{f['line']}` [{f['severity']}] {f['category']} — {f['pattern']}")
    else:
        lines.append("✅ No actionable findings.")
    return "\n".join(lines)


def post_gitlab_note(body: str):
    token = os.getenv("GITLAB_TOKEN") or os.getenv("CI_JOB_TOKEN")
    api = os.getenv("CI_API_V4_URL")
    project_id = os.getenv("CI_PROJECT_ID")
    mr_iid = os.getenv("CI_MERGE_REQUEST_IID")
    if not (token and api and project_id and mr_iid):
        return False, "missing GitLab CI env vars for note posting"

    url = f"{api}/projects/{project_id}/merge_requests/{mr_iid}/notes"
    data = f"body={quote_plus(body)}".encode()
    req = request.Request(url, data=data, method="POST")
    req.add_header("PRIVATE-TOKEN", token)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with request.urlopen(req, timeout=20) as resp:
            return True, f"posted ({resp.status})"
    except Exception as e:
        return False, str(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True)
    ap.add_argument("--summary", default="audit-summary.md")
    args = ap.parse_args()

    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    summary = make_summary(report)
    Path(args.summary).write_text(summary, encoding="utf-8")

    ok, msg = post_gitlab_note(summary)
    print(f"note_posted={ok} msg={msg}")


if __name__ == "__main__":
    main()
