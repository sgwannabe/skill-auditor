#!/usr/bin/env python3
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict
from urllib import request
from urllib.parse import quote_plus


def get_pass_fail_recommendation(report: Dict) -> str:
    grade = report.get("grade", "SAFE")
    risk_metrics = report.get("risk_metrics", {})
    high_risk_count = risk_metrics.get("high_risk_count", 0)
    max_risk = risk_metrics.get("max_risk", 0)
    actionable = report.get("severity", {}).get("actionable", 0)

    if grade == "DANGER" or max_risk >= 90 or high_risk_count >= 3:
        return "FAIL - Critical security issues detected. Review required before merge."
    elif grade == "WARNING" or high_risk_count >= 1 or actionable > 5:
        return "CONDITIONAL - Security concerns identified. Review recommended."
    else:
        return "PASS - No significant security issues detected."


def format_risk_indicator(score: int, threshold: int) -> str:
    if score >= 90:
        return f"Critical ({score})"
    elif score >= threshold:
        return f"High ({score})"
    elif score >= 50:
        return f"Medium ({score})"
    else:
        return f"Low ({score})"


def make_summary(report: Dict) -> str:
    lines = []

    sev = report.get("severity", {})
    risk_metrics = report.get("risk_metrics", {})
    findings = report.get("findings", [])
    threshold = report.get("high_risk_threshold", 70)
    time_saved = report.get("estimated_review_minutes_saved", 0)

    lines.append("## Skill-Auditor Security Report")
    lines.append("")

    recommendation = get_pass_fail_recommendation(report)
    lines.append(f"**Recommendation:** {recommendation}")
    lines.append("")

    lines.append("### Risk Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Grade | **{report.get('grade', 'UNKNOWN')}** |")
    lines.append(f"| Scanned Files | {report.get('scanned_files', 0)} |")
    lines.append(f"| Total Findings | {report.get('findings_total', 0)} |")
    lines.append(f"| Actionable | {sev.get('actionable', 0)} |")
    lines.append(f"| Average Risk | {risk_metrics.get('average_risk', 0)} |")
    lines.append(
        f"| Max Risk | {format_risk_indicator(risk_metrics.get('max_risk', 0), threshold)} |"
    )
    lines.append(f"| High Risk Count | {risk_metrics.get('high_risk_count', 0)} |")
    if time_saved > 0:
        lines.append(f"| Est. Time Saved | ~{time_saved} min |")
    lines.append("")

    baseline = report.get("baseline_comparison")
    if baseline:
        lines.append("### Baseline Comparison")
        lines.append("")
        lines.append("| Metric | Delta |")
        lines.append("|--------|-------|")
        lines.append(f"| Findings | {baseline.get('findings_delta', 0):+d} |")
        lines.append(f"| Actionable | {baseline.get('actionable_delta', 0):+d} |")
        lines.append(f"| High Risk | {baseline.get('high_risk_delta', 0):+d} |")
        lines.append(f"| Max Risk | {baseline.get('max_risk_delta', 0):+d} |")
        lines.append("")

    actionable_findings = [f for f in findings if f.get("actionable")]
    actionable_findings.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

    if actionable_findings:
        lines.append("### Top 5 High-Risk Actionable Findings")
        lines.append("")

        for i, f in enumerate(actionable_findings[:5], 1):
            file_path = f.get("file", "unknown")
            line_num = f.get("line", 0)
            category = f.get("category", "unknown")
            pattern = f.get("pattern", "unknown")
            risk_score = f.get("risk_score", 0)
            severity = f.get("severity", "warning")

            display_path = file_path
            if len(display_path) > 60:
                display_path = "..." + display_path[-57:]

            lines.append(f"{i}. **{format_risk_indicator(risk_score, threshold)}**")
            lines.append(
                f"   `{display_path}:{line_num}` [{severity.upper()}] {category}"
            )
            lines.append(f"   - Pattern: {pattern}")
            lines.append("")
    else:
        lines.append("### No Actionable Findings")
        lines.append("")
        lines.append("No actionable security issues were detected.")
        lines.append("")

    findings_with_fixes = [f for f in actionable_findings if f.get("fix_suggestion")][
        :5
    ]

    if findings_with_fixes:
        lines.append("### Fix Suggestions")
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>Click to view suggested fixes</summary>")
        lines.append("")

        for f in findings_with_fixes:
            file_path = f.get("file", "unknown")
            line_num = f.get("line", 0)
            category = f.get("category", "unknown")
            fix_suggestion = f.get("fix_suggestion", "")

            lines.append(f"**{category}** - `{Path(file_path).name}:{line_num}`")
            lines.append(f"```")
            lines.append(f"{fix_suggestion[:200]}")
            lines.append(f"```")
            lines.append("")

        lines.append("</details>")
        lines.append("")

    categories = report.get("categories", {})
    if categories:
        lines.append("### Categories")
        lines.append("")
        cat_items = [
            f"{k}: {v}" for k, v in sorted(categories.items(), key=lambda x: -x[1])
        ]
        lines.append(" | ".join(cat_items[:6]))
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("*Report generated by Skill-Auditor*")
    lines.append("")

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
    ap = argparse.ArgumentParser(
        description="Generate GitLab MR comment from Skill-Auditor report"
    )
    ap.add_argument("--report", required=True, help="Path to Skill-Auditor JSON report")
    ap.add_argument("--summary", default="audit-summary.md", help="Output summary file")
    ap.add_argument(
        "--no-post",
        action="store_true",
        help="Generate summary but do not post to GitLab",
    )
    args = ap.parse_args()

    report_path = Path(args.report).expanduser().resolve()
    if not report_path.exists():
        print(f"Error: Report file not found: {args.report}", file=sys.stderr)
        sys.exit(1)

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: Could not read report: {e}", file=sys.stderr)
        sys.exit(1)

    summary = make_summary(report)
    Path(args.summary).write_text(summary, encoding="utf-8")
    print(f"Summary written to: {args.summary}")

    if not args.no_post:
        ok, msg = post_gitlab_note(summary)
        print(f"GitLab note posted: {ok} ({msg})")
    else:
        print("GitLab posting skipped (--no-post)")

    print(f"\nRecommendation: {get_pass_fail_recommendation(report)}")


if __name__ == "__main__":
    main()
