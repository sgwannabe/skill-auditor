#!/usr/bin/env python3
"""Generate markdown fix suggestions from Skill-Auditor report JSON.

Reads a report JSON file and outputs a formatted markdown document
with prioritized fix suggestions for actionable findings.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional


def format_risk_badge(risk_score: int, threshold: int) -> str:
    """Generate a visual risk indicator."""
    if risk_score >= 90:
        return f"🔴 **{risk_score}** (Critical)"
    elif risk_score >= threshold:
        return f"🟠 **{risk_score}** (High)"
    elif risk_score >= 50:
        return f"🟡 **{risk_score}** (Medium)"
    else:
        return f"🟢 **{risk_score}** (Low)"


def generate_fixes_markdown(report: Dict) -> str:
    """Generate markdown document from report findings."""
    lines = []

    # Header
    lines.append("# 🔧 Skill-Auditor Fix Suggestions")
    lines.append("")

    # Summary section
    grade = report.get("grade", "UNKNOWN")
    findings_total = report.get("findings_total", 0)
    risk_metrics = report.get("risk_metrics", {})
    threshold = report.get("high_risk_threshold", 70)
    time_saved = report.get("estimated_review_minutes_saved", 0)

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Grade:** {grade}")
    lines.append(f"- **Total Findings:** {findings_total}")
    lines.append(f"- **Average Risk:** {risk_metrics.get('average_risk', 0)}")
    lines.append(f"- **Max Risk:** {risk_metrics.get('max_risk', 0)}")
    lines.append(f"- **High Risk Count:** {risk_metrics.get('high_risk_count', 0)}")
    if time_saved > 0:
        lines.append(f"- **Estimated Review Time Saved:** ~{time_saved} minutes")
    lines.append("")

    # Get actionable findings with fix suggestions
    findings = report.get("findings", [])
    actionable_with_fixes = [
        f for f in findings if f.get("actionable") and f.get("fix_suggestion")
    ]

    # Sort by risk score descending
    actionable_with_fixes.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

    if not actionable_with_fixes:
        lines.append("## ✅ No Actionable Fixes Required")
        lines.append("")
        lines.append("No actionable findings with fix suggestions were detected.")
        return "\n".join(lines)

    # Priority fixes section
    lines.append("## 🎯 Priority Fixes")
    lines.append("")
    lines.append(
        f"Found **{len(actionable_with_fixes)}** actionable findings with suggested fixes."
    )
    lines.append("")

    for i, f in enumerate(actionable_with_fixes, 1):
        file_path = f.get("file", "unknown")
        line_num = f.get("line", 0)
        category = f.get("category", "unknown")
        pattern = f.get("pattern", "unknown")
        snippet = f.get("snippet", "")
        risk_score = f.get("risk_score", 0)
        fix_suggestion = f.get("fix_suggestion", "")

        lines.append(f"### {i}. [{category}] {pattern}")
        lines.append("")
        lines.append(f"**Location:** `{file_path}:{line_num}`")
        lines.append("")
        lines.append(f"**Risk Score:** {format_risk_badge(risk_score, threshold)}")
        lines.append("")

        # Code snippet
        if snippet:
            lines.append("**Current Code:**")
            lines.append("```")
            lines.append(snippet[:200])  # Limit snippet length
            lines.append("```")
            lines.append("")

        # Fix suggestion
        lines.append("**Suggested Fix:**")
        lines.append(f"> {fix_suggestion}")
        lines.append("")
        lines.append("---")
        lines.append("")

    # High-risk findings without fixes
    high_risk_no_fix = [
        f
        for f in findings
        if f.get("actionable")
        and f.get("risk_score", 0) >= threshold
        and not f.get("fix_suggestion")
    ]

    if high_risk_no_fix:
        lines.append("## ⚠️ High-Risk Findings (Manual Review Required)")
        lines.append("")
        lines.append("The following high-risk findings require manual review:")
        lines.append("")

        for f in high_risk_no_fix[:10]:  # Limit to top 10
            file_path = f.get("file", "unknown")
            line_num = f.get("line", 0)
            category = f.get("category", "unknown")
            pattern = f.get("pattern", "unknown")
            risk_score = f.get("risk_score", 0)

            lines.append(f"- **{format_risk_badge(risk_score, threshold)}** ")
            lines.append(f"  `{file_path}:{line_num}` - [{category}] {pattern}")
            lines.append("")

    # Category breakdown
    categories = report.get("categories", {})
    if categories:
        lines.append("## 📊 Category Breakdown")
        lines.append("")
        lines.append("| Category | Count |")
        lines.append("|----------|-------|")
        for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
            lines.append(f"| {cat} | {count} |")
        lines.append("")

    # Baseline comparison if available
    baseline = report.get("baseline_comparison")
    if baseline:
        lines.append("## 📈 Baseline Comparison")
        lines.append("")
        lines.append("| Metric | Delta |")
        lines.append("|--------|-------|")
        lines.append(f"| Findings | {baseline.get('findings_delta', 0):+d} |")
        lines.append(f"| Actionable | {baseline.get('actionable_delta', 0):+d} |")
        lines.append(f"| High Risk | {baseline.get('high_risk_delta', 0):+d} |")
        lines.append(f"| Max Risk | {baseline.get('max_risk_delta', 0):+d} |")
        lines.append(f"| Avg Risk | {baseline.get('average_risk_delta', 0):+.2f} |")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append("")
    lines.append("*Generated by Skill-Auditor*")
    lines.append("")

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(
        description="Generate markdown fix suggestions from Skill-Auditor report"
    )
    ap.add_argument("--report", required=True, help="Path to Skill-Auditor JSON report")
    ap.add_argument(
        "--out",
        default="fixes.md",
        help="Output markdown file path (default: fixes.md)",
    )
    ap.add_argument(
        "--stdout", action="store_true", help="Print output to stdout instead of file"
    )
    args = ap.parse_args()

    # Load report
    report_path = Path(args.report).expanduser().resolve()
    if not report_path.exists():
        print(f"Error: Report file not found: {args.report}", file=sys.stderr)
        sys.exit(1)

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in report file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: Could not read report file: {e}", file=sys.stderr)
        sys.exit(1)

    # Generate markdown
    markdown = generate_fixes_markdown(report)

    if args.stdout:
        print(markdown)
    else:
        output_path = Path(args.out).expanduser().resolve()
        output_path.write_text(markdown, encoding="utf-8")
        print(f"Fix suggestions written to: {output_path}")

        # Print summary
        actionable_count = sum(
            1
            for f in report.get("findings", [])
            if f.get("actionable") and f.get("fix_suggestion")
        )
        print(f"  - {actionable_count} findings with fix suggestions")
        print(
            f"  - Estimated time saved: ~{report.get('estimated_review_minutes_saved', 0)} minutes"
        )


if __name__ == "__main__":
    main()
