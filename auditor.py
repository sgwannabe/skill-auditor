#!/usr/bin/env python3
"""Skill-Auditor: Security scanner with risk scoring, auto-fixes, and baseline comparison."""

import argparse
import fnmatch
import json
import re
import sys
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple, Optional, Any
from urllib.parse import urlparse

DEFAULT_GLOBS = ["*.md", "*.py", "*.js", "*.ts", "*.json", "*.yaml", "*.yml", "*.sh"]
DEFAULT_EXCLUDES = [
    ".git/*",
    "node_modules/*",
    "__pycache__/*",
    "*.min.js",
    "report.json",
]
DEFAULT_ALLOW_DOMAINS = ["www.w3.org"]

RISK_WEIGHTS = {
    "severity": {"danger": 50, "warning": 25},
    "executable_context": 20,
    "actionable": 15,
    "category": {
        "destructive-command": 15,
        "credential-exfil": 15,
        "prompt-injection": 10,
        "shell-exec": 10,
        "network-call": 5,
        "suspicious": 5,
    },
}

HIGH_RISK_THRESHOLD = 70


@dataclass
class Finding:
    file: str
    line: int
    severity: str
    category: str
    pattern: str
    snippet: str
    executable_context: bool
    actionable: bool
    risk_score: int = 0
    fix_suggestion: Optional[str] = None


DANGER_RULES = [
    ("destructive-command", "rm -rf root", re.compile(r"rm\s+-rf\s+/(\s|$)"), 10),
    ("destructive-command", "mkfs usage", re.compile(r"\bmkfs\b"), 10),
    ("destructive-command", "dd to disk", re.compile(r"\bdd\b.*\bof=/dev/"), 10),
    (
        "credential-exfil",
        "send env secrets",
        re.compile(
            r"(curl|wget).*(\$\{?(OPENAI|ANTHROPIC|GITHUB|AWS|TOKEN|API_KEY)[A-Z0-9_]*\}?)",
            re.I,
        ),
        15,
    ),
    (
        "prompt-injection",
        "ignore previous instructions",
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
        5,
    ),
    ("prompt-injection", "you are now", re.compile(r"\byou\s+are\s+now\b", re.I), 5),
]

WARNING_RULES = [
    ("network-call", "curl invocation", re.compile(r"\bcurl\b"), 0),
    ("network-call", "wget invocation", re.compile(r"\bwget\b"), 0),
    (
        "shell-exec",
        "subprocess shell true",
        re.compile(r"subprocess\.(run|Popen)\(.*shell\s*=\s*True", re.I),
        10,
    ),
    ("shell-exec", "exec/eval", re.compile(r"\b(exec|eval)\s*\("), 10),
    (
        "prompt-injection",
        "do not tell user",
        re.compile(r"do\s+not\s+tell\s+the\s+user", re.I),
        5,
    ),
    (
        "prompt-injection",
        "execute immediately",
        re.compile(r"execute\s+immediately", re.I),
        5,
    ),
    (
        "suspicious",
        "base64 decode pipe shell",
        re.compile(r"base64\s+-d\s*\|\s*(bash|sh)"),
        10,
    ),
]

DOC_EXAMPLE_HINTS = [
    "example",
    "예시",
    "samples",
    "prompt injection",
    "injection patterns",
    "grep -riE",
]


def should_exclude(path: Path, excludes: List[str]) -> bool:
    p = path.as_posix()
    name = path.name
    return any(
        fnmatch.fnmatch(p, pat) or fnmatch.fnmatch(name, pat) for pat in excludes
    )


def iter_files(
    targets: List[Path], globs: List[str], excludes: List[str], max_file_kb: int
):
    max_bytes = max_file_kb * 1024
    for target in targets:
        if target.is_file():
            files = [target]
        else:
            files = [p for p in target.rglob("*") if p.is_file()]
        for p in files:
            if p.stat().st_size > max_bytes:
                continue
            if should_exclude(p, excludes):
                continue
            if any(fnmatch.fnmatch(p.name, g.strip()) for g in globs):
                yield p


def is_likely_executable(path: Path, line: str) -> bool:
    ext = path.suffix.lower()
    if ext in {".sh", ".py", ".js", ".ts"}:
        return True
    stripped = line.strip()
    command_prefixes = (
        "$ ",
        "curl ",
        "wget ",
        "bash ",
        "sh ",
        "python ",
        "python3 ",
        "node ",
    )
    return stripped.startswith(command_prefixes)


def looks_like_documentation_example(line: str) -> bool:
    s = line.lower().strip()
    if "`" in line:
        return True
    if s.startswith("- ") or s.startswith("* ") or s.startswith("#"):
        return True
    if any(h in s for h in DOC_EXAMPLE_HINTS):
        return True
    return False


def extract_domains(line: str) -> List[str]:
    urls = re.findall(r"https?://[^\s)\]>'\"]+", line)
    out = []
    for u in urls:
        try:
            host = (urlparse(u).hostname or "").lower()
            if host:
                out.append(host)
        except Exception:
            pass
    return out


def has_insecure_http(line: str) -> bool:
    urls = re.findall(r"http://[^\s)\]>'\"]+", line)
    return len(urls) > 0


def generate_fix_suggestion(
    category: str, pattern: str, line: str, path: Path
) -> Optional[str]:
    ext = path.suffix.lower()

    if category == "shell-exec" and "subprocess" in pattern.lower():
        if ext == ".py":
            return "Replace `shell=True` with `shell=False` and pass command as list. Example: subprocess.run(['ls', '-la']) instead of subprocess.run('ls -la', shell=True)"
        return "Avoid shell=True in subprocess calls. Use list-based commands without shell interpolation."

    if category == "shell-exec" and "exec/eval" in pattern.lower():
        if ext == ".py":
            return "Replace eval() with ast.literal_eval() for safe literal evaluation. Replace exec() with direct code or importlib for dynamic imports."
        elif ext in [".js", ".ts"]:
            return "Avoid eval() and new Function(). Use JSON.parse() for JSON, or structured alternatives for dynamic code."
        return "Avoid exec/eval. Use safer alternatives like literal_eval, JSON.parse, or structured configuration."

    if category == "network-call" and has_insecure_http(line):
        urls = re.findall(r"http://[^\s)\]>'\"]+", line)
        if urls:
            secure_urls = [u.replace("http://", "https://", 1) for u in urls]
            return f"Change HTTP to HTTPS: Replace {urls[0]} with {secure_urls[0]} (verify server supports HTTPS)"

    if category == "prompt-injection" and ext in [".py", ".sh", ".js", ".ts"]:
        if "ignore" in pattern.lower():
            return "Sanitize user input before including in prompts. Use allowlist validation or escape special patterns."
        if "you are now" in pattern.lower():
            return "Implement prompt boundaries and input validation. Use structured prompts with clear delimiters."
        if "do not tell" in pattern.lower():
            return "Add output filtering and logging. Implement response validation before returning to users."
        return "Validate and sanitize all user-controlled input before processing. Use prompt templates with strict boundaries."

    if category == "destructive-command":
        return "Ensure destructive commands are properly guarded with confirmation prompts and dry-run modes."

    if category == "credential-exfil":
        return "Never transmit secrets via command-line tools. Use secure secret management and environment injection."

    return None


def calculate_risk_score(
    severity: str,
    category: str,
    executable_context: bool,
    actionable: bool,
    risk_modifier: int = 0,
) -> int:
    score = 0
    score += RISK_WEIGHTS["severity"].get(severity, 0)
    score += RISK_WEIGHTS["category"].get(category, 0)
    if executable_context:
        score += RISK_WEIGHTS["executable_context"]
    if actionable:
        score += RISK_WEIGHTS["actionable"]
    score += risk_modifier
    return max(0, min(100, score))


def effective_severity(
    base_severity: str, category: str, line: str, strict_docs: bool
) -> Tuple[str, bool]:
    executable = True
    if (
        category == "prompt-injection"
        and not strict_docs
        and looks_like_documentation_example(line)
    ):
        return "warning", False
    return base_severity, executable


def is_actionable(
    path: Path, category: str, line: str, executable: bool, allow_domains: List[str]
) -> bool:
    if not executable:
        return False
    if category == "network-call":
        domains = extract_domains(line)
        if domains and all(d in allow_domains for d in domains):
            return False
    return True


def scan_text(
    path: Path, text: str, strict_docs: bool, allow_domains: List[str]
) -> List[Finding]:
    findings = []
    for i, line in enumerate(text.splitlines(), start=1):
        for category, pattern_name, rx, risk_modifier in DANGER_RULES:
            if rx.search(line):
                sev, exec_ctx = effective_severity(
                    "danger", category, line, strict_docs
                )
                exec_ctx = exec_ctx and is_likely_executable(path, line)
                actionable = is_actionable(
                    path, category, line, exec_ctx, allow_domains
                )
                risk_score = calculate_risk_score(
                    sev, category, exec_ctx, actionable, risk_modifier
                )
                fix_suggestion = generate_fix_suggestion(
                    category, pattern_name, line, path
                )
                findings.append(
                    Finding(
                        str(path),
                        i,
                        sev,
                        category,
                        pattern_name,
                        line.strip()[:220],
                        exec_ctx,
                        actionable,
                        risk_score,
                        fix_suggestion,
                    )
                )

        for category, pattern_name, rx, risk_modifier in WARNING_RULES:
            if rx.search(line):
                sev, exec_ctx = effective_severity(
                    "warning", category, line, strict_docs
                )
                exec_ctx = exec_ctx and is_likely_executable(path, line)
                actionable = is_actionable(
                    path, category, line, exec_ctx, allow_domains
                )
                risk_score = calculate_risk_score(
                    sev, category, exec_ctx, actionable, risk_modifier
                )
                fix_suggestion = generate_fix_suggestion(
                    category, pattern_name, line, path
                )
                findings.append(
                    Finding(
                        str(path),
                        i,
                        sev,
                        category,
                        pattern_name,
                        line.strip()[:220],
                        exec_ctx,
                        actionable,
                        risk_score,
                        fix_suggestion,
                    )
                )
    return findings


def classify(findings: List[Finding]) -> str:
    if not findings:
        return "SAFE"
    avg_risk = sum(f.risk_score for f in findings) / len(findings)
    max_risk = max(f.risk_score for f in findings) if findings else 0
    high_risk_count = sum(1 for f in findings if f.risk_score >= HIGH_RISK_THRESHOLD)

    if max_risk >= 90 or high_risk_count >= 3:
        return "DANGER"
    if max_risk >= 70 or high_risk_count >= 1 or avg_risk >= 50:
        return "WARNING"
    if findings:
        return "WARNING"
    return "SAFE"


def summarize(findings: List[Finding]) -> Dict[str, int]:
    out = {"danger": 0, "warning": 0, "executable": 0, "actionable": 0}
    for f in findings:
        out[f.severity] += 1
        if f.executable_context:
            out["executable"] += 1
        if f.actionable:
            out["actionable"] += 1
    return out


def calculate_risk_metrics(findings: List[Finding]) -> Dict[str, Any]:
    if not findings:
        return {
            "average_risk": 0.0,
            "max_risk": 0,
            "high_risk_count": 0,
            "total_risk_score": 0,
        }

    risk_scores = [f.risk_score for f in findings]
    return {
        "average_risk": round(sum(risk_scores) / len(risk_scores), 2),
        "max_risk": max(risk_scores),
        "high_risk_count": sum(1 for s in risk_scores if s >= HIGH_RISK_THRESHOLD),
        "total_risk_score": sum(risk_scores),
    }


def calculate_review_time_saved(findings: List[Finding]) -> int:
    total_minutes = 0
    for f in findings:
        if f.actionable:
            total_minutes += 2
            if f.fix_suggestion:
                total_minutes += 3
            if f.risk_score >= HIGH_RISK_THRESHOLD:
                total_minutes += 2
    return total_minutes


def compute_baseline_delta(
    current_report: Dict, baseline_report: Dict
) -> Dict[str, Any]:
    current_metrics = current_report.get("risk_metrics", {})
    baseline_metrics = baseline_report.get("risk_metrics", {})
    current_actionable = current_report.get("severity", {}).get("actionable", 0)
    baseline_actionable = baseline_report.get("severity", {}).get("actionable", 0)

    return {
        "actionable_delta": current_actionable - baseline_actionable,
        "high_risk_delta": current_metrics.get("high_risk_count", 0)
        - baseline_metrics.get("high_risk_count", 0),
        "max_risk_delta": current_metrics.get("max_risk", 0)
        - baseline_metrics.get("max_risk", 0),
        "average_risk_delta": round(
            current_metrics.get("average_risk", 0)
            - baseline_metrics.get("average_risk", 0),
            2,
        ),
        "findings_delta": current_report.get("findings_total", 0)
        - baseline_report.get("findings_total", 0),
    }


def build_report(
    targets: List[Path],
    globs: List[str],
    excludes: List[str],
    max_file_kb: int,
    strict_docs: bool = False,
    allow_domains: Optional[List[str]] = None,
    baseline_report: Optional[Dict] = None,
) -> Dict:
    all_findings = []
    scanned_files = 0
    allow_domains = [d.lower() for d in (allow_domains or DEFAULT_ALLOW_DOMAINS)]

    for p in iter_files(targets, globs, excludes, max_file_kb):
        scanned_files += 1
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        all_findings.extend(scan_text(p, txt, strict_docs, allow_domains))

    grade = classify(all_findings)
    sev = summarize(all_findings)
    risk_metrics = calculate_risk_metrics(all_findings)

    categories = {}
    for f in all_findings:
        categories[f.category] = categories.get(f.category, 0) + 1

    report = {
        "grade": grade,
        "scanned_files": scanned_files,
        "findings_total": len(all_findings),
        "severity": sev,
        "categories": categories,
        "risk_metrics": risk_metrics,
        "estimated_review_minutes_saved": calculate_review_time_saved(all_findings),
        "high_risk_threshold": HIGH_RISK_THRESHOLD,
        "allow_domains": allow_domains,
        "findings": [asdict(f) for f in all_findings],
    }

    if baseline_report:
        report["baseline_comparison"] = compute_baseline_delta(report, baseline_report)

    return report


def should_fail(report: Dict, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    actionable = report.get("severity", {}).get("actionable", 0)
    danger = report.get("severity", {}).get("danger", 0)
    max_risk = report.get("risk_metrics", {}).get("max_risk", 0)
    high_risk_count = report.get("risk_metrics", {}).get("high_risk_count", 0)

    if fail_on == "warning":
        return actionable > 0 or high_risk_count > 0
    if fail_on == "danger":
        return (report.get("grade") == "DANGER" and danger > 0) or max_risk >= 90
    return False


def main():
    ap = argparse.ArgumentParser(
        description="Skill-Auditor: Security scanner with risk scoring and auto-fixes"
    )
    ap.add_argument(
        "--target", action="append", required=True, help="Scan target path (repeatable)"
    )
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument(
        "--max-file-kb", type=int, default=256, help="Skip files larger than this"
    )
    ap.add_argument(
        "--include",
        default=",".join(DEFAULT_GLOBS),
        help="Comma-separated glob patterns",
    )
    ap.add_argument(
        "--exclude",
        default=",".join(DEFAULT_EXCLUDES),
        help="Comma-separated exclude patterns",
    )
    ap.add_argument("--out", default="", help="Write JSON report to file path")
    ap.add_argument(
        "--strict-docs",
        action="store_true",
        help="Do not downgrade documentation examples",
    )
    ap.add_argument(
        "--allow-domains",
        default=",".join(DEFAULT_ALLOW_DOMAINS),
        help="Comma-separated trusted domains",
    )
    ap.add_argument(
        "--fail-on",
        choices=["danger", "warning", "never"],
        default="never",
        help="Exit non-zero based on actionable risk",
    )
    ap.add_argument(
        "--baseline", default="", help="Path to baseline report JSON for comparison"
    )
    args = ap.parse_args()

    targets = [Path(t).expanduser().resolve() for t in args.target]
    missing = [str(t) for t in targets if not t.exists()]
    if missing:
        raise SystemExit(f"Target not found: {', '.join(missing)}")

    globs = [g.strip() for g in args.include.split(",") if g.strip()]
    excludes = [e.strip() for e in args.exclude.split(",") if e.strip()]
    allow_domains = [
        d.strip().lower() for d in args.allow_domains.split(",") if d.strip()
    ]

    baseline_report = None
    if args.baseline:
        baseline_path = Path(args.baseline).expanduser().resolve()
        if baseline_path.exists():
            try:
                baseline_report = json.loads(baseline_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, Exception) as e:
                print(f"Warning: Could not load baseline report: {e}", file=sys.stderr)
        else:
            print(
                f"Warning: Baseline report not found: {args.baseline}", file=sys.stderr
            )

    report = build_report(
        targets,
        globs,
        excludes,
        args.max_file_kb,
        args.strict_docs,
        allow_domains,
        baseline_report,
    )

    if args.out:
        Path(args.out).write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        sev = report["severity"]
        risk = report["risk_metrics"]
        print(f"Grade: {report['grade']}")
        print(f"Scanned files: {report['scanned_files']}")
        print(
            f"Findings: {report['findings_total']} (danger={sev['danger']}, warning={sev['warning']}, executable={sev['executable']}, actionable={sev['actionable']})"
        )
        print(
            f"Risk Metrics: avg={risk['average_risk']}, max={risk['max_risk']}, high_risk={risk['high_risk_count']}"
        )
        if report["estimated_review_minutes_saved"] > 0:
            print(
                f"Estimated review time saved: ~{report['estimated_review_minutes_saved']} minutes"
            )
        if report.get("baseline_comparison"):
            delta = report["baseline_comparison"]
            print(
                f"Baseline Delta: actionable={delta['actionable_delta']:+d}, high_risk={delta['high_risk_delta']:+d}, max_risk={delta['max_risk_delta']:+d}"
            )
        if report["categories"]:
            print("Categories:")
            for k, v in sorted(
                report["categories"].items(), key=lambda x: (-x[1], x[0])
            ):
                print(f"  - {k}: {v}")
        findings = report["findings"]
        if findings:
            print("\nTop findings:")
            sorted_findings = sorted(
                findings, key=lambda x: x.get("risk_score", 0), reverse=True
            )
            for f in sorted_findings[:30]:
                exec_tag = "EXEC" if f["executable_context"] else "DOC"
                act_tag = "ACT" if f["actionable"] else "INFO"
                fix_hint = " [FIXABLE]" if f.get("fix_suggestion") else ""
                print(
                    f"- [{f['severity'].upper()}/{exec_tag}/{act_tag}] Risk={f.get('risk_score', 0)}{fix_hint} {f['file']}:{f['line']} | {f['category']} | {f['pattern']}"
                )
                print(f"    {f['snippet']}")
                if f.get("fix_suggestion"):
                    print(f"    Fix: {f['fix_suggestion'][:120]}...")

    if should_fail(report, args.fail_on):
        sys.exit(2)


if __name__ == "__main__":
    main()
