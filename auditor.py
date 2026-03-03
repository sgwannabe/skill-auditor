#!/usr/bin/env python3
import argparse
import fnmatch
import json
import re
import sys
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple
from urllib.parse import urlparse

DEFAULT_GLOBS = ["*.md", "*.py", "*.js", "*.ts", "*.json", "*.yaml", "*.yml", "*.sh"]
DEFAULT_EXCLUDES = [".git/*", "node_modules/*", "__pycache__/*", "*.min.js", "report.json"]
DEFAULT_ALLOW_DOMAINS = ["www.w3.org"]

@dataclass
class Finding:
    file: str
    line: int
    severity: str  # warning|danger
    category: str
    pattern: str
    snippet: str
    executable_context: bool
    actionable: bool

DANGER_RULES: List[Tuple[str, str, re.Pattern]] = [
    ("destructive-command", "rm -rf root", re.compile(r"rm\s+-rf\s+/(\s|$)")),
    ("destructive-command", "mkfs usage", re.compile(r"\bmkfs\b")),
    ("destructive-command", "dd to disk", re.compile(r"\bdd\b.*\bof=/dev/")),
    ("credential-exfil", "send env secrets", re.compile(r"(curl|wget).*(\$\{?(OPENAI|ANTHROPIC|GITHUB|AWS|TOKEN|API_KEY)[A-Z0-9_]*\}?)", re.I)),
    ("prompt-injection", "ignore previous instructions", re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I)),
    ("prompt-injection", "you are now", re.compile(r"\byou\s+are\s+now\b", re.I)),
]

WARNING_RULES: List[Tuple[str, str, re.Pattern]] = [
    ("network-call", "curl invocation", re.compile(r"\bcurl\b")),
    ("network-call", "wget invocation", re.compile(r"\bwget\b")),
    ("shell-exec", "subprocess shell true", re.compile(r"subprocess\.(run|Popen)\(.*shell\s*=\s*True", re.I)),
    ("shell-exec", "exec/eval", re.compile(r"\b(exec|eval)\s*\(")),
    ("prompt-injection", "do not tell user", re.compile(r"do\s+not\s+tell\s+the\s+user", re.I)),
    ("prompt-injection", "execute immediately", re.compile(r"execute\s+immediately", re.I)),
    ("suspicious", "base64 decode pipe shell", re.compile(r"base64\s+-d\s*\|\s*(bash|sh)")),
]

DOC_EXAMPLE_HINTS = [
    "example", "예시", "samples", "prompt injection", "injection patterns", "grep -riE"
]


def should_exclude(path: Path, excludes: List[str]) -> bool:
    p = path.as_posix()
    name = path.name
    return any(fnmatch.fnmatch(p, pat) or fnmatch.fnmatch(name, pat) for pat in excludes)


def iter_files(targets: List[Path], globs: List[str], excludes: List[str], max_file_kb: int):
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
    command_prefixes = ("$ ", "curl ", "wget ", "bash ", "sh ", "python ", "python3 ", "node ")
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


def effective_severity(base_severity: str, category: str, line: str, strict_docs: bool) -> Tuple[str, bool]:
    executable = True
    if category == "prompt-injection" and not strict_docs and looks_like_documentation_example(line):
        return "warning", False
    return base_severity, executable


def is_actionable(path: Path, category: str, line: str, executable: bool, allow_domains: List[str]) -> bool:
    if not executable:
        return False
    if category == "network-call":
        domains = extract_domains(line)
        if domains and all(d in allow_domains for d in domains):
            return False
    return True


def scan_text(path: Path, text: str, strict_docs: bool, allow_domains: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        for category, pattern_name, rx in DANGER_RULES:
            if rx.search(line):
                sev, exec_ctx = effective_severity("danger", category, line, strict_docs)
                exec_ctx = exec_ctx and is_likely_executable(path, line)
                findings.append(Finding(str(path), i, sev, category, pattern_name, line.strip()[:220], exec_ctx, is_actionable(path, category, line, exec_ctx, allow_domains)))
        for category, pattern_name, rx in WARNING_RULES:
            if rx.search(line):
                sev, exec_ctx = effective_severity("warning", category, line, strict_docs)
                exec_ctx = exec_ctx and is_likely_executable(path, line)
                findings.append(Finding(str(path), i, sev, category, pattern_name, line.strip()[:220], exec_ctx, is_actionable(path, category, line, exec_ctx, allow_domains)))
    return findings


def classify(findings: List[Finding]) -> str:
    if any(f.severity == "danger" and f.actionable for f in findings):
        return "DANGER"
    if any(f.actionable for f in findings):
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


def build_report(targets: List[Path], globs: List[str], excludes: List[str], max_file_kb: int, strict_docs: bool = False, allow_domains: List[str] = None) -> Dict:
    all_findings: List[Finding] = []
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
    categories: Dict[str, int] = {}
    for f in all_findings:
        categories[f.category] = categories.get(f.category, 0) + 1

    return {
        "grade": grade,
        "scanned_files": scanned_files,
        "findings_total": len(all_findings),
        "severity": sev,
        "categories": categories,
        "allow_domains": allow_domains,
        "findings": [asdict(f) for f in all_findings],
    }


def should_fail(report: Dict, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    actionable = report.get("severity", {}).get("actionable", 0)
    danger = report.get("severity", {}).get("danger", 0)
    if fail_on == "warning":
        return actionable > 0
    if fail_on == "danger":
        return report.get("grade") == "DANGER" and danger > 0
    return False


def main():
    ap = argparse.ArgumentParser(description="Skill-Auditor MVP")
    ap.add_argument("--target", action="append", required=True, help="Scan target path (repeatable)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--max-file-kb", type=int, default=256, help="Skip files larger than this")
    ap.add_argument("--include", default=",".join(DEFAULT_GLOBS), help="Comma-separated glob patterns")
    ap.add_argument("--exclude", default=",".join(DEFAULT_EXCLUDES), help="Comma-separated exclude patterns")
    ap.add_argument("--out", default="", help="Write JSON report to file path")
    ap.add_argument("--strict-docs", action="store_true", help="Do not downgrade documentation examples")
    ap.add_argument("--allow-domains", default=",".join(DEFAULT_ALLOW_DOMAINS), help="Comma-separated trusted domains")
    ap.add_argument("--fail-on", choices=["danger", "warning", "never"], default="never", help="Exit non-zero based on actionable risk")
    args = ap.parse_args()

    targets = [Path(t).expanduser().resolve() for t in args.target]
    missing = [str(t) for t in targets if not t.exists()]
    if missing:
        raise SystemExit(f"Target not found: {', '.join(missing)}")

    globs = [g.strip() for g in args.include.split(",") if g.strip()]
    excludes = [e.strip() for e in args.exclude.split(",") if e.strip()]
    allow_domains = [d.strip().lower() for d in args.allow_domains.split(",") if d.strip()]

    report = build_report(targets, globs, excludes, args.max_file_kb, args.strict_docs, allow_domains)

    if args.out:
        Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        sev = report["severity"]
        print(f"Grade: {report['grade']}")
        print(f"Scanned files: {report['scanned_files']}")
        print(f"Findings: {report['findings_total']} (danger={sev['danger']}, warning={sev['warning']}, executable={sev['executable']}, actionable={sev['actionable']})")
        if report["categories"]:
            print("Categories:")
            for k, v in sorted(report["categories"].items(), key=lambda x: (-x[1], x[0])):
                print(f"  - {k}: {v}")
        findings = report["findings"]
        if findings:
            print("\nTop findings:")
            for f in findings[:30]:
                exec_tag = "EXEC" if f["executable_context"] else "DOC"
                act_tag = "ACT" if f["actionable"] else "INFO"
                print(f"- [{f['severity'].upper()}/{exec_tag}/{act_tag}] {f['file']}:{f['line']} | {f['category']} | {f['pattern']}")
                print(f"    {f['snippet']}")

    if should_fail(report, args.fail_on):
        sys.exit(2)

if __name__ == "__main__":
    main()
