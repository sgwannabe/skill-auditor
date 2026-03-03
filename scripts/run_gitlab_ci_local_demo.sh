#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEMO_DIR="$ROOT_DIR/demo"

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"
cat > "$DEMO_DIR/risky_example.py" <<'PY'
import subprocess

def run(user_input):
    return subprocess.run(f"echo {user_input}", shell=True, capture_output=True, text=True)
PY

python3 "$ROOT_DIR/auditor.py" --target "$DEMO_DIR" --exclude "audit-report.json,audit-summary.md,fixes.md" --out "$DEMO_DIR/audit-report.json" --fail-on never
python3 "$ROOT_DIR/scripts/gitlab_mr_comment.py" --report "$DEMO_DIR/audit-report.json" --summary "$DEMO_DIR/audit-summary.md" --no-post
python3 "$ROOT_DIR/scripts/generate_fixes_md.py" --report "$DEMO_DIR/audit-report.json" --out "$DEMO_DIR/fixes.md"

echo "\n✅ Local GitLab-style demo completed"
echo "- Report:  $DEMO_DIR/audit-report.json"
echo "- Summary: $DEMO_DIR/audit-summary.md"
echo "- Fixes:   $DEMO_DIR/fixes.md"
