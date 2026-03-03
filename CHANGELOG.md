# Changelog

## v0.2.0 - 2026-03-03
- Added `actionable` field to distinguish executable risk from informational findings.
- Added `--allow-domains` to reduce false positives for trusted domains.
- Added `--fail-on danger|warning|never` for CI fail-gates.
- Improved documentation/example handling (`--strict-docs`).
- Added OSS starter files: `LICENSE`, `CONTRIBUTING.md`, GitHub Actions CI.

## v0.1.0 - 2026-03-03
- Initial MVP CLI scanner with static pattern rules.
- Grade output: SAFE/WARNING/DANGER.
- JSON/text report output with include/exclude support.
