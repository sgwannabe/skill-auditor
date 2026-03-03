# Contributing

## Quick start
```bash
python3 -m unittest -v tests/test_auditor.py
python3 auditor.py --target .
```

## Rule quality bar
- Prefer low false positives over broad noisy catches.
- Every new rule must include at least 1 positive/negative test fixture.
- Avoid hard-failing on documentation-only examples.

## PR checklist
- [ ] Tests pass
- [ ] Added/updated fixtures
- [ ] Added note in README if CLI behavior changed
