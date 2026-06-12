# Regression Fixtures

This directory contains expected-output fixtures for real-codebase regression tests.

## kanakku_expected.py

**Source:** https://github.com/code-with-amitab/kanakku  
**Captured:** 2026-06-12  
**Scanner version:** post-precision-fixes (commit c8aaa54+)  
**Local path (when available):** `/Users/kennedywright/Documents/GitHub/kanakku`

Documents the 10 expected findings from the kanakku codebase. If findings change
(count or rule_ids shift), a regression has occurred.

Rules that fire:
- `PRBL-C001` × 5 — hardcoded credentials in config and tool scripts
- `PRBL-C002` × 1 — hardcoded session secret in backend config
- `PRBL-I003` × 1 — code injection in test imports file
- `PRBL-P001` × 2 — hallucinated package references in test files (requires network check)
  - Note: P001 findings require network access (PyPI/npm registry checks). These are
    captured here for documentation but the CI kanakku test skips P001 to avoid
    network dependency.

## Not included

**Expensify/App** and **OnComply** are not locally accessible on this machine.
- Expensify was used for stress testing (3,466 files, 0 FP) but is not cloned locally.
- OnComply was the production codebase used to validate the SSRF rule removal.

To add fixtures for these repos, clone them locally and run:
```bash
python3 -c "
from prbl.scanner.scanner import PrblScanner
from pathlib import Path
s = PrblScanner(check_packages=False)
for r in s.scan_directory(Path('/path/to/repo')):
    for f in r.findings:
        print(f.rule_id, f.severity, r.file, f.line_number)
"
```
