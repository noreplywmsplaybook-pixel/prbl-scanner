"""
Kanakku real-codebase regression test.

Verifies that the scanner still produces the expected findings on the kanakku
codebase when run locally. Skipped automatically if kanakku is not cloned.

Run manually: pytest tests/regression/test_kanakku_regression.py -v
"""

import sys
import os
import pytest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

KANAKKU_PATH = Path('/Users/kennedywright/Documents/GitHub/kanakku')

pytestmark = pytest.mark.skipif(
    not KANAKKU_PATH.exists(),
    reason="kanakku repo not available locally"
)


def test_kanakku_finding_count():
    """Kanakku must produce exactly 10 findings (static rules only, no network)."""
    from prbl.scanner.scanner import PrblScanner
    from tests.regression.fixtures.kanakku_expected import EXPECTED_TOTAL

    scanner = PrblScanner(check_packages=False)
    results = scanner.scan_directory(KANAKKU_PATH)

    all_findings = []
    for r in results:
        all_findings.extend(r.findings)

    assert len(all_findings) == EXPECTED_TOTAL, (
        f"Kanakku finding count changed: expected {EXPECTED_TOTAL}, got {len(all_findings)}.\n"
        f"Findings: {[(f.rule_id, f.severity, r.file) for r in results for f in r.findings]}"
    )


def test_kanakku_rule_ids():
    """Kanakku must produce findings only from the expected rules."""
    from prbl.scanner.scanner import PrblScanner
    from tests.regression.fixtures.kanakku_expected import EXPECTED_FINDINGS

    scanner = PrblScanner(check_packages=False)
    results = scanner.scan_directory(KANAKKU_PATH)

    actual = sorted(
        [(f.rule_id, f.severity) for r in results for f in r.findings]
    )
    expected = sorted(
        [(e['rule_id'], e['severity']) for e in EXPECTED_FINDINGS]
    )

    assert actual == expected, (
        f"Kanakku rule_id/severity mismatch.\n"
        f"Expected: {expected}\n"
        f"Actual:   {actual}"
    )


def test_kanakku_no_new_high_findings():
    """No new HIGH findings must appear in kanakku beyond what was already captured."""
    from prbl.scanner.scanner import PrblScanner
    from tests.regression.fixtures.kanakku_expected import EXPECTED_FINDINGS

    scanner = PrblScanner(check_packages=False)
    results = scanner.scan_directory(KANAKKU_PATH)

    actual_highs = sorted(
        [(f.rule_id, r.file.replace(str(KANAKKU_PATH) + '/', ''))
         for r in results for f in r.findings if f.severity == 'high']
    )
    expected_highs = sorted(
        [(e['rule_id'], e['file_suffix'])
         for e in EXPECTED_FINDINGS if e['severity'] == 'high']
    )

    assert len(actual_highs) == len(expected_highs), (
        f"HIGH finding count changed from {len(expected_highs)} to {len(actual_highs)}.\n"
        f"Actual: {actual_highs}"
    )
