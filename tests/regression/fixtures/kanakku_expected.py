"""
Kanakku (https://github.com/code-with-amitab/kanakku) — expected scanner findings.

Captured: 2026-06-12
Scanner version: post-precision-fixes (commit c8aaa54+)
Run with: PrblScanner(check_packages=False).scan_directory(...)

These findings are the ground truth for the kanakku codebase.
If the count or rule_ids change, a regression has occurred.

To re-capture: run tests/regression/fixtures/rerun_kanakku.py
"""

EXPECTED_FINDINGS = [
    # adminserver/config/dashboard_config.py:124 — hardcoded credential (medium)
    {"rule_id": "PRBL-C001", "severity": "medium",
     "file_suffix": "adminserver/config/dashboard_config.py"},

    # adminserver/test_imports.py:13 — code injection (high)
    {"rule_id": "PRBL-I003", "severity": "high",
     "file_suffix": "adminserver/test_imports.py"},

    # backend/app/config.py:100 — session secret (high)
    {"rule_id": "PRBL-C002", "severity": "high",
     "file_suffix": "backend/app/config.py"},

    # banktransactions/tests/test_core/test_email_parser.py:13 — hallucinated package (high)
    {"rule_id": "PRBL-P001", "severity": "high",
     "file_suffix": "banktransactions/tests/test_core/test_email_parser.py"},

    # banktransactions/tests/test_core/test_transaction_data.py:17 — hallucinated package (high)
    {"rule_id": "PRBL-P001", "severity": "high",
     "file_suffix": "banktransactions/tests/test_core/test_transaction_data.py"},

    # banktransactions/tools/debug_encryption.py:99 — hardcoded credential (high)
    {"rule_id": "PRBL-C001", "severity": "high",
     "file_suffix": "banktransactions/tools/debug_encryption.py"},

    # banktransactions/tools/update_test_password.py:74 — hardcoded credential (high)
    {"rule_id": "PRBL-C001", "severity": "high",
     "file_suffix": "banktransactions/tools/update_test_password.py"},

    # frontend/e2e/utils/test-utils.js:13 — hardcoded credential (high)
    {"rule_id": "PRBL-C001", "severity": "high",
     "file_suffix": "frontend/e2e/utils/test-utils.js"},

    # frontend/e2e/utils/test-utils.js:35 — hardcoded credential (high)
    {"rule_id": "PRBL-C001", "severity": "high",
     "file_suffix": "frontend/e2e/utils/test-utils.js"},

    # frontend/e2e/utils/test-utils.js:36 — hardcoded credential (high)
    {"rule_id": "PRBL-C001", "severity": "high",
     "file_suffix": "frontend/e2e/utils/test-utils.js"},
]

EXPECTED_TOTAL = len(EXPECTED_FINDINGS)  # 10
