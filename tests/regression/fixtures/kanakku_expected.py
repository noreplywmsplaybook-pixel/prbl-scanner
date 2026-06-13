"""
Kanakku (https://github.com/code-with-amitab/kanakku) — expected scanner findings.

Captured: 2026-06-13
Scanner version: PRBL-C003 — TLS verification disabled (CWE-295). Adds 1 new
                 true-positive C003 finding in banktransactions/core/imap_client.py
                 (ssl.CERT_NONE used unconditionally — a comment suggests dev-only
                 intent but no runtime guard is present).
Previous: Fix 4 — PRBL-C002 now detects app.config['SECRET_KEY'] = 'literal'
                 form (Flask dict-assignment).
E2E / playwright / __mocks__ directories treated as test scaffolding — findings
in those paths are suppressed in non-production mode.
Run with: PrblScanner(check_packages=False).scan_directory(...)

These findings are the ground truth for the kanakku codebase.
If the count or rule_ids change, a regression has occurred.

To re-capture: run tests/regression/fixtures/rerun_kanakku.py
"""

EXPECTED_FINDINGS = [
    # adminserver/config/dashboard_config.py:16 — or-fallback DASHBOARD_SECRET_KEY (medium)
    {"rule_id": "PRBL-C001", "severity": "medium",
     "file_suffix": "adminserver/config/dashboard_config.py"},

    # adminserver/config/dashboard_config.py:124 — hardcoded credential (medium)
    {"rule_id": "PRBL-C001", "severity": "medium",
     "file_suffix": "adminserver/config/dashboard_config.py"},

    # adminserver/test_imports.py:13 — code injection (high)
    {"rule_id": "PRBL-I003", "severity": "high",
     "file_suffix": "adminserver/test_imports.py"},

    # backend/app/config.py:100 — session secret (high)
    {"rule_id": "PRBL-C002", "severity": "high",
     "file_suffix": "backend/app/config.py"},

    # backend/app/config.py:11 — or-fallback SECRET_KEY (medium)
    {"rule_id": "PRBL-C001", "severity": "medium",
     "file_suffix": "backend/app/config.py"},

    # backend/app/config.py:20 — or-fallback JWT_SECRET_KEY (medium)
    {"rule_id": "PRBL-C001", "severity": "medium",
     "file_suffix": "backend/app/config.py"},

    # banktransactions/tests/test_core/test_email_parser.py:13 — hallucinated package (high)
    {"rule_id": "PRBL-P001", "severity": "high",
     "file_suffix": "banktransactions/tests/test_core/test_email_parser.py"},

    # banktransactions/tests/test_core/test_transaction_data.py:17 — hallucinated package (high)
    {"rule_id": "PRBL-P001", "severity": "high",
     "file_suffix": "banktransactions/tests/test_core/test_transaction_data.py"},

    # banktransactions/tools/debug_encryption.py:53 — app.config SECRET_KEY (high) [Fix 4]
    {"rule_id": "PRBL-C002", "severity": "high",
     "file_suffix": "banktransactions/tools/debug_encryption.py"},

    # banktransactions/tools/debug_encryption.py:99 — hardcoded credential (high)
    {"rule_id": "PRBL-C001", "severity": "high",
     "file_suffix": "banktransactions/tools/debug_encryption.py"},

    # banktransactions/tools/update_test_password.py:44 — app.config SECRET_KEY (high) [Fix 4]
    {"rule_id": "PRBL-C002", "severity": "high",
     "file_suffix": "banktransactions/tools/update_test_password.py"},

    # banktransactions/tools/update_test_password.py:74 — hardcoded credential (high)
    {"rule_id": "PRBL-C001", "severity": "high",
     "file_suffix": "banktransactions/tools/update_test_password.py"},

    # banktransactions/core/imap_client.py:478 — ssl.CERT_NONE unconditional (high) [PRBL-C003]
    # Comment says "dev/testing" but no runtime guard (if DEBUG:, if NODE_ENV...) is present.
    {"rule_id": "PRBL-C003", "severity": "high",
     "file_suffix": "banktransactions/core/imap_client.py"},

    # NOTE: frontend/e2e/utils/test-utils.js was previously counted here (3 findings).
    # These are now suppressed because frontend/e2e/ is recognized as a test directory.
    # E2E credential fixtures (password='Password123!') are test scaffolding, not
    # production secrets. The suppression prevents noise in E2E test code reviews.
]

EXPECTED_TOTAL = len(EXPECTED_FINDINGS)  # 13
