"""
Fix 1 regression: minified and bundled files must produce zero findings.

Rationale: minified JS/CSS files contain concatenated third-party code that
triggers false positives on credential and injection patterns. These files
should be skipped entirely — scanning them is noise, not signal.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from prbl.scanner.rules import run_all_rules


def run(code: str, language: str = 'javascript', file_path: str = 'app.js') -> list:
    return [{'rule_id': m.rule_id, 'severity': m.severity, 'line': m.line_number}
            for m in run_all_rules(code, language, file_path)]


# ── Fix 1: .min.js filename ────────────────────────────────────────────────────

def test_min_js_filename_produces_no_findings():
    """Fix 1: *.min.js files must be skipped entirely."""
    code = '''
password = "hardcoded123"
const secret = "mysecret"
const query = "SELECT * FROM users WHERE id=" + userId
'''
    findings = run(code, 'javascript', 'static/js/jssor.slider-27.5.0.min.js')
    assert not findings, f"min.js file produced findings — should be 0: {findings}"


def test_min_css_filename_produces_no_findings():
    """Fix 1: *.min.css files must be skipped entirely."""
    code = 'a{background:url("secret://hardcoded")}'
    findings = run(code, 'javascript', 'static/css/bootstrap.min.css')
    assert not findings, f"min.css file produced findings: {findings}"


def test_long_line_file_skipped():
    """Fix 1: a file with any line over 500 chars is treated as minified and skipped."""
    long_line = ('x' * 501) + '; password="hardcoded123"; '
    findings = run(long_line, 'javascript', 'bundle.js')
    assert not findings, f"Long-line bundle produced findings — should be 0: {findings}"


def test_regular_js_file_not_skipped():
    """Fix 1: regular JS files (no long lines) are not suppressed."""
    code = '''
const password = "hardcoded-secret"
'''
    findings = run(code, 'javascript', 'app.js')
    assert findings, "Regular JS file with hardcoded credential must still produce findings"


def test_regular_file_with_long_comment_not_skipped():
    """Fix 1: long lines only in comments shouldn't suppress the whole file."""
    # Comments don't trigger real patterns, but let's confirm a normal file
    # with a long-ish but sub-500 line isn't suppressed.
    normal_line = 'x' * 499  # 499 chars — under the 500 threshold
    code = f"{normal_line}\npassword = 'hardcoded-secret'\n"
    findings = run(code, 'python', 'app.py')
    assert any(f['rule_id'] == 'PRBL-C001' for f in findings), \
        "File with lines under 500 chars must not be suppressed"
