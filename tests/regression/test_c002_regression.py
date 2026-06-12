"""
PRBL-C002 regression suite — Hardcoded Session Secrets.

Covers:
  - C001/C002 session-secret double-fire must not happen
  - Env var fallback pattern fires exactly C001 (not C002)
  - Fully hardcoded session secret fires exactly C002 (not C001)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from prbl.scanner.rules import run_all_rules


def run(code: str, language: str = 'javascript', file_path: str = 'app.js') -> list:
    return [{'rule_id': m.rule_id, 'severity': m.severity, 'line': m.line_number}
            for m in run_all_rules(code, language, file_path)]


# ── TRUE POSITIVES ────────────────────────────────────────────────────────────

def test_hardcoded_session_secret_fires_c002():
    """True positive: fully hardcoded session secret fires C002."""
    code = '''
const session = require('express-session')
app.use(session({ secret: 'fully-hardcoded-secret' }))
'''
    findings = run(code)
    c002 = [f for f in findings if f['rule_id'] == 'PRBL-C002']
    assert c002, "PRBL-C002 must fire on hardcoded session secret"


# ── FALSE POSITIVE REGRESSIONS ────────────────────────────────────────────────

def test_env_var_fallback_fires_c001_not_c002():
    """Regression: process.env fallback fires C001 only (not C002)."""
    code = '''
const session = require('express-session')
app.use(session({ secret: process.env.SESSION_SECRET || 'fallback-secret' }))
'''
    findings = run(code)
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    c002 = [f for f in findings if f['rule_id'] == 'PRBL-C002']
    assert len(c001) == 1, f"Expected exactly 1 C001 for fallback. Got: {c001}"
    assert not c002, f"C002 must not fire when process.env is used. Got: {c002}"


def test_no_double_fire_on_fallback_session():
    """Regression: fallback session secret must produce at most 1 C001, 0 C002."""
    code = "app.use(session({ secret: process.env.SESSION_SECRET || 'fallback-secret' }))"
    findings = run(code)
    c001_count = sum(1 for f in findings if f['rule_id'] == 'PRBL-C001')
    c002_count = sum(1 for f in findings if f['rule_id'] == 'PRBL-C002')
    assert c001_count <= 1, f"C001 fired {c001_count} times — must be at most 1"
    assert c002_count == 0, f"C002 fired on process.env fallback — must not"


def test_env_session_secret_no_firing():
    """True negative: pure env var session secret must not fire at all."""
    code = "app.use(session({ secret: process.env.SESSION_SECRET }))"
    findings = run(code)
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    c002 = [f for f in findings if f['rule_id'] == 'PRBL-C002']
    assert not c001 and not c002, \
        "Neither C001 nor C002 should fire on pure process.env session secret"
