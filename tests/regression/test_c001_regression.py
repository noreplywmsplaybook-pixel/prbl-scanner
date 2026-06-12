"""
PRBL-C001 regression suite — Hardcoded Credentials.

Covers every false-positive fix:
  - Test file credentials (password='testpass123' in test fixtures) not flagged HIGH
  - Demo/marketing/animation content downgraded to LOW
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from prbl.scanner.rules import run_all_rules


def run(code: str, language: str = 'javascript', file_path: str = 'test.js') -> list:
    return [{'rule_id': m.rule_id, 'severity': m.severity, 'line': m.line_number}
            for m in run_all_rules(code, language, file_path)]


# ── TRUE POSITIVES ────────────────────────────────────────────────────────────

def test_hardcoded_api_key_fires():
    """True positive: hardcoded API key in production code fires C001."""
    # Note: key fragments split across concatenation so GitHub push protection
    # doesn't block this test file — the scanner sees the joined string at runtime.
    prefix = "sk_li" + "ve_"
    suffix = "abcdefghijklmnopqr" + "stuvwx"
    code = f"const apiKey = '{prefix}{suffix}'"
    findings = run(code, file_path='app.js')
    assert any(f['rule_id'] == 'PRBL-C001' for f in findings)


def test_hardcoded_password_fires():
    """True positive: hardcoded password in non-test file fires C001."""
    code = "password = 'supersecret123'"
    findings = run(code, language='python', file_path='app.py')
    assert any(f['rule_id'] == 'PRBL-C001' for f in findings)


def test_stripe_live_key_fires():
    """True positive: Stripe live key always fires."""
    # Key split to prevent GitHub push protection from blocking the test file.
    key = "sk_li" + "ve_aBcDeFgHiJk" + "LmNoPqRsTuVwX"
    code = f"const stripe = require('stripe')('{key}')"
    findings = run(code, file_path='payment.js')
    assert any(f['rule_id'] == 'PRBL-C001' for f in findings)


def test_aws_key_fires():
    """True positive: AWS access key always fires."""
    code = "const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"
    findings = run(code, file_path='config.js')
    assert any(f['rule_id'] == 'PRBL-C001' for f in findings)


# ── FALSE POSITIVE REGRESSIONS ────────────────────────────────────────────────

def test_test_fixture_password_not_flagged_high():
    """Regression: password='testpass123' in test fixtures must not fire C001 HIGH."""
    code = "password='testpass123'"
    findings = run(code, language='python', file_path='tests/test_views.py')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, \
        f"PRBL-C001 must not fire on password in test file. Got: {c001}"


def test_test_file_generic_credentials_not_flagged():
    """Regression: generic test credentials in test files must not fire."""
    code = '''
def test_login():
    response = client.post('/login', {'username': 'testuser', 'password': 'testpass123'})
    assert response.status_code == 200
'''
    findings = run(code, language='python', file_path='tests/test_auth.py')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, \
        f"PRBL-C001 must not fire in test files. Got: {c001}"


def test_spec_file_credentials_not_flagged():
    """Regression: credentials in spec files must not fire."""
    code = '''
describe('auth', () => {
  it('logs in', async () => {
    const res = await api.post('/login', { password: 'testpass123' })
    expect(res.status).toBe(200)
  })
})
'''
    findings = run(code, file_path='spec/auth.spec.js')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, \
        f"PRBL-C001 must not fire in spec files. Got: {c001}"


def test_demo_content_downgraded_to_low():
    """Regression: credentials in demo/animation content downgraded to LOW."""
    code = "const demoPassword = 'demo-password-123'"
    findings = run(code, file_path='remotion/HeroAnimation.tsx')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    if c001:
        assert c001[0]['severity'] == 'low', \
            f"PRBL-C001 must be LOW in remotion/demo files. Got: {c001[0]['severity']}"


def test_landing_page_demo_content_downgraded():
    """Regression: credentials in app/page.tsx (marketing landing page) downgraded to LOW."""
    code = "const exampleKey = 'sk_test_example123456789'"
    findings = run(code, file_path='app/page.tsx')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    if c001:
        assert c001[0]['severity'] == 'low', \
            f"C001 must be LOW in app/page.tsx (marketing landing page). Got: {c001[0]['severity']}"


def test_env_var_reference_not_flagged():
    """True negative: env var reference must never fire C001."""
    code = "const apiKey = process.env.API_KEY"
    findings = run(code)
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, "PRBL-C001 must not fire on process.env reference"


def test_python_environ_not_flagged():
    """True negative: os.environ reference must never fire C001."""
    code = "api_key = os.environ.get('API_KEY')"
    findings = run(code, language='python', file_path='config.py')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, "PRBL-C001 must not fire on os.environ reference"
