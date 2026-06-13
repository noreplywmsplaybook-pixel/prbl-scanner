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


# ── PRBL-C001: Dict/object literal credential patterns (ITEM 10) ─────────────

def test_python_dict_password_fires():
    """True positive: Python dict literal with hardcoded password fires C001."""
    code = '''config = {"password": "hunter2secret", "host": "localhost"}'''
    findings = run(code, language='python', file_path='config.py')
    assert any(f['rule_id'] == 'PRBL-C001' for f in findings), \
        "PRBL-C001 must fire on Python dict literal with hardcoded password"


def test_python_dict_secret_fires():
    """True positive: Python dict literal with hardcoded secret fires C001."""
    code = '''db_config = {"secret": "my-secret-key-123456", "port": 5432}'''
    findings = run(code, language='python', file_path='db.py')
    assert any(f['rule_id'] == 'PRBL-C001' for f in findings), \
        "PRBL-C001 must fire on Python dict literal with hardcoded secret"


def test_js_object_password_fires():
    """True positive: JS object literal with hardcoded password fires C001."""
    code = """const config = { password: "hunter2secret123", apiKey: "abc123secret" }"""
    findings = run(code, file_path='config.js')
    assert any(f['rule_id'] == 'PRBL-C001' for f in findings), \
        "PRBL-C001 must fire on JS object literal with hardcoded password"


def test_dict_env_var_not_flagged():
    """True negative: dict with os.environ reference must not fire C001."""
    code = '''config = {"password": os.environ["DB_PASSWORD"]}'''
    findings = run(code, language='python', file_path='config.py')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, \
        f"PRBL-C001 must not fire when dict value is os.environ reference. Got: {c001}"


def test_dict_validation_message_not_flagged():
    """True negative: dict with validation message value must not fire C001."""
    code = '''errors = {"password": "is required"}'''
    findings = run(code, language='python', file_path='forms.py')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, \
        f"PRBL-C001 must not fire on dict with validation message. Got: {c001}"


def test_dict_placeholder_name_not_flagged():
    """True negative: dict key containing 'your-password' placeholder must not fire."""
    code = '''hints = {"your-password": "..."}'''
    findings = run(code, language='python', file_path='help.py')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, \
        f"PRBL-C001 must not fire on placeholder variable name. Got: {c001}"


def test_python_environ_not_flagged():
    """True negative: os.environ reference must never fire C001."""
    code = "api_key = os.environ.get('API_KEY')"
    findings = run(code, language='python', file_path='config.py')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, "PRBL-C001 must not fire on os.environ reference"


# ── PRBL-C001: Python or-fallback pattern (_FALLBACK_PY_OR) ──────────────────

def test_py_or_fallback_secret_key_fires():
    """True positive: os.environ.get('SECRET_KEY') or 'dev-secret' fires C001."""
    code = "SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'"
    findings = run(code, language='python', file_path='settings.py')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert c001, "PRBL-C001 must fire on os.environ.get(...) or 'literal' with credential var name"


def test_py_or_fallback_jwt_secret_fires():
    """True positive: os.getenv('JWT_SECRET') or 'supersecret' fires C001."""
    code = "JWT_SECRET = os.getenv('JWT_SECRET') or 'supersecret'"
    findings = run(code, language='python', file_path='config.py')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert c001, "PRBL-C001 must fire on os.getenv(...) or 'literal' with jwt_secret"


def test_py_or_fallback_with_none_sentinel_fires():
    """True positive: os.environ.get('API_KEY', None) or 'hardcoded-api-key' fires C001."""
    code = "API_KEY = os.environ.get('API_KEY', None) or 'hardcoded-api-key'"
    findings = run(code, language='python', file_path='config.py')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert c001, "PRBL-C001 must fire on os.environ.get('KEY', None) or 'literal'"


def test_py_or_fallback_debug_not_flagged():
    """True negative: os.environ.get('DEBUG') or 'false' — 'false' is safe value."""
    code = "DEBUG = os.environ.get('DEBUG') or 'false'"
    findings = run(code, language='python', file_path='config.py')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, f"PRBL-C001 must not fire on DEBUG with 'false' fallback. Got: {c001}"


def test_py_or_fallback_log_level_not_flagged():
    """True negative: os.environ.get('LOG_LEVEL') or 'INFO' — non-credential name + safe value."""
    code = "LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'"
    findings = run(code, language='python', file_path='config.py')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, f"PRBL-C001 must not fire on LOG_LEVEL with 'INFO' fallback. Got: {c001}"


def test_py_or_fallback_port_not_flagged():
    """True negative: os.getenv('PORT') or '3000' — '3000' matches _FALLBACK_SAFE_VALUE (digits only)."""
    code = "PORT = os.getenv('PORT') or '3000'"
    findings = run(code, language='python', file_path='config.py')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, f"PRBL-C001 must not fire on PORT with '3000' fallback. Got: {c001}"


def test_py_or_fallback_localhost_not_flagged():
    """True negative: os.getenv('DB_HOST') or 'localhost' — non-credential name + safe value."""
    code = "DB_HOST = os.getenv('DB_HOST') or 'localhost'"
    findings = run(code, language='python', file_path='config.py')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, f"PRBL-C001 must not fire on DB_HOST with 'localhost' fallback. Got: {c001}"


def test_py_or_fallback_workers_not_flagged():
    """True negative: os.environ.get('WORKERS') or '4' — WORKERS is not a credential name."""
    code = "WORKERS = os.environ.get('WORKERS') or '4'"
    findings = run(code, language='python', file_path='config.py')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, f"PRBL-C001 must not fire on WORKERS. Got: {c001}"


# ── PRBL-C001: JS/TS destructuring default (_FALLBACK_JS_DESTRUCT) ────────────

def test_js_destruct_jwt_secret_fires():
    """True positive: const { JWT_SECRET = 'my-hardcoded-secret' } = process.env fires C001."""
    code = "const { JWT_SECRET = 'my-hardcoded-secret' } = process.env"
    findings = run(code, language='javascript', file_path='config.js')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert c001, "PRBL-C001 must fire on JS destructuring with credential var name"


def test_js_destruct_session_secret_fires():
    """True positive: const { SESSION_SECRET = 'default-session' } = process.env fires C001."""
    code = "const { SESSION_SECRET = 'default-session' } = process.env"
    findings = run(code, language='javascript', file_path='server.js')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert c001, "PRBL-C001 must fire on SESSION_SECRET destructuring default"


def test_js_destruct_api_key_fires():
    """True positive: const { API_KEY = 'hardcoded-key-value' } = process.env fires C001."""
    code = "const { API_KEY = 'hardcoded-key-value' } = process.env"
    findings = run(code, language='typescript', file_path='config.ts')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert c001, "PRBL-C001 must fire on API_KEY destructuring default"


def test_js_destruct_port_not_flagged():
    """True negative: const { PORT = '3000' } = process.env — PORT not a credential name."""
    code = "const { PORT = '3000' } = process.env"
    findings = run(code, language='javascript', file_path='server.js')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, f"PRBL-C001 must not fire on PORT destructuring. Got: {c001}"


def test_js_destruct_node_env_not_flagged():
    """True negative: const { NODE_ENV = 'development' } = process.env — not a credential."""
    code = "const { NODE_ENV = 'development' } = process.env"
    findings = run(code, language='javascript', file_path='app.js')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, f"PRBL-C001 must not fire on NODE_ENV destructuring. Got: {c001}"


def test_js_destruct_placeholder_not_flagged():
    """True negative: const { JWT_SECRET = 'your-secret-here' } = process.env — safe placeholder."""
    code = "const { JWT_SECRET = 'your-secret-here' } = process.env"
    findings = run(code, language='javascript', file_path='config.js')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, f"PRBL-C001 must not fire on 'your-*' placeholder. Got: {c001}"


def test_js_destruct_debug_not_flagged():
    """True negative: const { DEBUG = 'false' } = process.env — DEBUG not credential, 'false' is safe."""
    code = "const { DEBUG = 'false' } = process.env"
    findings = run(code, language='javascript', file_path='app.js')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, f"PRBL-C001 must not fire on DEBUG destructuring. Got: {c001}"


# ── PRECISION FIXES: placeholder suppression, seeder dirs, bcrypt ─────────────

def test_placeholder_password_not_flagged():
    """True negative: password: 'password' is a placeholder — not a real credential."""
    code = "const config = { password: 'password', host: 'localhost' }"
    findings = run(code, language='javascript', file_path='config/database.js')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, f"PRBL-C001 must not fire on placeholder 'password'. Got: {c001}"


def test_placeholder_mysecret_not_flagged():
    """True negative: password: 'mysecret' is a known placeholder."""
    code = "const config = { password: 'mysecret', host: 'localhost' }"
    findings = run(code, language='javascript', file_path='config.js')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, f"PRBL-C001 must not fire on 'mysecret'. Got: {c001}"


def test_real_password_still_fires():
    """True positive: password: 'X9k$mP2#vL8' is high-entropy and not a placeholder."""
    code = "const config = { password: 'X9kmP2vL8abc', host: 'localhost' }"
    findings = run(code, language='javascript', file_path='config.js')
    assert any(f['rule_id'] == 'PRBL-C001' for f in findings), \
        "PRBL-C001 must fire on high-entropy non-placeholder password"


def test_bcrypt_hash_not_flagged():
    """True negative: bcrypt hash value is not a plaintext secret."""
    code = "const config = { password: '$2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LdWMn8zOvhG', host: 'db' }"
    findings = run(code, language='javascript', file_path='config.js')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, f"PRBL-C001 must not fire on bcrypt hash. Got: {c001}"


def test_seeder_dir_skipped():
    """True negative: files in database/seeders/ are skipped (seeder dir)."""
    code = "const password = 'hunter2secret';"
    findings = run(code, language='javascript', file_path='database/seeders/UserSeeder.js')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, f"PRBL-C001 must not fire in seeders/ dir. Got: {c001}"


def test_fixtures_dir_skipped():
    """True negative: files in fixtures/ are skipped."""
    code = "const password = 'hunter2secret';"
    findings = run(code, language='javascript', file_path='tests/fixtures/UserFixture.js')
    c001 = [f for f in findings if f['rule_id'] == 'PRBL-C001']
    assert not c001, f"PRBL-C001 must not fire in fixtures/ dir. Got: {c001}"
