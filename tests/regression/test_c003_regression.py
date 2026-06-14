"""
PRBL-C003 regression suite — TLS/Certificate Verification Disabled.

Covers:
  - True positives (must fire HIGH): rejectUnauthorized: false, verify=False, etc.
  - Dev-guard downgrades (must fire LOW, not HIGH)
  - False positives (must NOT fire): safe forms
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from prbl.scanner.rules import run_all_rules


def run(code: str, language: str = 'javascript', file_path: str = 'app.js') -> list:
    return [{'rule_id': m.rule_id, 'severity': m.severity, 'line': m.line_number}
            for m in run_all_rules(code, language, file_path)]


# ── TRUE POSITIVES — must fire HIGH ──────────────────────────────────────────

def test_pg_pool_reject_unauthorized_false():
    """TP1: pg.Pool with rejectUnauthorized: false fires HIGH."""
    code = "const pool = new pg.Pool({ ssl: { rejectUnauthorized: false } })"
    findings = run(code, 'javascript', 'db.js')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert c003, "PRBL-C003 must fire on pg.Pool rejectUnauthorized: false"
    assert c003[0]['severity'] == 'high', f"Expected HIGH, got {c003[0]['severity']}"


def test_https_request_reject_unauthorized_false():
    """TP2: https.request with rejectUnauthorized: false fires HIGH."""
    code = "https.request({ hostname: 'api.example.com', rejectUnauthorized: false })"
    findings = run(code, 'javascript', 'api.js')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert c003, "PRBL-C003 must fire on https.request rejectUnauthorized: false"
    assert c003[0]['severity'] == 'high'


def test_axios_reject_unauthorized_false():
    """TP3: axios.create with httpsAgent rejectUnauthorized: false fires HIGH."""
    code = "const client = axios.create({ httpsAgent: new https.Agent({ rejectUnauthorized: false }) })"
    findings = run(code, 'javascript', 'client.js')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert c003, "PRBL-C003 must fire on axios rejectUnauthorized: false"
    assert c003[0]['severity'] == 'high'


def test_node_tls_reject_unauthorized_env_zero():
    """TP4: process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0' fires HIGH."""
    code = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'"
    findings = run(code, 'javascript', 'bootstrap.js')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert c003, "PRBL-C003 must fire on NODE_TLS_REJECT_UNAUTHORIZED = '0'"
    assert c003[0]['severity'] == 'high'


def test_python_requests_verify_false():
    """TP5: requests.get with verify=False fires HIGH."""
    code = "response = requests.get(url, verify=False)"
    findings = run(code, 'python', 'fetch.py')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert c003, "PRBL-C003 must fire on requests.get verify=False"
    assert c003[0]['severity'] == 'high'


def test_python_session_verify_false():
    """TP6: session.verify = False fires HIGH."""
    code = "session.verify = False"
    findings = run(code, 'python', 'session.py')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert c003, "PRBL-C003 must fire on session.verify = False"
    assert c003[0]['severity'] == 'high'


def test_python_ssl_create_unverified_context():
    """TP7: ssl._create_unverified_context() fires HIGH."""
    code = "ctx = ssl._create_unverified_context()"
    findings = run(code, 'python', 'ssl_util.py')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert c003, "PRBL-C003 must fire on ssl._create_unverified_context()"
    assert c003[0]['severity'] == 'high'


def test_python_ssl_cert_none():
    """TP8: ssl.CERT_NONE fires HIGH."""
    code = "ctx.verify_mode = ssl.CERT_NONE"
    findings = run(code, 'python', 'ssl_util.py')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert c003, "PRBL-C003 must fire on ssl.CERT_NONE"
    assert c003[0]['severity'] == 'high'


# ── DEV-GUARD — must fire LOW ─────────────────────────────────────────────────

def test_js_reject_unauthorized_false_with_dev_env_guard():
    """DEV-GUARD TP9: rejectUnauthorized: false with NODE_ENV dev check → LOW."""
    code = """\
if (process.env.NODE_ENV === 'development') {
  opts.rejectUnauthorized = false
}
"""
    findings = run(code, 'javascript', 'config.js')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert c003, "PRBL-C003 must fire (but as LOW) when dev guard present"
    assert c003[0]['severity'] == 'low', f"Expected LOW (dev guard), got {c003[0]['severity']}"


def test_js_reject_unauthorized_false_not_equals_production_guard():
    """DEV-GUARD TP9b: rejectUnauthorized: false with NODE_ENV !== 'production' → LOW."""
    code = """\
if (process.env.NODE_ENV !== 'production') {
  opts.rejectUnauthorized = false
}
"""
    findings = run(code, 'javascript', 'config.js')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert c003, "PRBL-C003 must fire (but as LOW) when !== production guard present"
    assert c003[0]['severity'] == 'low', f"Expected LOW (!== production guard), got {c003[0]['severity']}"


def test_js_reject_unauthorized_false_equals_production_is_high():
    """DEV-GUARD TP9c: rejectUnauthorized in production ternary → HIGH (not LOW).

    ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    means TLS is disabled IN production — dangerous, must be HIGH.
    """
    code = "ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,"
    findings = run(code, 'javascript', 'database.js')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert c003, "PRBL-C003 must fire when rejectUnauthorized: false is in production branch"
    assert c003[0]['severity'] == 'high', f"Expected HIGH (production branch), got {c003[0]['severity']}"


def test_python_verify_false_with_debug_guard():
    """DEV-GUARD TP10: verify=False inside if DEBUG: block → LOW."""
    code = """\
if DEBUG:
    response = requests.get(url, verify=False)
"""
    findings = run(code, 'python', 'http_client.py')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert c003, "PRBL-C003 must fire (but as LOW) when DEBUG guard present"
    assert c003[0]['severity'] == 'low', f"Expected LOW (DEBUG guard), got {c003[0]['severity']}"


# ── FALSE POSITIVES — must NOT fire ──────────────────────────────────────────

def test_reject_unauthorized_true_is_safe():
    """FP11: rejectUnauthorized: true is explicitly safe — must not fire."""
    code = "const agent = new https.Agent({ rejectUnauthorized: true })"
    findings = run(code, 'javascript', 'agent.js')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert not c003, f"PRBL-C003 must NOT fire on rejectUnauthorized: true. Got: {c003}"


def test_reject_unauthorized_false_in_comment_does_not_fire():
    """FP12: rejectUnauthorized: false in a comment must not fire."""
    code = "// rejectUnauthorized: false — don't use this in production"
    findings = run(code, 'javascript', 'notes.js')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert not c003, f"PRBL-C003 must NOT fire on commented-out code. Got: {c003}"


def test_requests_with_custom_ca_is_safe():
    """FP13: requests.get with verify='/path/to/ca.crt' is safe — must not fire."""
    code = "response = requests.get(url, verify='/path/to/ca.crt')"
    findings = run(code, 'python', 'client.py')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert not c003, f"PRBL-C003 must NOT fire when verify= has a CA path. Got: {c003}"


# ── TEST-FILE SUPPRESSION — must NOT fire ─────────────────────────────────────

def test_reject_unauthorized_false_in_test_dir_suppressed():
    """FP14: rejectUnauthorized: false in test/ directory must not fire."""
    code = "const agent = new https.Agent({ rejectUnauthorized: false })"
    findings = run(code, 'javascript', '/project/test/helpers/https-server.ts')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert not c003, f"PRBL-C003 must NOT fire in test/ directory. Got: {c003}"


def test_reject_unauthorized_false_in_tests_dir_suppressed():
    """FP15: rejectUnauthorized: false in __tests__/ directory must not fire."""
    code = "const agent = new https.Agent({ rejectUnauthorized: false })"
    findings = run(code, 'javascript', '/project/src/__tests__/tls.test.ts')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert not c003, f"PRBL-C003 must NOT fire in __tests__/ directory. Got: {c003}"


def test_reject_unauthorized_false_in_spec_dir_suppressed():
    """FP16: rejectUnauthorized: false in spec/ directory must not fire."""
    code = "const agent = new https.Agent({ rejectUnauthorized: false })"
    findings = run(code, 'javascript', '/project/spec/integration/tls_spec.js')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert not c003, f"PRBL-C003 must NOT fire in spec/ directory. Got: {c003}"


def test_reject_unauthorized_false_not_in_test_dir_still_fires():
    """TP17: rejectUnauthorized: false in production code (not test dir) must still fire."""
    code = "const pool = new pg.Pool({ ssl: { rejectUnauthorized: false } })"
    findings = run(code, 'javascript', '/project/src/config/database.js')
    c003 = [f for f in findings if f['rule_id'] == 'PRBL-C003']
    assert c003, "PRBL-C003 must still fire in non-test production code"
    assert c003[0]['severity'] == 'high'
