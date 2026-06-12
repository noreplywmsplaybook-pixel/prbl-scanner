"""
PRBL-R002 regression suite — Insecure Equality Comparison on Security-Critical Values.

Sub-pattern A: HMAC/crypto digest output compared with == or ===
Sub-pattern B: webhook/signature token from request compared directly with == or ===
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from prbl.scanner.rules import run_all_rules


def run(code: str, language: str = 'javascript', file_path: str = 'test.js') -> list:
    return [{'rule_id': m.rule_id, 'severity': m.severity, 'line': m.line_number}
            for m in run_all_rules(code, language, file_path)]


def r002(findings):
    return [f for f in findings if f['rule_id'] == 'PRBL-R002']


# ── TRUE POSITIVES ────────────────────────────────────────────────────────────

def test_python_hmac_hexdigest_direct_comparison():
    """Sub-pattern A: Python hmac.new().hexdigest() == value on same line."""
    code = '''
import hmac
key = b'secret'
msg = b'data'
if hmac.new(key, msg).hexdigest() == provided_value:
    process()
'''
    findings = r002(run(code, 'python', 'app.py'))
    assert findings, "Must fire: direct hmac hexdigest comparison"
    assert findings[0]['severity'] == 'high'


def test_python_hmac_assigned_then_compared():
    """Sub-pattern A: Python digest assigned to var, compared within 5 lines."""
    code = '''
import hmac
computed = hmac.new(key, msg).hexdigest()
if computed == request.args['signature']:
    allow()
'''
    findings = r002(run(code, 'python', 'app.py'))
    assert findings, "Must fire: assigned digest var compared with =="


def test_js_createhmac_with_triple_equals():
    """Sub-pattern A: JS createHmac chain with === on same line."""
    code = '''
const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex')
if (sig === req.headers['x-hub-signature']) {
  processWebhook()
}
'''
    findings = r002(run(code, 'javascript', 'webhook.js'))
    assert findings, "Must fire: JS HMAC digest compared with ==="


def test_js_createhmac_assigned_within_5_lines():
    """Sub-pattern A: JS digest assigned, then compared within 5 lines."""
    code = '''
const computed = crypto.createHmac('sha256', secret).update(body).digest('hex')
const provided = req.headers['x-signature-256']
if (computed === provided) {
  next()
}
'''
    findings = r002(run(code, 'javascript', 'server.js'))
    assert findings, "Must fire: digest var compared with === within 5 lines"


def test_calcom_feishucalendar_pattern():
    """Sub-pattern B: The cal.com feishucalendar exact TP pattern."""
    code = '''
const open_verification_token = process.env.FEISHU_OPEN_VERIFICATION_TOKEN
export default async function handler(req, res) {
  if (req.method === "POST") {
    if (req.body.token === open_verification_token) {
      return res.status(200).json({ challenge: req.body.challenge })
    }
  }
}
'''
    findings = r002(run(code, 'typescript', 'events.ts'))
    assert findings, "Must fire: req.body.token === open_verification_token (cal.com pattern)"
    assert findings[0]['severity'] == 'high'


def test_calcom_reversed_operand_order():
    """Sub-pattern B: open_verification_token on left side of ===."""
    code = '''
if (open_verification_token === req.body.token) {
  res.json({ challenge: req.body.challenge })
}
'''
    findings = r002(run(code, 'typescript', 'events.ts'))
    assert findings, "Must fire: reversed operand order still a TP"


def test_python_webhook_secret_from_headers():
    """Sub-pattern B: Python webhook_secret compared with request header."""
    code = '''
webhook_secret = os.environ.get('WEBHOOK_SECRET')
if request.headers.get('X-Signature') == webhook_secret:
    handle_event()
'''
    findings = r002(run(code, 'python', 'webhook.py'))
    assert findings, "Must fire: webhook_secret compared with request header"


def test_python_expected_signature_with_request_args():
    """Sub-pattern B: Python expected_signature compared with request.args."""
    code = '''
expected_signature = compute_expected(payload)
incoming = request.args.get('sig')
if incoming == expected_signature:
    pass
'''
    findings = r002(run(code, 'python', 'verify.py'))
    assert findings, "Must fire: expected_signature compared with request-tainted var — BUT wait, incoming is request-tainted but the comparison is incoming == expected_signature"


def test_js_verification_token_req_body():
    """Sub-pattern B: verification_token compared with req.body value."""
    code = '''
const verification_token = process.env.VERIFICATION_TOKEN
if (req.body.token === verification_token) {
  res.json({ ok: true })
}
'''
    findings = r002(run(code, 'javascript', 'handler.js'))
    assert findings, "Must fire: verification_token === req.body value"


# ── FALSE POSITIVES ───────────────────────────────────────────────────────────

def test_fp_string_literal_url_verification():
    """FP: req.body.type === 'url_verification' — routing/discriminator check."""
    code = '''
if (req.body.type === 'url_verification') {
  res.json({ challenge: req.body.challenge })
}
'''
    findings = r002(run(code, 'javascript', 'handler.js'))
    assert not findings, f"Must NOT fire: string literal on RHS is routing logic, got {findings}"


def test_fp_typeof_type_guard():
    """FP: typeof x === 'string' type guard must not fire."""
    code = '''
if (typeof appKeys.client_secret === "string") {
  doSomething(appKeys.client_secret)
}
'''
    findings = r002(run(code, 'typescript', 'app.ts'))
    assert not findings, f"Must NOT fire: typeof type guard, got {findings}"


def test_fp_timing_safe_equal_suppresses():
    """FP: crypto.timingSafeEqual present in window suppresses the finding."""
    code = '''
const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex')
const provided = req.headers['x-hub-signature']
if (crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(provided))) {
  processWebhook()
}
'''
    findings = r002(run(code, 'javascript', 'webhook.js'))
    assert not findings, f"Must NOT fire: timingSafeEqual is present, got {findings}"


def test_fp_compare_digest_suppresses():
    """FP: hmac.compare_digest present in window suppresses the finding."""
    code = '''
import hmac
computed = hmac.new(key, msg).hexdigest()
if hmac.compare_digest(computed, provided):
    allow()
'''
    findings = r002(run(code, 'python', 'app.py'))
    assert not findings, f"Must NOT fire: compare_digest is present, got {findings}"


def test_fp_enum_status_check():
    """FP: tokenStatus === 'expired' — enum/string comparison."""
    code = '''
if (tokenStatus === 'expired') {
  return res.status(401).json({ error: 'expired' })
}
'''
    findings = r002(run(code, 'javascript', 'auth.js'))
    assert not findings, f"Must NOT fire: string literal comparison is enum check, got {findings}"


def test_fp_config_config_comparison_no_request_taint():
    """FP: two config values compared — no webhook var and no request taint."""
    code = '''
const expected = config.apiVersion
const actual = response.apiVersion
if (expected === actual) {
  proceed()
}
'''
    findings = r002(run(code, 'javascript', 'client.js'))
    assert not findings, f"Must NOT fire: no webhook var and no request taint, got {findings}"


def test_fp_webhook_var_but_string_literal_rhs():
    """FP: webhook_secret compared with a string literal — routing check."""
    code = '''
if (webhook_secret === 'disabled') {
  skipVerification()
}
'''
    findings = r002(run(code, 'javascript', 'handler.js'))
    assert not findings, f"Must NOT fire: webhook_secret vs string literal is routing/feature flag, got {findings}"


def test_fp_secrets_compare_digest_suppresses():
    """FP: secrets.compare_digest present in window suppresses."""
    code = '''
import secrets
computed = hashlib.sha256(data).hexdigest()
if secrets.compare_digest(computed, request.args['signature']):
    allow()
'''
    findings = r002(run(code, 'python', 'verify.py'))
    assert not findings, f"Must NOT fire: secrets.compare_digest is present, got {findings}"
