"""
PRBL-R003 regression suite — AES-GCM cipher created without authentication tag length verification.

Detects crypto.createDecipheriv() with AES-GCM mode where setAuthTagLength() is
not called within a 20-line lookahead window.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from prbl.scanner.rules import run_all_rules


def run(code: str, language: str = 'javascript', file_path: str = 'app.js') -> list:
    return [{'rule_id': m.rule_id, 'severity': m.severity, 'line': m.line_number}
            for m in run_all_rules(code, language, file_path)]


def r003(findings):
    return [f for f in findings if f['rule_id'] == 'PRBL-R003']


# ── TRUE POSITIVES ────────────────────────────────────────────────────────────

def test_basic_aes256_gcm_no_auth_tag_length():
    """TP1: Basic aes-256-gcm with no setAuthTagLength anywhere in window."""
    code = '''
const crypto = require('crypto');
const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
decipher.setAuthTag(authTag);
const decrypted = decipher.update(ciphertext, 'hex', 'utf8') + decipher.final('utf8');
'''
    findings = r003(run(code))
    assert findings, "Must fire: aes-256-gcm without setAuthTagLength"
    assert findings[0]['severity'] == 'high'


def test_aes128_gcm_variant():
    """TP2: aes-128-gcm variant."""
    code = '''
const crypto = require('crypto');
const decipher = crypto.createDecipheriv('aes-128-gcm', key, iv);
decipher.setAuthTag(tag);
const out = decipher.update(data, 'hex', 'utf8') + decipher.final('utf8');
'''
    findings = r003(run(code))
    assert findings, "Must fire: aes-128-gcm without setAuthTagLength"


def test_aes192_gcm_variant():
    """TP3: aes-192-gcm variant."""
    code = '''
const crypto = require('crypto');
const decipher = crypto.createDecipheriv('aes-192-gcm', key, iv);
decipher.setAuthTag(tag);
const out = decipher.update(data, 'hex', 'utf8') + decipher.final('utf8');
'''
    findings = r003(run(code))
    assert findings, "Must fire: aes-192-gcm without setAuthTagLength"


def test_setauthtag_present_but_not_setauthtaglength():
    """TP4: setAuthTag() is present but setAuthTagLength() is absent — common mistake."""
    code = '''
const crypto = require('crypto');
function decrypt(ciphertext, key, iv, authTag) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);  // passes the tag bytes, but doesn't enforce length
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
'''
    findings = r003(run(code))
    assert findings, "Must fire: setAuthTag present but not setAuthTagLength"


def test_multiple_deciphers_only_second_fires():
    """TP5: Multiple decipher instances — first has setAuthTagLength, second doesn't."""
    code = '''
const crypto = require('crypto');
// First decipher — correctly configured
const d1 = crypto.createDecipheriv('aes-256-gcm', key1, iv1);
d1.setAuthTagLength(16);
d1.setAuthTag(tag1);
const out1 = d1.update(ct1, 'hex', 'utf8') + d1.final('utf8');

// Second decipher — missing setAuthTagLength
const d2 = crypto.createDecipheriv('aes-256-gcm', key2, iv2);
d2.setAuthTag(tag2);
const out2 = d2.update(ct2, 'hex', 'utf8') + d2.final('utf8');
'''
    findings = r003(run(code))
    assert len(findings) == 1, f"Must fire exactly once (for d2): got {findings}"
    # The second createDecipheriv is on line 11
    assert findings[0]['line'] > 5, "Finding should be on the second decipher line"


def test_setauthtaglength_outside_20_line_window():
    """TP6: setAuthTagLength present but >20 lines after createDecipheriv — fires."""
    padding = '\n'.join([f'const x{i} = {i};' for i in range(25)])
    code = f'''
const crypto = require('crypto');
const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
{padding}
decipher.setAuthTagLength(16);
decipher.setAuthTag(tag);
const out = decipher.update(data) + decipher.final('utf8');
'''
    findings = r003(run(code))
    assert findings, "Must fire: setAuthTagLength is outside the 20-line lookahead"


# ── FALSE POSITIVES ───────────────────────────────────────────────────────────

def test_setauthtaglength_16_present_no_finding():
    """FP7: setAuthTagLength(16) called within 5 lines → no finding."""
    code = '''
const crypto = require('crypto');
const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
decipher.setAuthTagLength(16);
decipher.setAuthTag(authTag);
const decrypted = decipher.update(ciphertext, 'hex', 'utf8') + decipher.final('utf8');
'''
    findings = r003(run(code))
    assert not findings, f"Must NOT fire: setAuthTagLength(16) present. Got: {findings}"


def test_setauthtaglength_nonstandard_12_no_finding():
    """FP8: setAuthTagLength(12) — non-standard but explicit — no finding."""
    code = '''
const crypto = require('crypto');
const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
decipher.setAuthTagLength(12);  // explicitly set to 12 bytes
decipher.setAuthTag(authTag);
const decrypted = decipher.update(ciphertext, 'hex', 'utf8') + decipher.final('utf8');
'''
    findings = r003(run(code))
    assert not findings, f"Must NOT fire: explicit setAuthTagLength present. Got: {findings}"


def test_createcipheriv_encryption_not_decryption():
    """FP9: createCipheriv (encryption side) — must NOT fire."""
    code = '''
const crypto = require('crypto');
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const encrypted = cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
const authTag = cipher.getAuthTag();
'''
    findings = r003(run(code))
    assert not findings, f"Must NOT fire on createCipheriv (encryption). Got: {findings}"


def test_aes_256_cbc_not_gcm():
    """FP10: createDecipheriv with AES-CBC — rule is GCM-only."""
    code = '''
const crypto = require('crypto');
const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
const decrypted = decipher.update(ciphertext, 'hex', 'utf8') + decipher.final('utf8');
'''
    findings = r003(run(code))
    assert not findings, f"Must NOT fire on AES-CBC mode. Got: {findings}"


def test_aes_256_ctr_not_gcm():
    """FP11: createDecipheriv with AES-CTR — rule is GCM-only."""
    code = '''
const crypto = require('crypto');
const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
const decrypted = decipher.update(ciphertext, 'hex', 'utf8') + decipher.final('utf8');
'''
    findings = r003(run(code))
    assert not findings, f"Must NOT fire on AES-CTR mode. Got: {findings}"


def test_test_file_skipped():
    """FP12: File in test directory → no finding."""
    code = '''
const crypto = require('crypto');
const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
decipher.setAuthTag(authTag);
const decrypted = decipher.update(ciphertext, 'hex', 'utf8') + decipher.final('utf8');
'''
    findings = r003(run(code, file_path='tests/crypto.test.js'))
    assert not findings, f"Must NOT fire in test files. Got: {findings}"


def test_python_file_not_js():
    """FP13: Python file — rule is JS/TS only."""
    code = '''
# Python code mentioning createDecipheriv (should not fire)
line = "crypto.createDecipheriv('aes-256-gcm', key, iv)"
print(line)
'''
    findings = r003(run(code, language='python', file_path='app.py'))
    assert not findings, f"Must NOT fire on Python files. Got: {findings}"


def test_commented_out_createDecipheriv():
    """FP14: Commented-out createDecipheriv — must NOT fire."""
    code = '''
const crypto = require('crypto');
// const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
// The above is disabled; using a different approach below
const result = 'not using gcm';
'''
    findings = r003(run(code))
    assert not findings, f"Must NOT fire on commented-out code. Got: {findings}"


def test_setauthtaglength_at_line_20_of_window_fires():
    """TP15: setAuthTagLength exactly 21 lines after createDecipheriv — fires."""
    # 21 padding lines puts setAuthTagLength outside the 20-line window
    padding = '\n'.join([f'doSomething({i});' for i in range(21)])
    code = f'''const crypto = require('crypto');
const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
{padding}
decipher.setAuthTagLength(16);
'''
    findings = r003(run(code))
    assert findings, "Must fire: setAuthTagLength is outside 20-line window"


def test_setauthtaglength_within_window_no_finding():
    """Boundary: setAuthTagLength exactly within 20-line window — no finding."""
    # 19 padding lines, then setAuthTagLength — should be in window
    padding = '\n'.join([f'doSomething({i});' for i in range(18)])
    code = f'''const crypto = require('crypto');
const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
{padding}
decipher.setAuthTagLength(16);
decipher.setAuthTag(tag);
'''
    findings = r003(run(code))
    assert not findings, f"Must NOT fire: setAuthTagLength within 20-line window. Got: {findings}"


def test_typescript_file_fires():
    """TP: TypeScript file — rule applies to JS/TS."""
    code = '''
import * as crypto from 'crypto';
const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
decipher.setAuthTag(authTag);
const decrypted = decipher.update(ciphertext) + decipher.final('utf8');
'''
    findings = r003(run(code, language='javascript', file_path='decrypt.ts'))
    assert findings, "Must fire on TypeScript files"
    assert findings[0]['severity'] == 'high'


def test_case_insensitive_algorithm_string():
    """TP: Case-insensitive algorithm name match."""
    code = '''
const crypto = require('crypto');
const decipher = crypto.createDecipheriv('AES-256-GCM', key, iv);
decipher.setAuthTag(authTag);
const out = decipher.update(data);
'''
    findings = r003(run(code))
    assert findings, "Must fire: case-insensitive AES-256-GCM match"
