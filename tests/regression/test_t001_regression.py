"""
PRBL-T001 regression suite — Path Traversal.

Basic true positives and false negatives for path traversal detection.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from prbl.scanner.rules import run_all_rules


def run(code: str, language: str = 'javascript', file_path: str = 'test.js') -> list:
    return [{'rule_id': m.rule_id, 'severity': m.severity, 'line': m.line_number}
            for m in run_all_rules(code, language, file_path)]


# ── TRUE POSITIVES ────────────────────────────────────────────────────────────

def test_fs_read_user_input_fires():
    """True positive: fs.readFile() with user-controlled path concatenation fires T001."""
    code = '''
const file = req.query.filename
fs.readFile('/uploads/' + file)
'''
    findings = run(code)
    assert any(f['rule_id'] == 'PRBL-T001' for f in findings), \
        "PRBL-T001 must fire when fs.readFile is used with user input concatenation"


def test_python_path_traversal_fires():
    """True positive: Python open() with user-controlled path fires T001."""
    code = '''
def read_file(filename):
    with open('/uploads/' + filename) as f:
        return f.read()
'''
    findings = run(code, language='python', file_path='views.py')
    assert any(f['rule_id'] == 'PRBL-T001' for f in findings)


# ── FALSE POSITIVE REGRESSIONS ────────────────────────────────────────────────

def test_static_path_not_flagged():
    """True negative: fully static file path must not fire T001."""
    code = '''
const filePath = path.join(__dirname, 'public', 'index.html')
res.sendFile(filePath)
'''
    findings = run(code)
    t001 = [f for f in findings if f['rule_id'] == 'PRBL-T001']
    assert not t001, \
        f"PRBL-T001 must not fire on fully static path. Got: {t001}"


def test_dirname_only_not_flagged():
    """True negative: __dirname alone must not fire T001."""
    code = "const dir = path.join(__dirname, 'assets')"
    findings = run(code)
    t001 = [f for f in findings if f['rule_id'] == 'PRBL-T001']
    assert not t001, \
        f"PRBL-T001 must not fire on static __dirname join. Got: {t001}"


# ── EASY FIX: pathlib read_text / read_bytes sinks ────────────────────────────

def test_pathlib_read_text_user_input_fires():
    """True positive: pathlib Path.read_text() with user-controlled path fires T001."""
    code = '''
from pathlib import Path
def serve_file(filename):
    return Path('/uploads/' + filename).read_text()
'''
    findings = run(code, language='python', file_path='views.py')
    assert any(f['rule_id'] == 'PRBL-T001' for f in findings), \
        "PRBL-T001 must fire on pathlib Path.read_text() with user-controlled path"


def test_pathlib_read_bytes_user_input_fires():
    """True positive: pathlib Path.read_bytes() with user-controlled path fires T001."""
    code = '''
from pathlib import Path
def download(request):
    name = request.args.get('file')
    return Path('/data/' + name).read_bytes()
'''
    findings = run(code, language='python', file_path='api.py')
    assert any(f['rule_id'] == 'PRBL-T001' for f in findings), \
        "PRBL-T001 must fire on pathlib Path.read_bytes() with user input"


def test_pathlib_static_path_not_flagged():
    """True negative: pathlib Path.read_text() on a static path must not fire."""
    code = '''
from pathlib import Path
config = Path('/etc/app/config.json').read_text()
'''
    findings = run(code, language='python', file_path='init.py')
    t001 = [f for f in findings if f['rule_id'] == 'PRBL-T001']
    assert not t001, \
        f"PRBL-T001 must not fire on pathlib read_text() with fully static path. Got: {t001}"


# ── EASY FIX: C002 Django SECRET_KEY_BASE context ─────────────────────────────

def test_c002_secret_key_base_fires():
    """True positive: SECRET_KEY_BASE with hardcoded value fires C002."""
    code = '''
SECRET_KEY_BASE = 'hardcoded-very-long-secret-value-123456789'
'''
    findings = run(code, language='python', file_path='settings.py')
    c002 = [f for f in findings if f['rule_id'] == 'PRBL-C002']
    assert c002, "PRBL-C002 must fire on hardcoded SECRET_KEY_BASE"
