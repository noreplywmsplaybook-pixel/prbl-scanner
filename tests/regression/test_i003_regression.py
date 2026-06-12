"""
PRBL-I003 regression suite — Code Injection (eval/exec).

Covers:
  - .eval() / .exec() method call false positives (negative lookbehind for '.')
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from prbl.scanner.rules import run_all_rules


def run(code: str, language: str = 'javascript', file_path: str = 'test.js') -> list:
    return [{'rule_id': m.rule_id, 'severity': m.severity, 'line': m.line_number}
            for m in run_all_rules(code, language, file_path)]


# ── TRUE POSITIVES ────────────────────────────────────────────────────────────

def test_bare_eval_fires():
    """True positive: bare eval() with user input fires I003."""
    code = '''
const userCode = req.body.code
eval(userCode)
'''
    findings = run(code)
    assert any(f['rule_id'] == 'PRBL-I003' for f in findings)


def test_new_function_fires():
    """True positive: new Function() with user-controlled input fires I003."""
    code = "const fn = new Function('return ' + req.body.code)"
    findings = run(code)
    assert any(f['rule_id'] == 'PRBL-I003' for f in findings)


# ── FALSE POSITIVE REGRESSIONS ────────────────────────────────────────────────

def test_db_eval_not_flagged():
    """Regression: db.eval() method call must not fire I003."""
    code = "db.eval('some expression')"
    findings = run(code)
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert not i003, \
        f"PRBL-I003 must not fire on db.eval() — it's a method call, not bare eval. Got: {i003}"


def test_session_exec_not_flagged():
    """Regression: session.exec() must not fire I003."""
    code = "session.exec(query)"
    findings = run(code)
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert not i003, \
        f"PRBL-I003 must not fire on session.exec(). Got: {i003}"


def test_regex_exec_not_flagged():
    """Regression: /pattern/.exec() must not fire I003."""
    code = "/[a-z]+/.exec(userInput)"
    findings = run(code)
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert not i003, \
        f"PRBL-I003 must not fire on regex .exec(). Got: {i003}"


def test_arbitrary_method_eval_not_flagged():
    """Regression: anyObject.eval() must not fire I003."""
    code = "vm.eval(code)"
    findings = run(code)
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert not i003, \
        f"PRBL-I003 must not fire on vm.eval(). Got: {i003}"
