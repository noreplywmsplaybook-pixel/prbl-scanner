"""
PRBL-I002 regression suite — Command Injection.

Covers:
  - shell=True without traceable user input must not fire
  - RegExp .exec() false positive (covered in overlap tests, re-verified here)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from prbl.scanner.rules import run_all_rules


def run(code: str, language: str = 'javascript', file_path: str = 'test.js') -> list:
    return [{'rule_id': m.rule_id, 'severity': m.severity, 'line': m.line_number}
            for m in run_all_rules(code, language, file_path)]


# ── TRUE POSITIVES ────────────────────────────────────────────────────────────

def test_exec_with_user_input_fires():
    """True positive: exec() with string concatenation and user input fires I002."""
    code = '''
function run(userInput) {
  exec('ls ' + userInput)
}
'''
    findings = run(code)
    assert any(f['rule_id'] == 'PRBL-I002' for f in findings)


def test_spawn_template_literal_fires():
    """True positive: spawn() with template literal and user input fires I002."""
    code = '''
const cmd = req.query.cmd
exec(`ls ${cmd}`)
'''
    findings = run(code)
    assert any(f['rule_id'] == 'PRBL-I002' for f in findings)


def test_python_subprocess_user_input_fires():
    """True positive: subprocess.run() with user input fires I002."""
    code = '''
import subprocess
def run_cmd(user_cmd):
    subprocess.run("ls " + user_cmd, shell=True)
'''
    findings = run(code, language='python', file_path='utils.py')
    assert any(f['rule_id'] == 'PRBL-I002' for f in findings)


# ── FALSE POSITIVE REGRESSIONS ────────────────────────────────────────────────

def test_regex_exec_not_flagged():
    """Regression: someRegex.exec() is RegExp method, not shell exec."""
    code = '''
function process(userInput) {
  const match = someRegex.exec(userInput)
  return match
}
'''
    findings = run(code)
    i002 = [f for f in findings if f['rule_id'] == 'PRBL-I002']
    assert not i002, \
        f"PRBL-I002 must not fire on someRegex.exec() — this is RegExp.exec. Got: {i002}"


def test_shell_true_no_user_input_not_flagged():
    """Regression: shell=True without user input must not fire I002."""
    code = '''
import subprocess
subprocess.run(['ls', '-la'], shell=True)
'''
    findings = run(code, language='python', file_path='utils.py')
    i002 = [f for f in findings if f['rule_id'] == 'PRBL-I002']
    assert not i002, \
        f"PRBL-I002 must not fire on shell=True without user input. Got: {i002}"


def test_method_exec_variants_not_flagged():
    """Regression: .exec() method calls on other objects must not fire I002."""
    for code in [
        "db.exec(userInput)",
        "session.exec(userInput)",
        "stmt.exec(userInput)",
        "/pattern/.exec(userInput)",
    ]:
        findings = run(code)
        i002 = [f for f in findings if f['rule_id'] == 'PRBL-I002']
        assert not i002, \
            f"PRBL-I002 must not fire on .exec() method: {code!r}. Got: {i002}"
