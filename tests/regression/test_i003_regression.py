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


# ── PRBL-I003: importlib.import_module() code injection (ITEM 7) ──────────────

def test_importlib_user_controlled_fires():
    """True positive: importlib.import_module() with user-controlled input fires I003."""
    code = '''
import importlib
module = importlib.import_module(request.args["plugin"])
'''
    findings = run(code, language='python', file_path='loader.py')
    assert any(f['rule_id'] == 'PRBL-I003' for f in findings), \
        "PRBL-I003 must fire on importlib.import_module with request.args input"


def test_importlib_user_input_variable_fires():
    """True positive: importlib.import_module(user_input) fires I003."""
    code = '''
import importlib
def load_plugin(user_input):
    plugin = importlib.import_module(user_input)
'''
    findings = run(code, language='python', file_path='loader.py')
    assert any(f['rule_id'] == 'PRBL-I003' for f in findings), \
        "PRBL-I003 must fire on importlib.import_module with function parameter taint"


def test_importlib_form_input_fires():
    """True positive: importlib.import_module() with form input fires I003."""
    code = '''
import importlib
plugin_name = request.form.get("plugin")
mod = importlib.import_module(plugin_name)
'''
    findings = run(code, language='python', file_path='api.py')
    assert any(f['rule_id'] == 'PRBL-I003' for f in findings), \
        "PRBL-I003 must fire on importlib.import_module with request.form taint"


def test_importlib_literal_string_not_flagged():
    """True negative: importlib.import_module('myapp.models') must not fire."""
    code = 'importlib.import_module("myapp.models")'
    findings = run(code, language='python', file_path='utils.py')
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert not i003, \
        f"PRBL-I003 must not fire on importlib.import_module with literal string. Got: {i003}"


def test_importlib_config_setting_not_flagged():
    """True negative: importlib.import_module(settings.PLUGIN_MODULE) must not fire."""
    code = 'importlib.import_module(settings.PLUGIN_MODULE)'
    findings = run(code, language='python', file_path='config.py')
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert not i003, \
        f"PRBL-I003 must not fire on importlib.import_module with settings config. Got: {i003}"


def test_arbitrary_method_eval_not_flagged():
    """Regression: anyObject.eval() must not fire I003."""
    code = "vm.eval(code)"
    findings = run(code)
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert not i003, \
        f"PRBL-I003 must not fire on vm.eval(). Got: {i003}"


# ── CLASS A FP: shell-wrapper function definition ─────────────────────────────

def test_exec_wrapper_definition_not_flagged():
    """Regression FP Class A: defining an exec() wrapper must not fire I003.
    The function is an abstraction — its parameter 'command' is the wrapper's
    interface, not user taint reaching an actual dangerous eval."""
    code = '''
export function exec(command: string, args?: string[], options?: Partial<Options>) {
    return childProcess.exec(command, args, options)
}
'''
    findings = run(code, language='javascript', file_path='exec.ts')
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert not i003, \
        f"PRBL-I003 must not fire when defining an exec wrapper function. Got: {i003}"


def test_ts_overload_exec_not_flagged():
    """Regression FP Class A: TypeScript overload declaration for exec must not fire.
    Overloads have no body and cannot introduce taint."""
    code = '''
export function exec(command: string, callback: ExecCallback): ChildProcess;
export function exec(command: string, options: ExecOptions): ChildProcess;
export function exec(command: string, options?: ExecOptions, callback?: ExecCallback): ChildProcess {
    return child_process.exec(command, options as any, callback)
}
'''
    findings = run(code, language='javascript', file_path='child_process.ts')
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert not i003, \
        f"PRBL-I003 must not fire on TS exec() overload declarations. Got: {i003}"


def test_spawn_wrapper_definition_not_flagged():
    """Regression FP Class A: defining a spawn() wrapper must not fire I002."""
    code = '''
function spawn(cmd: string, args: string[]) {
    return child_process.spawn(cmd, args)
}
'''
    findings = run(code, language='javascript', file_path='spawn-util.ts')
    i002 = [f for f in findings if f['rule_id'] == 'PRBL-I002']
    assert not i002, \
        f"PRBL-I002 must not fire when defining a spawn() wrapper. Got: {i002}"


def test_exec_wrapper_tp_still_fires():
    """True positive: user-tainted exec in a non-wrapper context must still fire."""
    code = '''
app.post('/run', (req, res) => {
    const cmd = req.body.command
    exec(cmd)
})
'''
    findings = run(code, language='javascript', file_path='routes.js')
    i002_or_i003 = [f for f in findings if f['rule_id'] in ('PRBL-I002', 'PRBL-I003')]
    assert i002_or_i003, \
        "PRBL-I002 or PRBL-I003 must fire when user input is passed to exec. Got no findings."


# ── CLASS B FP: eval inside string literal ────────────────────────────────────

def test_eval_in_error_string_not_flagged():
    """Regression FP Class B: eval() in an error message string must not fire I003.
    Pattern from nextjs compiled bundles: throw new Error('eval() is not supported...')"""
    code = '''
export function exec(command: string) {
    throw new Error(
        "eval() is not supported in this environment. If this page was served with a " +
        "Content-Security-Policy header, make sure that `unsafe-eval` is included."
    )
}
'''
    findings = run(code, language='javascript', file_path='polyfill.js')
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert not i003, \
        f"PRBL-I003 must not fire when eval() appears inside a string literal. Got: {i003}"


def test_eval_in_string_single_line_not_flagged():
    """Regression FP Class B: single-line eval-in-string must not fire."""
    code = 'var msg = "eval() is not supported in this environment";\n'
    findings = run(code, language='javascript', file_path='error.js')
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert not i003, \
        f"PRBL-I003 must not fire when eval() appears only inside a string literal. Got: {i003}"


def test_compiled_bundle_path_skipped():
    """Regression FP Class B: files in /compiled/ path must be skipped entirely."""
    code = '''
function run(command) {
    eval(command)
}
'''
    findings = run(code, language='javascript',
                   file_path='/tmp/stress_batch/nextjs/packages/next/src/compiled/react/bundle.js')
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert not i003, \
        f"PRBL-I003 must not fire on files inside /compiled/ path. Got: {i003}"


# ── Fix 2: HN stress-test false positives ────────────────────────────────────

def test_playwright_dollar_dollar_eval_not_flagged():
    """Regression 2a: Playwright's page.$$eval() is a DOM query API method,
    unrelated to JS eval(). Found in parsaghaffari/browserbee during the HN
    stress test — the bare-eval pattern matched "eval(" inside "$$eval(" since
    '$' is a non-word character and satisfies the original word boundary."""
    code = '''
function run(req) {
    const matches = req.activePage.$$eval(req.body.selector, els => els.length)
}
'''
    findings = run(code, language='javascript', file_path='observationTools.ts')
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert not i003, f"PRBL-I003 must not fire on Playwright's $$eval(). Got: {i003}"


def test_playwright_single_dollar_eval_not_flagged():
    """Regression 2a: page.$eval() (single-element variant) is the same Playwright
    DOM query API as $$eval() and must not fire either."""
    code = '''
function run(req) {
    const el = req.activePage.$eval(req.body.selector, e => e.textContent)
}
'''
    findings = run(code, language='javascript', file_path='observationTools.ts')
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert not i003, f"PRBL-I003 must not fire on Playwright's $eval(). Got: {i003}"


def test_python_def_exec_shadow_not_flagged():
    """Regression 2b: a Python function literally named `exec` (shadowing the
    builtin) that recursively calls itself is not code injection. Found in
    Ligo-Biosciences/AlphaFold3's checkpointing.py during the HN stress test:
    `def exec(b, a): return exec(blocks[s:e], a)` — pure recursion on a
    user-defined function, not the eval/exec builtin. The shell-wrapper guard
    was JS-only (function/const/let/var) and missed Python's `def`."""
    code = '''
def exec(b, a):
    s, e = b
    return exec(blocks[s:e], a)
'''
    findings = run(code, language='python', file_path='checkpointing.py')
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert not i003, f"PRBL-I003 must not fire on a Python function shadowing exec/eval. Got: {i003}"


def test_python_def_run_cmd_still_fires():
    """Regression guard: the def-exec/eval shadow guard must be scoped to just
    the builtin names exec/eval — a function with a descriptive name like
    run_cmd that genuinely calls subprocess with shell=True must still fire."""
    code = '''
import subprocess
def run_cmd(user_cmd):
    subprocess.run("ls " + user_cmd, shell=True)
'''
    findings = run(code, language='python', file_path='utils.py')
    assert any(f['rule_id'] == 'PRBL-I002' for f in findings), \
        "A descriptively-named wrapper function must not get a free pass from the exec/eval shadow guard"


def test_importlib_literal_string_arg_not_flagged():
    """Regression 2c: importlib.import_module() with a hardcoded string literal
    cannot be attacker-controlled. Found repeatedly in Kanaries/pygwalker's test
    suite during the HN stress test: importlib.reload(importlib.import_module(
    "pygwalker.api.reflex")) — a fixed internal module path, not user input."""
    code = '''
def reload_api(request):
    reflex = importlib.reload(importlib.import_module("pygwalker.api.reflex"))
    return reflex
'''
    findings = run(code, language='python', file_path='test_integration_apis.py')
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert not i003, \
        f"PRBL-I003 must not fire on importlib.import_module() with a literal string. Got: {i003}"


def test_importlib_variable_arg_still_fires():
    """Regression guard: importlib.import_module() with a VARIABLE argument is
    still a legitimate candidate for review — only literal string arguments
    are suppressed, since a variable might carry tainted input."""
    code = '''
def load_plugin(request):
    module_path = request.get_json()["plugin"]
    module = importlib.import_module(module_path)
    return module
'''
    findings = run(code, language='python', file_path='plugin_loader.py')
    i003 = [f for f in findings if f['rule_id'] == 'PRBL-I003']
    assert i003, \
        "PRBL-I003 must still fire on importlib.import_module() with a variable argument"
