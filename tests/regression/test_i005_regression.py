"""
Regression tests for PRBL-I005: Prototype pollution via tainted bracket assignment.
22 tests: 10 true positives + 12 false positives (must NOT fire).
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from prbl.scanner.rules import run_all_rules


def _findings(code: str, language: str = "javascript", file_path: str = "app.js"):
    return [r for r in run_all_rules(code, language, file_path=file_path)
            if r.rule_id == "PRBL-I005"]


# ── True Positives (must fire) ────────────────────────────────────────────────

def test_tp_direct_req_params_key():
    """Shape 1: bracket key is req.params.* directly."""
    code = "obj[req.params.key] = value;"
    assert _findings(code), "Expected PRBL-I005 to fire on req.params key"


def test_tp_req_query_key():
    """Shape 1: bracket key is req.query.*."""
    code = "obj[req.query.field] = value;"
    assert _findings(code), "Expected PRBL-I005 to fire on req.query key"


def test_tp_req_body_key():
    """Shape 1: bracket key is req.body.*."""
    code = "config[req.body.name] = userValue;"
    assert _findings(code), "Expected PRBL-I005 to fire on req.body key"


def test_tp_variable_key_traced_to_request():
    """Shape 2: variable key traced to req.params in lookback."""
    code = (
        "const key = req.params.field;\n"
        "obj[key] = value;\n"
    )
    assert _findings(code), "Expected PRBL-I005 to fire on tainted variable key"


def test_tp_function_param_key():
    """Shape 3: request handler function with bracket key assignment."""
    code = (
        "function setProperty(req, key, val) {\n"
        "    req.data[key] = val;\n"
        "}\n"
    )
    assert _findings(code), "Expected PRBL-I005 to fire on request handler param key"


def test_tp_nested_req_taint():
    """Shape 1: nested tainted bracket access."""
    code = "target[req.params.prop] = value;"
    assert _findings(code), "Expected PRBL-I005 to fire on nested req.params"


def test_tp_config_variable_from_body():
    """Shape 2: config[userKey] where userKey = req.body.key in lookback."""
    code = (
        "const userKey = req.body.key;\n"
        "config[userKey] = userValue;\n"
    )
    assert _findings(code), "Expected PRBL-I005 to fire on config[userKey] traced to req.body"


def test_tp_schema_path_function_param():
    """Shape 3: request handler with bracket assignment on schema key."""
    code = (
        "function defineField(req, schema, path) {\n"
        "    schema[path] = req.body.definition;\n"
        "}\n"
    )
    assert _findings(code), "Expected PRBL-I005 to fire on schema[path] with req taint"


def test_tp_multiple_assignments_only_tainted_fires():
    """Only the tainted assignment fires, not a safe one."""
    code = (
        "safe['literal'] = 1;\n"
        "obj[req.query.prop] = 2;\n"
    )
    results = _findings(code)
    assert len(results) == 1, f"Expected exactly 1 finding, got {len(results)}"
    assert results[0].line_number == 2


def test_tp_arrow_function_param_key():
    """Shape 3: arrow function handler with req and bracket assignment."""
    code = (
        "const handler = (req, res) => {\n"
        "    const key = req.body.field;\n"
        "    target[key] = value;\n"
        "};\n"
    )
    assert _findings(code), "Expected PRBL-I005 to fire on arrow function with req taint"


# ── False Positives (must NOT fire) ──────────────────────────────────────────

def test_fp_string_literal_key():
    """String literal keys are never prototype pollution."""
    code = "obj['literal_key'] = value;"
    assert not _findings(code), "Must NOT fire on string literal key"


def test_fp_numeric_index():
    """Numeric array index is not prototype pollution."""
    code = "arr[0] = value;"
    assert not _findings(code), "Must NOT fire on numeric index"


def test_fp_loop_counter_key():
    """Loop counter variable (i) is not prototype pollution."""
    code = (
        "for (let i = 0; i < arr.length; i++) {\n"
        "    arr[i] = transform(arr[i]);\n"
        "}\n"
    )
    assert not _findings(code), "Must NOT fire on loop counter index 'i'"


def test_fp_map_set_method():
    """Map.set() is not bracket assignment — should not fire."""
    code = (
        "const m = new Map();\n"
        "m.set(key, value);\n"
    )
    assert not _findings(code), "Must NOT fire on Map.set()"


def test_fp_null_prototype_object():
    """Object.create(null) has no prototype to pollute."""
    code = (
        "const safeObj = Object.create(null);\n"
        "safeObj[key] = value;\n"
    )
    assert not _findings(code), "Must NOT fire on Object.create(null) target"


def test_fp_target_name_cache():
    """Target object named 'cache' is a common legitimate use."""
    code = "cache[key] = computedValue;"
    assert not _findings(code), "Must NOT fire when target is named 'cache'"


def test_fp_python_file():
    """Rule is JS/TS only — Python file must not fire."""
    code = "obj[key] = value\n"
    assert not _findings(code, language="python", file_path="app.py"), \
        "Must NOT fire for Python files"


def test_fp_has_own_property_guard():
    """hasOwnProperty check nearby suppresses finding."""
    code = (
        "if (Object.prototype.hasOwnProperty.call(obj, key)) {\n"
        "    obj[key] = value;\n"
        "}\n"
    )
    assert not _findings(code), "Must NOT fire when hasOwnProperty check is present"


def test_fp_allowlist_includes_check():
    """ALLOWED_KEYS.includes(key) in lookback suppresses finding."""
    code = (
        "const key = req.params.field;\n"
        "if (ALLOWED_KEYS.includes(key)) {\n"
        "    obj[key] = value;\n"
        "}\n"
    )
    assert not _findings(code), "Must NOT fire when allowlist check is present"


def test_fp_map_target_bracket():
    """New Map assigned to variable — bracket on that variable is not pollution."""
    code = (
        "const m = new Map();\n"
        "m[key] = value;\n"
    )
    assert not _findings(code), "Must NOT fire when target is a Map instance"


def test_fp_target_name_store():
    """Target object named 'store' is a common legitimate use."""
    code = "store[actionType] = handler;"
    assert not _findings(code), "Must NOT fire when target is named 'store'"


def test_fp_idx_key_name():
    """Key variable named 'idx' is a loop index — suppress."""
    code = (
        "for (let idx = 0; idx < items.length; idx++) {\n"
        "    result[idx] = process(items[idx]);\n"
        "}\n"
    )
    assert not _findings(code), "Must NOT fire on 'idx' key variable"


# ── FP regressions: array destructuring confused with bracket assignment ────
# `const [x] = await asyncCall()` matches the same `\w[\w.]*\[\w[\w.]*\]\s*=`
# shape as `obj[key] = value` — group(1) captures "const" (a declaration
# keyword, not a real object) and group(2) captures the destructured variable
# name, not a property key. Found in production in niledatabase/nile-auth's
# own authentication code during a 976-repo HN stress test — at its worst
# this single bug accounted for the majority of I005 findings in a batch.

def test_fp_destructuring_const_session():
    """Array destructuring of an async auth call — not bracket assignment."""
    code = "const [session] = await auth(req)"
    assert not _findings(code, language="typescript", file_path="auth.ts"), \
        "Must NOT fire on array destructuring `const [session] = await auth(req)`"


def test_fp_destructuring_const_csrf_token():
    """Array destructuring of an async CSRF check — not bracket assignment."""
    code = "const [hasValidToken] = await validCsrfToken(req)"
    assert not _findings(code, language="typescript", file_path="auth.ts"), \
        "Must NOT fire on array destructuring `const [hasValidToken] = await validCsrfToken()`"


def test_fp_destructuring_let_and_var():
    """`let` and `var` destructuring must be suppressed the same as `const`."""
    code1 = "let [first] = await getRows(req)"
    code2 = "var [row] = await db.select().from(users)"
    assert not _findings(code1, language="typescript", file_path="db.ts")
    assert not _findings(code2, language="typescript", file_path="db.ts")


def test_tp_real_bracket_assignment_with_tainted_key_still_fires():
    """Regression guard: the destructuring fix must not weaken real bracket
    assignment detection — a tainted key in a request-handler context must
    still fire."""
    code = (
        "function handler(req, res) {\n"
        "  const userKey = req.params.key\n"
        "  obj[userKey] = value\n"
        "}\n"
    )
    assert _findings(code, language="typescript", file_path="handler.ts"), \
        "Must still fire PRBL-I005 on real obj[key] = value with a tainted key"
