"""
PRBL-I004 regression suite — NoSQL Injection.

Covers:
  - $where triggering both I001 and I004 (double-fire prevented)
  - mongoose context signals should route to I004, not I001
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from prbl.scanner.rules import run_all_rules


def run(code: str, language: str = 'javascript', file_path: str = 'test.js') -> list:
    return [{'rule_id': m.rule_id, 'severity': m.severity, 'line': m.line_number}
            for m in run_all_rules(code, language, file_path)]


# ── TRUE POSITIVES ────────────────────────────────────────────────────────────

def test_req_body_to_find_fires_i004():
    """True positive: User.find(req.body) fires I004."""
    code = '''
function findUser(req) {
  return User.find(req.body)
}
'''
    findings = run(code)
    assert any(f['rule_id'] == 'PRBL-I004' for f in findings)


def test_dollar_where_string_concat_fires_i004():
    """True positive: $where string concatenation fires I004."""
    code = '''
function findUser(name) {
  collection.find({ $where: "this.name == '" + name + "'" })
}
'''
    findings = run(code)
    assert any(f['rule_id'] == 'PRBL-I004' for f in findings)


# ── FALSE POSITIVE REGRESSIONS ────────────────────────────────────────────────

def test_dollar_where_does_not_fire_i001():
    """Regression: $where must not fire I001 (it's NoSQL, not SQL)."""
    code = '''
function findUser(name) {
  collection.find({ $where: "this.name == '" + name + "'" })
}
'''
    findings = run(code)
    i001 = [f for f in findings if f['rule_id'] == 'PRBL-I001']
    assert not i001, \
        f"PRBL-I001 must not fire on $where (MongoDB operator). Got: {i001}"


def test_mongoose_import_alone_not_i001():
    """Regression: mongoose import must not cause I001 via SQL context signal."""
    code = '''
const mongoose = require('mongoose')
const filter = 'name_' + userId
User.find(filter)
'''
    findings = run(code)
    i001 = [f for f in findings if f['rule_id'] == 'PRBL-I001']
    assert not i001, \
        f"PRBL-I001 must not fire when only signal is mongoose (NoSQL driver). Got: {i001}"


def test_safe_nosql_query_not_flagged():
    """True negative: parameterized mongoose query must not fire."""
    code = '''
const user = await User.findOne({ email: req.body.email })
'''
    findings = run(code)
    i004 = [f for f in findings if f['rule_id'] == 'PRBL-I004']
    assert not i004, \
        f"PRBL-I004 must not fire on findOne with explicit field. Got: {i004}"


# ── pymongo dict-value injection (PRBL-I004 roadmap item 4) ──────────────────

def test_pymongo_dict_value_request_args_fires():
    """True positive: collection.find with request.args value inside dict fires I004."""
    code = '''
def search(request):
    collection.find({"name": request.args.get("name")})
'''
    findings = run(code, language='python', file_path='views.py')
    assert any(f['rule_id'] == 'PRBL-I004' for f in findings), \
        "PRBL-I004 must fire on collection.find() with request.args value in dict"


def test_pymongo_dict_value_request_form_fires():
    """True positive: collection.find with request.form in a multi-field dict fires I004."""
    code = '''
def login(request):
    users.find({"email": request.form["email"], "active": True})
'''
    findings = run(code, language='python', file_path='views.py')
    assert any(f['rule_id'] == 'PRBL-I004' for f in findings), \
        "PRBL-I004 must fire on collection.find() with request.form value in dict"


def test_pymongo_findone_request_json_fires():
    """True positive: collection.findOne with request.json value in dict fires I004."""
    code = '''
def authenticate(request):
    users.findOne({"username": request.json.get("username")})
'''
    findings = run(code, language='python', file_path='views.py')
    assert any(f['rule_id'] == 'PRBL-I004' for f in findings), \
        "PRBL-I004 must fire on collection.findOne() with request.json value in dict"


def test_pymongo_dict_static_value_not_flagged():
    """True negative: collection.find with only static values must not fire."""
    code = '''
def get_alices():
    collection.find({"name": "alice"})
'''
    findings = run(code, language='python', file_path='views.py')
    i004 = [f for f in findings if f['rule_id'] == 'PRBL-I004']
    assert not i004, \
        f"PRBL-I004 must not fire on find() with static string value. Got: {i004}"


def test_pymongo_dict_config_value_not_flagged():
    """True negative: collection.find with config.get() value must not fire (not request input)."""
    code = '''
def get_by_status():
    collection.find({"status": config.get("status")})
'''
    findings = run(code, language='python', file_path='views.py')
    i004 = [f for f in findings if f['rule_id'] == 'PRBL-I004']
    assert not i004, \
        f"PRBL-I004 must not fire on find() with config.get() value (not request input). Got: {i004}"


def test_pymongo_dict_no_taint_not_flagged():
    """True negative: find with computed status (no request taint) must not fire."""
    code = '''
STATUS = "active"
collection.find({"status": STATUS, "verified": True})
'''
    findings = run(code, language='python', file_path='db.py')
    i004 = [f for f in findings if f['rule_id'] == 'PRBL-I004']
    assert not i004, \
        f"PRBL-I004 must not fire on find() with no user taint. Got: {i004}"
