"""
PRBL-I001 regression suite — SQL Injection.

Also covers:
  - Python %-string formatting SQL injection (psycopg2 / legacy pattern)

Covers every false-positive fix discovered across production stress testing:
  - Mongoose .select('+password') was flagged as SQL injection
  - mongoose removed from SQL context signals
  - useOnyx() template literals with keys like LAST_SELECTED_FEED (word boundary issue)
  - @vercel/postgres sql``, Prisma $queryRaw``, Drizzle sql`` safe parameterized templates
  - window.confirm() / alert() / prompt() falsely flagged as SQL sinks
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from prbl.scanner.rules import run_all_rules


def run(code: str, language: str = 'javascript', file_path: str = 'test.js') -> list:
    return [{'rule_id': m.rule_id, 'severity': m.severity, 'line': m.line_number}
            for m in run_all_rules(code, language, file_path)]


# ── TRUE POSITIVES ────────────────────────────────────────────────────────────

def test_sql_string_concat_fires():
    """True positive: string concatenation into SQL must be caught."""
    code = '''
const query = "SELECT * FROM users WHERE id = " + req.params.id
db.execute(query)
'''
    findings = run(code)
    assert any(f['rule_id'] == 'PRBL-I001' for f in findings)


def test_sql_template_literal_fires():
    """True positive: template literal with SQL keyword and taint fires."""
    code = '''
const id = req.query.id
const q = `SELECT * FROM users WHERE id = ${id}`
db.query(q)
'''
    findings = run(code)
    assert any(f['rule_id'] == 'PRBL-I001' for f in findings)


def test_python_fstring_sql_fires():
    """True positive: Python f-string SQL injection fires."""
    code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
'''
    findings = run(code, language='python', file_path='views.py')
    assert any(f['rule_id'] == 'PRBL-I001' for f in findings)


def test_sql_assignment_concat_fires():
    """True positive: sql variable built with user input + concatenation fires."""
    code = '''
const db = require('pg')
const name = req.query.name
const sql = "SELECT * FROM users WHERE name = '" + name + "'"
db.query(sql)
'''
    findings = run(code)
    assert any(f['rule_id'] == 'PRBL-I001' for f in findings)


# ── FALSE POSITIVE REGRESSIONS ────────────────────────────────────────────────

def test_mongoose_select_password_not_sql_injection():
    """Regression: Mongoose .select('+password') was falsely flagged as SQL injection."""
    code = "const user = await User.findOne({ email }).select('+password')"
    findings = run(code)
    assert not any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        f"PRBL-I001 must not fire on mongoose .select('+password'). Got: {findings}"


def test_mongoose_not_sql_context_signal():
    """Regression: mongoose alone must not act as SQL context signal for I001."""
    code = '''
const mongoose = require('mongoose')
function lookupUser(userId) {
  const filter = 'name_' + userId
  return User.find(filter)
}
'''
    findings = run(code)
    i001 = [f for f in findings if f['rule_id'] == 'PRBL-I001']
    assert not i001, \
        f"PRBL-I001 must not fire when only context signal is mongoose (NoSQL). Got: {i001}"


def test_last_selected_feed_not_sql_injection():
    """Regression: LAST_SELECTED_FEED contains 'SELECT' but is not SQL injection."""
    code = '''
const key = `${ONYXKEYS.LAST_SELECTED_FEED}_${accountID}`
useOnyx(key)
'''
    findings = run(code)
    assert not any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "PRBL-I001 must not fire on LAST_SELECTED_FEED key construction (no SQL context)"


def test_updated_at_not_sql_injection():
    """Regression: UPDATED_AT contains 'UPDATE' but is not SQL injection."""
    code = '''
const key = `${ONYXKEYS.UPDATED_AT}_${userId}`
useOnyx(key)
'''
    findings = run(code)
    assert not any(f['rule_id'] == 'PRBL-I001' for f in findings)


def test_vercel_postgres_sql_tag_safe():
    """Regression: @vercel/postgres sql tagged template is parameterized — safe."""
    code = '''
import { sql } from "@vercel/postgres"
const userId = req.query.id
const result = await sql`SELECT * FROM users WHERE id = ${userId}`
'''
    findings = run(code)
    assert not any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "PRBL-I001 must not fire on @vercel/postgres sql`` tagged template"


def test_prisma_query_raw_safe():
    """Regression: Prisma $queryRaw tagged template is parameterized — safe."""
    code = '''
import { PrismaClient } from "@prisma/client"
const prisma = new PrismaClient()
const userId = req.params.id
const users = await prisma.$queryRaw`SELECT * FROM User WHERE id = ${userId}`
'''
    findings = run(code)
    assert not any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "PRBL-I001 must not fire on Prisma $queryRaw tagged template"


def test_drizzle_sql_tag_safe():
    """Regression: Drizzle sql tagged template is parameterized — safe."""
    code = '''
import { sql } from "drizzle-orm"
const userId = req.query.id
const result = await db.execute(sql`SELECT * FROM users WHERE id = ${userId}`)
'''
    findings = run(code)
    assert not any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "PRBL-I001 must not fire on drizzle sql`` tagged template"


def test_window_confirm_not_sql_sink():
    """Regression: window.confirm() must not be flagged as SQL injection sink."""
    code = '''
const confirmed = window.confirm("DELETE this record?")
if (confirmed) { deleteRecord() }
'''
    findings = run(code)
    assert not any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "PRBL-I001 must not fire on window.confirm() — it is a browser dialog, not a SQL sink"


def test_alert_not_sql_sink():
    """Regression: alert() must not be flagged as SQL injection sink."""
    code = '''
alert("SELECT your option:")
'''
    findings = run(code)
    assert not any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "PRBL-I001 must not fire on alert()"


def test_prompt_not_sql_sink():
    """Regression: prompt() must not be flagged as SQL injection sink."""
    code = '''
const name = prompt("INSERT your name:")
'''
    findings = run(code)
    assert not any(f['rule_id'] == 'PRBL-I001' for f in findings)


def test_template_literal_no_sql_context_not_flagged():
    """Regression: template literal with SQL keyword but no SQL context nearby should not fire."""
    code = '''
const cacheKey = `SELECTED_ITEMS_${userId}`
localStorage.setItem(cacheKey, JSON.stringify(items))
'''
    findings = run(code)
    assert not any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "PRBL-I001 must not fire on cache key construction with no SQL context"


def test_orm_method_calls_not_sql_injection():
    """Regression: model.update(), session.delete() etc. are ORM methods, not SQL."""
    cases = [
        "await User.update({ name: req.body.name }, { where: { id } })",
        "await session.delete(record)",
        "cipher.update(data, 'utf8', 'hex')",
    ]
    for code in cases:
        findings = run(code)
        i001 = [f for f in findings if f['rule_id'] == 'PRBL-I001']
        assert not i001, f"PRBL-I001 must not fire on ORM method call: {code!r}. Got: {i001}"


# ── EASY FIX: Python %-string formatting SQL injection ────────────────────────

def test_python_percent_format_sql_injection_fires():
    """True positive: Python %-format SQL injection (psycopg2 legacy pattern) fires I001."""
    code = '''
def get_user(username):
    query = "SELECT * FROM users WHERE name = '%s'" % username
    cursor.execute(query)
'''
    findings = run(code, language='python', file_path='db.py')
    assert any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "PRBL-I001 must fire on Python %-format SQL injection"


def test_python_percent_format_select_fires():
    """True positive: Python %-format with SELECT fires I001."""
    code = '''
def search(term):
    sql = "SELECT id, name FROM products WHERE category = '%s'" % term
    return cursor.execute(sql)
'''
    findings = run(code, language='python', file_path='products.py')
    assert any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "PRBL-I001 must fire on %-format SELECT injection"


def test_python_percent_format_safe_static_not_flagged():
    """True negative: Python %-format with a static string (no taint) must not fire."""
    code = '''
TABLE = "users"
query = "SELECT * FROM %s" % TABLE
cursor.execute(query)
'''
    findings = run(code, language='python', file_path='db.py')
    i001 = [f for f in findings if f['rule_id'] == 'PRBL-I001']
    assert not i001, \
        f"PRBL-I001 must not fire on %-format with a static constant (no user taint). Got: {i001}"


# ── SQLAlchemy text() sink (PRBL-I001 roadmap item 1) ────────────────────────

def test_sqlalchemy_text_concat_fires():
    """True positive: SQLAlchemy text() with string concatenation fires I001."""
    code = '''
from sqlalchemy import text
def get_user(user_id):
    result = db.execute(text("SELECT * FROM users WHERE id = " + user_id))
'''
    findings = run(code, language='python', file_path='db.py')
    assert any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "PRBL-I001 must fire on SQLAlchemy text() with string concatenation"


def test_sqlalchemy_text_fstring_fires():
    """True positive: SQLAlchemy text() with f-string fires I001."""
    code = '''
from sqlalchemy import text
def get_user(user_id):
    result = db.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))
'''
    findings = run(code, language='python', file_path='db.py')
    assert any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "PRBL-I001 must fire on SQLAlchemy text() with f-string interpolation"


def test_sqlalchemy_text_request_args_fires():
    """True positive: SQLAlchemy text() with request.args fires I001."""
    code = '''
from sqlalchemy import text
def search(request):
    uid = request.args.get("id")
    result = db.execute(text("SELECT * FROM users WHERE id = " + uid))
'''
    findings = run(code, language='python', file_path='views.py')
    assert any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "PRBL-I001 must fire on SQLAlchemy text() with request.args taint"


def test_sqlalchemy_text_bare_static_not_flagged():
    """True negative: SQLAlchemy text() with a bare static string must not fire."""
    code = '''
from sqlalchemy import text
result = db.execute(text("SELECT * FROM users"))
'''
    findings = run(code, language='python', file_path='db.py')
    i001 = [f for f in findings if f['rule_id'] == 'PRBL-I001']
    assert not i001, \
        f"PRBL-I001 must not fire on text() with bare static SQL (no interpolation). Got: {i001}"


def test_sqlalchemy_text_parameterized_not_flagged():
    """True negative: SQLAlchemy text() with named bound parameters must not fire."""
    code = '''
from sqlalchemy import text
def get_user(user_id):
    result = db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
'''
    findings = run(code, language='python', file_path='db.py')
    i001 = [f for f in findings if f['rule_id'] == 'PRBL-I001']
    assert not i001, \
        f"PRBL-I001 must not fire on text() with parameterized :id placeholder. Got: {i001}"


def test_sqlalchemy_text_no_taint_not_flagged():
    """True negative: SQLAlchemy text() concat with no user taint must not fire."""
    code = '''
from sqlalchemy import text
TABLE = "users"
result = db.execute(text("SELECT * FROM " + TABLE))
'''
    findings = run(code, language='python', file_path='db.py')
    i001 = [f for f in findings if f['rule_id'] == 'PRBL-I001']
    assert not i001, \
        f"PRBL-I001 must not fire on text() concat with static constant (no user taint). Got: {i001}"


# ── Python .format() string SQL injection (PRBL-I001 roadmap item 2) ─────────

def test_format_string_sql_fires():
    """True positive: .format() SQL injection with user input fires I001."""
    code = '''
def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
'''
    findings = run(code, language='python', file_path='db.py')
    assert any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "PRBL-I001 must fire on .format() SQL injection"


def test_format_string_table_injection_fires():
    """True positive: .format() with table name and WHERE clause fires I001."""
    code = '''
def search(table, name):
    query = "SELECT * FROM {} WHERE name = '{}'".format(table, name)
    cursor.execute(query)
'''
    findings = run(code, language='python', file_path='db.py')
    assert any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "PRBL-I001 must fire on .format() with table and WHERE clause"


def test_format_string_request_args_fires():
    """True positive: .format() with request.args fires I001."""
    code = '''
def search(request):
    uid = request.args["id"]
    cursor.execute("SELECT * FROM users WHERE id = {}".format(uid))
'''
    findings = run(code, language='python', file_path='views.py')
    assert any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "PRBL-I001 must fire on .format() SQL injection with request.args taint"


def test_format_string_log_message_not_flagged():
    """True negative: .format() on a log message must not fire (not a SQL context)."""
    code = '''
def process(user_id):
    log_message = "Processing user {}".format(user_id)
    print(log_message)
'''
    findings = run(code, language='python', file_path='utils.py')
    i001 = [f for f in findings if f['rule_id'] == 'PRBL-I001']
    assert not i001, \
        f"PRBL-I001 must not fire on .format() used for a log message (no SQL context). Got: {i001}"


def test_format_string_no_taint_not_flagged():
    """True negative: .format() SQL string with only static args must not fire."""
    code = '''
TABLE = "users"
LIMIT = 10
query = "SELECT * FROM {} LIMIT {}".format(TABLE, LIMIT)
cursor.execute(query)
'''
    findings = run(code, language='python', file_path='db.py')
    i001 = [f for f in findings if f['rule_id'] == 'PRBL-I001']
    assert not i001, \
        f"PRBL-I001 must not fire on .format() with static constants only (no user taint). Got: {i001}"


def test_format_string_insert_fires():
    """True positive: .format() with INSERT keyword fires I001."""
    code = '''
def insert_record(name):
    cursor.execute("INSERT INTO users (name) VALUES ('{}')".format(name))
'''
    findings = run(code, language='python', file_path='db.py')
    assert any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "PRBL-I001 must fire on .format() with INSERT SQL keyword"


# ── Fix 3: I001 requires SQL execution sink in file ───────────────────────────

def test_frontend_fetch_no_sql_sink_no_i001():
    """Fix 3: frontend file with fetch() template literal — no SQL sink — must not fire I001."""
    code = '''
async function deleteTodo(id) {
  const resp = await fetch(`/todos/${id}`, { method: 'DELETE' })
  return resp.json()
}
'''
    findings = run(code, language='javascript', file_path='src/api.ts')
    i001 = [f for f in findings if f['rule_id'] == 'PRBL-I001']
    assert not i001, "I001 must not fire in a file with no SQL execution sink"


def test_python_cursor_execute_still_fires():
    """Fix 3: Python file with cursor.execute still fires I001."""
    code = '''
import sqlite3
conn = sqlite3.connect('db.sqlite3')
cur = conn.cursor()
def get_user(user_id):
    cur.execute(f"SELECT * FROM users WHERE id={user_id}")
'''
    findings = run(code, language='python', file_path='app.py')
    assert any(f['rule_id'] == 'PRBL-I001' for f in findings), \
        "I001 must still fire when a SQL execution sink is present"
