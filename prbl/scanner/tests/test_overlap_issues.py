"""
Tests for the five rule-overlap issues investigated from the RULES.md documentation review.

Issue 1: OWASP category inconsistency — A05 vs A03 in RULES.md summary table (doc-only fix).
Issue 2: `mongoose` in I001's SQL context signal list — REAL, fixed.
Issue 3: `$where` triggering I001 as a false SQL injection — NOT present; confirmed I001 does not fire.
Issue 4: C001/C002 session-secret double-fire — NOT present; the two rules fire on mutually exclusive patterns.
Issue 5: I002 missing `.exec` negative lookbehind — NOT present; lookbehind already in place.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from prbl.scanner.rules import (
    check_injection,
    check_nosql_injection,
    check_hardcoded_credentials,
    check_session_secret,
    run_all_rules,
    _OWASP,
)


# ── Issue 1: OWASP category values in the _OWASP lookup table ────────────────

class TestIssue1OWASPCategories:
    """OWASP lookup table must consistently report A05 for all injection rules."""

    def test_i001_owasp_is_a05(self):
        _, category, rank = _OWASP["PRBL-I001"]
        assert category == "A05 — Injection", f"Expected A05, got {category!r}"
        assert rank == 5

    def test_i002_owasp_is_a05(self):
        _, category, rank = _OWASP["PRBL-I002"]
        assert category == "A05 — Injection", f"Expected A05, got {category!r}"
        assert rank == 5

    def test_i003_owasp_is_a05(self):
        _, category, rank = _OWASP["PRBL-I003"]
        assert category == "A05 — Injection", f"Expected A05, got {category!r}"
        assert rank == 5

    def test_i004_owasp_is_a05(self):
        _, category, rank = _OWASP["PRBL-I004"]
        assert category == "A05 — Injection", f"Expected A05, got {category!r}"
        assert rank == 5

    def test_owasp_category_propagates_to_rule_match(self):
        """RuleMatch objects carry the correct OWASP category from the lookup."""
        lines = [
            "function getUser(userId) {",
            "  const query = \"SELECT * FROM users WHERE id = \" + userId",
            "  db.query(query)",
            "}",
        ]
        findings = check_injection(lines, "javascript")
        i001 = [f for f in findings if f.rule_id == "PRBL-I001"]
        assert i001, "Expected PRBL-I001 to fire on SQL concatenation"
        assert i001[0].owasp_category == "A05 — Injection"
        assert i001[0].owasp_rank == 5


# ── Issue 2: mongoose must NOT be an I001 SQL context signal ─────────────────

class TestIssue2MongooseNotSQLContext:
    """
    mongoose is a MongoDB/NoSQL driver. Its presence near a template literal should
    NOT cause PRBL-I001 to fire; it should only influence PRBL-I004.
    """

    def test_mongoose_alone_does_not_trigger_i001(self):
        """
        A mongoose import must not act as the SQL context signal that tips I001 over.
        Use a non-SQL variable name so that `mongoose` is the only potential context signal.
        Before the fix, mongoose in _SQL_CONTEXT_SIGNALS caused I001 to fire here.
        """
        lines = [
            "const mongoose = require('mongoose')",
            "function lookupUser(userId) {",
            "  const filter = 'name_' + userId",
            "  return User.find(filter)",
            "}",
        ]
        findings = check_injection(lines, "javascript")
        i001 = [f for f in findings if f.rule_id == "PRBL-I001"]
        assert not i001, (
            "PRBL-I001 must not fire when the only ORM/driver context is mongoose "
            "(a NoSQL driver). Got: " + str([(f.rule_id, f.line) for f in i001])
        )

    def test_mongoose_with_nosql_injection_fires_i004_not_i001(self):
        """A genuine NoSQL injection pattern with mongoose fires I004, not I001."""
        lines = [
            "const mongoose = require('mongoose')",
            "function findUser(req) {",
            "  return User.find(req.body)",
            "}",
        ]
        i1 = check_injection(lines, "javascript")
        i4 = check_nosql_injection(lines, "javascript")
        i001 = [f for f in i1 if f.rule_id == "PRBL-I001"]
        i004 = [f for f in i4 if f.rule_id == "PRBL-I004"]
        assert not i001, "PRBL-I001 must not fire on mongoose/NoSQL patterns"
        assert i004, "PRBL-I004 must fire on User.find(req.body)"

    def test_sql_driver_still_triggers_i001(self):
        """Removing mongoose must not break I001 when a real SQL driver is present."""
        lines = [
            "const mysql = require('mysql')",
            "function getUser(userId) {",
            "  const q = \"SELECT * FROM users WHERE id = '\" + userId + \"'\"",
            "  db.query(q)",
            "}",
        ]
        findings = check_injection(lines, "javascript")
        i001 = [f for f in findings if f.rule_id == "PRBL-I001"]
        assert i001, "PRBL-I001 must still fire when a SQL driver (mysql) is the context signal"

    def test_sequelize_still_triggers_i001(self):
        """sequelize (SQL ORM) remains a valid SQL context signal."""
        lines = [
            "const { sequelize } = require('./db')",
            "function getUser(userId) {",
            "  const q = \"SELECT * FROM users WHERE id = '\" + userId + \"'\"",
            "  sequelize.query(q)",
            "}",
        ]
        findings = check_injection(lines, "javascript")
        i001 = [f for f in findings if f.rule_id == "PRBL-I001"]
        assert i001, "PRBL-I001 must fire with sequelize as SQL context signal"


# ── Issue 3: $where must not trigger I001 ────────────────────────────────────

class TestIssue3DollarWhere:
    """
    $where is a MongoDB operator. A line using $where string concatenation is a
    NoSQL injection pattern (I004), not a SQL injection pattern (I001).
    """

    def test_dollar_where_does_not_fire_i001(self):
        """$where concatenation must not be flagged as SQL injection."""
        lines = [
            "function findUser(name) {",
            "  collection.find({ $where: \"this.name == '\" + name + \"'\" })",
            "}",
        ]
        findings = check_injection(lines, "javascript")
        i001 = [f for f in findings if f.rule_id == "PRBL-I001"]
        assert not i001, (
            "PRBL-I001 must not fire on $where (MongoDB operator). "
            "Got: " + str([(f.rule_id, f.line) for f in i001])
        )

    def test_dollar_where_fires_i004(self):
        """$where string concatenation with user input must fire I004."""
        lines = [
            "function findUser(name) {",
            "  collection.find({ $where: \"this.name == '\" + name + \"'\" })",
            "}",
        ]
        findings = check_nosql_injection(lines, "javascript")
        i004 = [f for f in findings if f.rule_id == "PRBL-I004"]
        assert i004, "PRBL-I004 must fire on $where string concatenation"

    def test_dollar_where_template_does_not_fire_i001(self):
        """$where with template literal must not fire I001."""
        lines = [
            "function findUser(id) {",
            "  collection.find({ $where: `this.id == ${id}` })",
            "}",
        ]
        findings = check_injection(lines, "javascript")
        i001 = [f for f in findings if f.rule_id == "PRBL-I001"]
        assert not i001, "Template-literal $where must not fire PRBL-I001"


# ── Issue 4: C001 / C002 double-fire on session fallback ─────────────────────

class TestIssue4SessionSecretNoDoubleFire:
    """
    session({ secret: process.env.SESSION_SECRET || 'fallback' }) should produce
    exactly ONE finding (C001 for the fallback), not two.

    C002 is correctly suppressed because _CRED_SAFE_CONTEXT matches process.env.
    C001 is correctly raised via the fallback-secret sub-pattern.
    """

    def test_fallback_session_secret_fires_only_c001(self):
        lines = [
            "const session = require('express-session')",
            "app.use(session({ secret: process.env.SESSION_SECRET || 'fallback-secret' }))",
        ]
        c1 = check_hardcoded_credentials(lines)
        c2 = check_session_secret(lines, "javascript")
        assert len(c1) == 1 and c1[0].rule_id == "PRBL-C001", (
            f"Expected exactly 1 C001 finding, got: {[(f.rule_id, f.title) for f in c1]}"
        )
        assert not c2, (
            f"C002 must not fire on a process.env fallback line, got: {[(f.rule_id, f.title) for f in c2]}"
        )

    def test_hardcoded_session_secret_fires_only_c002(self):
        """A fully hardcoded session secret (no env var) fires only C002."""
        lines = [
            "const session = require('express-session')",
            "app.use(session({ secret: 'fully-hardcoded-secret' }))",
        ]
        all_findings = run_all_rules("\n".join(lines), "javascript", "app.js")
        c001 = [f for f in all_findings if f.rule_id == "PRBL-C001"]
        c002 = [f for f in all_findings if f.rule_id == "PRBL-C002"]
        assert not c001, f"C001 must not fire on fully hardcoded (no env fallback) session secret; got {c001}"
        assert c002, "C002 must fire on hardcoded session secret"

    def test_no_double_fire_from_run_all_rules(self):
        """run_all_rules must not produce duplicate findings for the fallback pattern."""
        code = "\n".join([
            "const session = require('express-session')",
            "app.use(session({ secret: process.env.SESSION_SECRET || 'fallback-secret' }))",
        ])
        findings = run_all_rules(code, "javascript", "app.js")
        rule_ids = [f.rule_id for f in findings]
        assert rule_ids.count("PRBL-C001") <= 1, "PRBL-C001 must not fire more than once per line"
        assert rule_ids.count("PRBL-C002") == 0, "PRBL-C002 must not fire when process.env is used"


# ── Issue 5: I002 must not flag RegExp.exec() ────────────────────────────────

class TestIssue5RegExpExecFalsePositive:
    """
    someRegex.exec(userInput) is JS RegExp.exec() — completely safe.
    The negative lookbehind for '.' in the exec pattern must exclude this.
    """

    def test_regex_exec_does_not_fire_i002(self):
        lines = [
            "function process(userInput) {",
            "  const match = someRegex.exec(userInput)",
            "  return match",
            "}",
        ]
        findings = check_injection(lines, "javascript")
        i002 = [f for f in findings if f.rule_id == "PRBL-I002"]
        assert not i002, (
            "PRBL-I002 must not fire on someRegex.exec() — this is RegExp.exec, not shell exec. "
            "Got: " + str([(f.rule_id, f.line) for f in i002])
        )

    def test_bare_exec_with_user_input_fires_i002(self):
        """Bare exec() with string concatenation and user input must fire I002."""
        lines = [
            "function run(userInput) {",
            "  exec('ls ' + userInput)",
            "}",
        ]
        findings = check_injection(lines, "javascript")
        i002 = [f for f in findings if f.rule_id == "PRBL-I002"]
        assert i002, "PRBL-I002 must fire on bare exec('cmd' + userInput)"

    def test_method_exec_variants_do_not_fire_i002(self):
        """Other .exec() method calls must not fire I002."""
        cases = [
            "  db.exec(userInput)",
            "  session.exec(userInput)",
            "  stmt.exec(userInput)",
            "  /pattern/.exec(userInput)",
        ]
        for case in cases:
            lines = [
                "function process(userInput) {",
                case,
                "}",
            ]
            findings = check_injection(lines, "javascript")
            i002 = [f for f in findings if f.rule_id == "PRBL-I002"]
            assert not i002, (
                f"PRBL-I002 must not fire on method .exec() call: {case!r}. "
                f"Got: {[(f.rule_id, f.line) for f in i002]}"
            )
