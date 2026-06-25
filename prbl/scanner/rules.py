# RULE VALIDATION REQUIREMENT
# Every new rule added to this scanner must pass:
# 1. A synthetic test suite (minimum 10 cases — true positives and false positives)
# 2. A batch stress test against minimum 20 real codebases
# 3. False positive rate confirmed under 10% on human-written code
# 4. Validated against at least one enterprise-scale codebase (1000+ files)
# No new rule ships without completing all four steps.

"""
Static pattern rules for the five Phase 2 vulnerability classes.
All rules are regex-based — no network calls, runs fully offline.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class RuleMatch:
    rule_id: str
    vuln_class: str
    line_number: int
    line: str
    title: str
    detail: str
    fix: str
    severity: str        # "high" | "medium" | "low"
    cwe: str = ""        # e.g. "CWE-798"
    owasp_category: str = ""  # e.g. "A07 — Authentication Failures"
    owasp_rank: int = 0  # 1–10


# ── CWE / OWASP constants per rule ───────────────────────────────────────────

_OWASP: dict[str, tuple[str, str, int]] = {
    # rule_id → (cwe, owasp_category, owasp_rank)
    "PRBL-C001": ("CWE-798",    "A07 — Authentication Failures", 7),
    "PRBL-R001": ("CWE-338",    "A02 — Cryptographic Failures",  2),
    "PRBL-I001": ("CWE-89",     "A05 — Injection",               5),
    "PRBL-I002": ("CWE-78",     "A05 — Injection",               5),
    "PRBL-I003": ("CWE-94/95",  "A05 — Injection",               5),
    "PRBL-A001": ("CWE-862",    "A01 — Broken Access Control",   1),
    "PRBL-P001": ("Emerging — no CWE", "A03 — Supply Chain Failures", 3),
    "PRBL-I004": ("CWE-943",    "A05 — Injection",               5),
    "PRBL-C002": ("CWE-798",    "A07 — Authentication Failures", 7),
    "PRBL-T001": ("CWE-22",     "A01 — Broken Access Control",   1),
    "PRBL-R002": ("CWE-208",    "A02 — Cryptographic Failures",  2),
    "PRBL-A002": ("CWE-347",    "A07 — Authentication Failures", 7),
    "PRBL-C003": ("CWE-295",    "A02 — Cryptographic Failures",  2),
    "PRBL-R003": ("CWE-345",    "A02 — Cryptographic Failures",  2),
    "PRBL-I005": ("CWE-1321",   "A03 — Injection",               3),
}


def _match(rule_id: str, **kwargs) -> RuleMatch:
    """Construct a RuleMatch with CWE/OWASP fields auto-populated."""
    cwe, owasp_category, owasp_rank = _OWASP.get(rule_id, ("", "", 0))
    return RuleMatch(rule_id=rule_id, cwe=cwe, owasp_category=owasp_category,
                     owasp_rank=owasp_rank, **kwargs)


# ── 1. HARDCODED CREDENTIALS ──────────────────────────────────────────────────

_CRED_PATTERNS = [
    # Generic assignment patterns
    (r'(?i)(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token|private_key)\s*=\s*["\'](?!.*\$\{)(?!.*process\.env)(?!.*os\.environ)(?!.*getenv).{8,}["\']',
     "Hardcoded secret assigned to a variable"),
    # Stripe
    (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe live secret key"),
    (r'rk_live_[0-9a-zA-Z]{24,}', "Stripe restricted key"),
    # AWS
    (r'AKIA[0-9A-Z]{16}', "AWS access key ID"),
    (r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}["\']', "AWS secret access key"),
    # GitHub
    (r'ghp_[0-9a-zA-Z]{36}', "GitHub personal access token"),
    (r'github_pat_[0-9a-zA-Z_]{82}', "GitHub fine-grained PAT"),
    # Generic high-entropy strings in key/token vars
    (r'(?i)(token|key|secret)\s*[=:]\s*["\'][0-9a-f]{32,}["\']', "Hardcoded hex token/key"),
    # JWT-shaped strings
    (r'eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}', "Hardcoded JWT"),
    # Dict/object literal: {"password": "value"} or { secret: "value" }
    # Catches Python dict and JS object literal syntax where a credential key maps to a literal string.
    # Use [^"']{8,} — NOT .{8,} — to avoid matching across quote boundaries into comments.
    (r'(?i)["\']?(?:password|passwd|pwd|secret|api_key|apikey|auth_token|access_token|private_key)["\']?'
     r'\s*:\s*["\'](?!\$\{)(?!.*os\.environ)(?!.*process\.env)[^"\']{8,}["\']',
     "Hardcoded credential in dict/object literal"),
]

# Canonical jwt.io example JWT — the most widely copy-pasted JWT in existence.
# Header decodes to {"alg":"HS256","typ":"JWT"}, payload to
# {"sub":"1234567890","name":"John Doe","iat":1516239022}. Appears in every
# tutorial, Swagger @ApiProperty example, and NestJS DTO. Never a real credential.
_JWTIO_EXAMPLE_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"

# Swagger/OpenAPI documentation context — JWTs in example: fields are not live credentials
_SWAGGER_EXAMPLE_CONTEXT = re.compile(
    r'(?i)(example\s*[:=]|@ApiProperty|ApiProperty|@ApiBody|swagger|openapi|\.example\s)',
)

# Safe context — if any of these appear anywhere in the line it's not a real secret
# (env var lookups, template syntax, vault references)
_CRED_SAFE_CONTEXT = re.compile(
    r'(process\.env|os\.environ|getenv|config\[|secrets\.|vault\.|<|>|\$\{)',
    re.IGNORECASE,
)

# Public search API key context — Algolia and similar search services use a
# "search-only" API key that is intentionally exposed in client-side code.
# The key is read-only and scoped to a specific index; it cannot modify data.
_CRED_PUBLIC_SEARCH_CONTEXT = re.compile(
    r'(?i)(algolia\s*[:{]|appId\s*[=:]|indexName\s*[=:]|docsearch|search-only|searchOnlyApiKey)',
)

# Safe variable name — if the *left side* of the assignment contains placeholder
# language the value is intentionally fake. Check only the variable name, not the
# value — "AKIAIOSFODNN7EXAMPLE" contains "example" but it's a real key format.
# Also matches when the value itself (right side) contains placeholder/dummy language:
#   access_token: "TOKEN_PLACEHOLDER_FOR_DELEGATION_CREDENTIAL"
_CRED_SAFE_VARNAME = re.compile(
    r'(?i)(^[^=:]*?(placeholder|example[_\s]|your[_-]|dummy|fake|sample|test[_-]key|demo)'
    r'|["\'][^"\']*(?:placeholder|_dummy|_fake|_example)[^"\']*["\'])',
)

# UI validation message exclusion — applied to the matched string *value*.
# If the string content looks like a user-facing error message it is not a secret.
_CRED_VALIDATION_MSG = re.compile(
    r'(?i)('
    r'is required|is invalid|must be|cannot be|please enter|is incorrect|'
    r'does not match|do not match|is too short|is too long|is not valid|already exists|'
    r'not found|is empty|enter your|your password|confirm password|'
    r'new password|old password|current password'
    r')',
)

# Extract the string value from a matched line (content between quotes)
_STRING_VALUE = re.compile(r'["\']([^"\']{4,})["\']')

# Well-known placeholder credential strings used in dev config and boilerplate.
# These are intentionally fake values — semantically identical to 'placeholder'
# or 'your-secret-here'. If the extracted string value matches, suppress the finding.
_CRED_PLACEHOLDER_VALUES = re.compile(
    r'^(?:password|passwd|secret|changeme|change.?me|yourpassword|your.password|'
    r'db.?password|admin|letmein|qwerty|123456|test|example|foobar|'
    r'supersecret|mysecret|mypassword|pass|p@ss|p@ssw0rd|'
    r'enter.?password|insert.?password|add.?password|'
    r'<password>|<secret>|\[password\]|\[secret\])$',
    re.IGNORECASE,
)

# Documentation/example finding format — "path/file.ext:LINE — description" is how
# security blog posts, marketing pages, and changelogs describe a vulnerability
# example in prose. It's not a real assignment in this file; it's text *about* one
# elsewhere (often in a different language than the file being scanned, e.g. a
# Python filename referenced from a .tsx marketing page). Real credential
# assignments don't carry a "file:line —" prefix.
_CRED_DOC_EXAMPLE_FORMAT = re.compile(
    r'[\w./-]+\.\w{1,10}:\d+\s*[—–\-]{1,2}\s',
)

# Bcrypt hash pattern — already-hashed passwords in seeders/fixtures are not
# plaintext secrets. A bcrypt hash cannot be reversed to recover the original.
_BCRYPT_HASH = re.compile(r'^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$')

# Suppress C001/C002 when the credential VALUE is an all-uppercase env-var name.
# These are config schema labels, not real secrets:
#   apiKey: "VLLM_API_KEY"  /  secret: "JWT_SECRET"  /  token: "GITHUB_TOKEN"
# Must be entirely uppercase letters, digits, and underscores (no lowercase).
_ENV_VAR_NAME_VALUE = re.compile(r'^[A-Z][A-Z0-9_]{2,}$')

# Suppress C001/C002 when the matched line is a test assertion verifying that a
# credential was REDACTED — not a real leaked credential.
# Patterns: expect(x).not.toContain("ghp_..."), assert "fake" not in result, etc.
_CRED_REDACTION_TEST = re.compile(
    r'(?:\.not\.toContain\s*\(|\.not\.toEqual\s*\(|assert\s+\S+\s+not\s+in\b|'
    r'assertNotIn\s*\(|\.not\.toMatch\s*\()',
    re.IGNORECASE,
)

# ── Value entropy suppressors (applied to the VALUE side only) ────────────────

def _is_non_ascii(value: str) -> bool:
    """Return True if the value contains any non-ASCII characters (Unicode > 127).
    Non-ASCII values are i18n labels, translated strings, or UI text — never secrets."""
    return any(ord(c) > 127 for c in value)


# Fix 1: UI label key-name hints — keys like `verifyPasswordLabel`, `confirmButtonText`,
# `errorMessage`, `modalTitle` are display strings, not credentials, regardless of
# the value. Checked against the KEY (left of `:`/`=`), not the value.
_UI_LABEL_KEY_HINTS = re.compile(
    r'(?i)\b\w*(?:label|text|title|placeholder|button|message|display|caption)\w*\b'
)


def _looks_like_plain_english_label(value: str) -> bool:
    """True if `value` reads like UI copy, not a secret: ASCII only, no digits,
    and no high-entropy mixed-case token. A real secret like 'aB3xZ9Lm' mixes
    case unpredictably within a single word; English phrases like 'Verify password'
    do not — each word is either all-lowercase, all-uppercase, or Capitalized."""
    if not value or _is_non_ascii(value):
        return False
    if any(c.isdigit() for c in value):
        return False
    for word in value.split():
        cleaned = ''.join(c for c in word if c.isalpha())
        if not cleaned:
            continue
        if cleaned not in (cleaned.lower(), cleaned.upper(), cleaned.capitalize()):
            return False  # erratic mixed case — entropy signal, not English text
    return True

# Known status/configuration indicator words — clearly not secrets.
# Explicit allowlist rather than a broad regex to avoid suppressing real credential words
# like 'supersecret', 'password', 'letmein', etc. (those are caught by _CRED_PLACEHOLDER_VALUES).
_STATUS_WORDS = frozenset({
    'configured', 'enabled', 'disabled', 'active', 'inactive',
    'success', 'pending', 'connected', 'disconnected', 'ready',
    'running', 'stopped', 'started', 'loading', 'loaded',
    'valid', 'invalid', 'verified', 'unverified', 'authorized',
    'unauthorized', 'authenticated', 'unauthenticated',
    'available', 'unavailable', 'online', 'offline', 'healthy',
    'unhealthy', 'idle', 'busy', 'paused', 'completed', 'failed',
    'initialized', 'uninitialized', 'deprecated', 'experimental',
})

# ── Fallback secret patterns ──────────────────────────────────────────────────
# Detects: process.env.X || 'literal'  /  process.env.X ?? 'literal'
#          os.environ.get('X', 'literal')  /  os.getenv('X', 'literal')
# These are the most common AI-generated credential mistake: a working fallback
# value that becomes the production secret if the env var is never set.

# Env-var names that signal the value is a credential — used to filter fallback
# findings so POSTGRES_USER / LOG_LEVEL / DB_HOST don't trigger PRBL-C001.
_CRED_VAR_NAME = re.compile(
    r'(?i)(password|passwd|pwd|secret|api_key|apikey|private_key|'
    r'auth_token|access_token|jwt_secret|signing_key|encryption_key|'
    r'client_secret|app_secret|master_key|webhook_secret)',
)

_FALLBACK_JS = re.compile(
    r'process\.env\.\w+\s*(?:\|\||\?\?)\s*["\']([^"\']+)["\']',
)
_FALLBACK_PY = re.compile(
    r'os\.(?:environ\.get|getenv)\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']',
)
# Python: os.environ.get('KEY') or 'literal'  /  os.getenv('KEY') or 'literal'
# Also handles the optional None sentinel: os.environ.get('KEY', None) or 'literal'
_FALLBACK_PY_OR = re.compile(
    r'os\.(?:environ\.get|getenv)\s*\(\s*["\']([^"\']+)["\'](?:\s*,\s*None)?\s*\)\s*or\s*["\']([^"\']+)["\']'
)
# JS/TS: const { JWT_SECRET = 'default' } = process.env  (single-variable only)
_FALLBACK_JS_DESTRUCT = re.compile(
    r'(?:const|let|var)\s*\{\s*(\w+)\s*=\s*["\']([^"\']+)["\']\s*\}\s*=\s*process\.env'
)

# Values that are NOT credentials: empty, None/null/undefined, booleans, pure numbers, URLs
_FALLBACK_SAFE_VALUE = re.compile(
    r'^(?:'
    r'|None|null|undefined|true|false|True|False'           # empty or boolean
    r'|\d+'                                                  # pure integer (port numbers etc.)
    r'|\d+\.\d+'                                             # float
    r'|https?://.+'                                          # any http/https URL
    r'|localhost(?::\d+)?(?:/.*)?'                           # localhost with optional port/path
    r'|127\.0\.0\.1(?::\d+)?(?:/.*)?'                       # loopback IP with optional port/path
    r'|0\.0\.0\.0(?::\d+)?'                                  # bind-all address
    # JWT / crypto algorithm names — not secrets, just configuration
    r'|HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512'
    r'|sha256|sha512|sha1|md5|bcrypt|argon2|pbkdf2'
    # Database connection strings with no embedded credentials
    r'|sqlite:///.*'                                         # SQLite file/in-memory paths
    r'|sqlite\+aiosqlite:///.*'
    # API path prefixes and routing config — not secrets
    r'|/[a-z0-9/_-]+'                                       # URL path (starts with /)
    # Log level names
    r'|DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL'
    # Wildcard / open values — explicit developer choice
    r'|\*'
    # Common non-secret defaults
    r'|utf-8|utf8|json|text/html|application/json'
    r'|nano|vim|vi|emacs|code|notepad'                       # editor defaults
    # Token/session time-to-live durations — never a secret value
    r'|\d+[smhd]'                                            # 15m, 7d, 1h, 30s, 24h, etc.
    # Placeholder/instructional fallback values — developer knows this must be changed
    r'|your-.+'                                              # your-secret-key, your-secret-here
    r'|change.?me|change.?in.?prod|change.?this|replace.?me|replace.?with'
    r'|todo.?change|todo.?replace|fixme'
    r')$',
    re.IGNORECASE,
)


def check_hardcoded_credentials(lines: list[str]) -> list[RuleMatch]:
    findings = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(('#', '//', '*', '"""', "'''")):
            continue
        # Documentation/marketing example — "jwt.js:3 — process.env.JWT_SECRET || 'x'"
        # describes a finding in prose, not a real fallback in this file. Must run
        # before the fallback check below, since that check intentionally bypasses
        # the later _CRED_SAFE_CONTEXT guard.
        if _CRED_DOC_EXAMPLE_FORMAT.search(line):
            continue

        # ── Fallback secret check ─────────────────────────────────────────────
        # Must run BEFORE the _CRED_SAFE_CONTEXT guard, because fallback lines
        # intentionally contain process.env / os.environ and would otherwise be
        # whitelisted. These patterns are unambiguous enough not to need the guard.
        fallback_found = False
        for regex in (_FALLBACK_JS, _FALLBACK_PY, _FALLBACK_PY_OR, _FALLBACK_JS_DESTRUCT):
            m = regex.search(line)
            if not m:
                continue
            # _FALLBACK_PY / _FALLBACK_PY_OR: group 1 = env var name, group 2 = fallback value
            # _FALLBACK_JS_DESTRUCT: group 1 = var name (check with _CRED_VAR_NAME), group 2 = fallback value
            # _FALLBACK_JS: group 1 = fallback value only — check full line for credential var name
            if regex in (_FALLBACK_PY, _FALLBACK_PY_OR):
                env_var_name = m.group(1)
                fallback_value = m.group(2).strip()
                # Only flag if the env var name looks like a credential
                if not _CRED_VAR_NAME.search(env_var_name):
                    continue
            elif regex is _FALLBACK_JS_DESTRUCT:
                env_var_name = m.group(1)
                fallback_value = m.group(2).strip()
                if not _CRED_VAR_NAME.search(env_var_name):
                    continue
            else:
                fallback_value = m.group(1).strip()
                # For JS, check the full expression for credential var names
                if not _CRED_VAR_NAME.search(line):
                    continue
            if _FALLBACK_SAFE_VALUE.match(fallback_value):
                continue  # empty / boolean / numeric / algorithm — not a secret
            # Suppress if the fallback value is non-ASCII or a single lowercase status word
            if _is_non_ascii(fallback_value) or fallback_value.lower() in _STATUS_WORDS:
                continue
            findings.append(_match(
                rule_id="PRBL-C001",
                vuln_class="hardcoded_credentials",
                line_number=i,
                line=stripped,
                title="Hardcoded fallback secret in env-var lookup",
                detail=(
                    f"The fallback value '{fallback_value}' becomes the live secret for every "
                    "deployment where the environment variable is not explicitly set. "
                    "AI-generated code often adds these fallbacks so the app works out of the box — "
                    "developers see it working locally and ship it without removing the default. "
                    "Anyone who clones and deploys this repo without configuring secrets gets "
                    "a known, predictable credential in production."
                ),
                fix=(
                    "Remove the fallback literal entirely. If the variable is required, raise an "
                    "error at startup if it is missing: "
                    "`const secret = process.env.SECRET_KEY; if (!secret) throw new Error('SECRET_KEY not set');`"
                ),
                severity="medium",
            ))
            fallback_found = True
            break  # one finding per line

        if fallback_found:
            continue  # already flagged — skip raw-credential scan for this line

        # ── Raw hardcoded credential scan ─────────────────────────────────────
        if _CRED_SAFE_CONTEXT.search(line):
            continue
        if _CRED_SAFE_VARNAME.search(line):
            continue
        # Swagger/OpenAPI example context — JWT in example: or @ApiProperty is documentation.
        # Also check up to 5 lines above in case the JWT is a multi-line continuation:
        #   example: {
        #     access_token:
        #       'eyJ...'  ← same-line check would miss this
        if _SWAGGER_EXAMPLE_CONTEXT.search(line):
            continue
        swagger_window_start = max(0, i - 6)
        swagger_window = '\n'.join(lines[swagger_window_start:i])
        if _SWAGGER_EXAMPLE_CONTEXT.search(swagger_window):
            continue
        # Canonical jwt.io example token — not a real credential
        if _JWTIO_EXAMPLE_HEADER in line:
            continue
        # Public search-only API keys (Algolia, DocSearch) are intentionally exposed
        # in client-side code — they are scoped to read-only search and cannot modify data.
        search_window = '\n'.join(lines[max(0, i - 5):min(len(lines), i + 2)])
        if _CRED_PUBLIC_SEARCH_CONTEXT.search(search_window):
            continue
        # Enum class members — variable names containing "secret" as part of an enum
        # value label (VIEW_ENDPOINT_SECRET = "ViewEndpointSecret") are capability
        # labels, not actual secrets. Check 20 lines above for enum class declaration.
        # Matches Python (class Foo(Enum)) and TypeScript (export enum Foo).
        enum_window = '\n'.join(lines[max(0, i - 20):i])
        if re.search(r'(?:class\s+\w+.*\bEnum\b|\benum\s+\w+\s*\{)', enum_window):
            continue
        for pattern, description in _CRED_PATTERNS:
            if re.search(pattern, line):
                # Check each string value on the line — if it looks like a UI
                # validation message rather than a secret, skip it.
                string_values = _STRING_VALUE.findall(line)
                if any(_CRED_VALIDATION_MSG.search(v) for v in string_values):
                    break
                # Suppress if the matched credential value is a well-known placeholder.
                # Extract the value from the match itself (the string after the colon/equals)
                # to avoid checking the key name (e.g. "password" in {"password": "hunter2"}).
                m_obj = re.search(pattern, line)
                cred_value = None
                if m_obj:
                    # The credential value is the last string literal in the matched span
                    cred_val_m = _STRING_VALUE.findall(m_obj.group(0))
                    if cred_val_m:
                        cred_value = cred_val_m[-1]
                if cred_value and _CRED_PLACEHOLDER_VALUES.match(cred_value):
                    break
                # Suppress C001/C002 when the value has obviously-too-low entropy:
                # non-ASCII chars → i18n label; single lowercase word → status indicator
                if cred_value and (_is_non_ascii(cred_value) or cred_value.lower() in _STATUS_WORDS):
                    break
                # Fix 1: UI label suppression. A multi-word plain-English value
                # (e.g. "Verify password") is UI copy, not a secret, regardless of
                # the key name. A single-word value only suppresses if the key
                # name itself signals UI copy (label/text/title/button/etc.) —
                # this avoids suppressing real single-word secrets like "supersecret".
                if cred_value and _looks_like_plain_english_label(cred_value):
                    key_part = line.split(':', 1)[0] if ':' in line else line.split('=', 1)[0]
                    if ' ' in cred_value or _UI_LABEL_KEY_HINTS.search(key_part):
                        break
                # Suppress if the value is a bcrypt hash — already-hashed passwords
                # in seeders/fixtures are not plaintext secrets.
                if cred_value and _BCRYPT_HASH.match(cred_value):
                    break
                # Suppress C001/C002 when the value is an all-uppercase env-var name.
                # e.g. apiKey: "VLLM_API_KEY" — a config schema label, not a real secret.
                if cred_value and _ENV_VAR_NAME_VALUE.match(cred_value):
                    break
                # Suppress C001/C002 when the line is a test assertion verifying redaction.
                # e.g. expect(result).not.toContain("ghp_...") — checking the redactor works.
                if _CRED_REDACTION_TEST.search(line):
                    break
                # Suppress C001 for session/cookie secrets — C002 covers these with
                # better context and messaging. Avoids double-firing on:
                #   app.use(session({ secret: 'hardcoded-value' }))
                if description == "Hardcoded credential in dict/object literal":
                    window_c002 = '\n'.join(lines[max(0, i - 6):min(len(lines), i + 2)])
                    if _SESSION_CONTEXT.search(window_c002):
                        break
                findings.append(_match(
                    rule_id="PRBL-C001",
                    vuln_class="hardcoded_credentials",
                    line_number=i,
                    line=stripped,
                    title=f"Hardcoded credential: {description}",
                    detail=(
                        "A secret is written directly into source code. Git history is permanent — "
                        "even if deleted in a later commit, the credential is recoverable. "
                        "Automated bots scan GitHub continuously; average time to exploit a leaked "
                        "AWS key is under 4 minutes."
                    ),
                    fix="Move this value to an environment variable or secrets manager (e.g. AWS Secrets Manager, Vault, Doppler).",
                    severity="high",
                ))
                break

    return findings


# ── 2. WEAK RANDOMNESS ────────────────────────────────────────────────────────

_WEAK_RANDOM_PATTERNS = [
    # JavaScript / TypeScript
    (r'Math\.random\(\)', "Math.random()"),
    # UUID v1 — time-based, includes MAC address; predictable and leaks host identity.
    # v4 (random) is the correct choice for tokens and session IDs.
    (r'(?i)\buuid\.v1\s*\(\)', "uuid.v1() (time-based UUID)"),
    (r"(?i)['\"]v1['\"].*uuidv?1|uuidv?1.*['\"]v1['\"]", "uuidv1() (time-based UUID)"),
    (r'\buuidv1\s*\(\)', "uuidv1() (time-based UUID)"),
    # Python
    (r'\brandom\.random\(\)', "random.random()"),
    (r'\brandom\.randint\(', "random.randint()"),
    (r'\brandom\.choice\(', "random.choice()"),
    (r'\brandom\.uniform\(', "random.uniform()"),
    (r'\brandom\.shuffle\(', "random.shuffle()"),
    (r'\brandom\.sample\(', "random.sample()"),
]

# Fix 3: R001 security-context gate, rewritten to check the *receiving variable
# name* rather than scanning a loose multi-line window for security keywords.
# The old window-based check over-fired: "pin" matched inside "pinned_apps_names"/
# "pin_count" (UI icon-pinning code) and "session" matched inside "sessionDuration"
# (a workout session length, not an auth session) — the keyword happened to
# appear nearby as a substring even though the call site has nothing to do with
# security. Gating on the assignment target itself eliminates that class of FP.
_R001_FIRE_WORDS = frozenset({
    'token', 'secret', 'password', 'otp', 'code',
    'session', 'auth', 'nonce', 'salt', 'hash',
})

# "key" and "id" alone are too overloaded to fire on bare presence — React
# component keys (componentKey, refreshKey), array/map keys, and analytics/
# tracking IDs (visitorId, anonymousId, formId) are extremely common and not
# security-sensitive. They only count when paired with a qualifying word.
_R001_ID_KEY_QUALIFIERS = frozenset({
    'api', 'auth', 'secret', 'private', 'session',
    'signing', 'encryption', 'access', 'jwt', 'csrf', 'request',
})

# A fire-word can appear in an otherwise non-security compound, e.g.
# "sessionDuration" (workout session length) vs "sessionId" (auth session).
# If a measurement/quantity word is also present, it's a length/count/time
# value, not an identifier or secret — override to suppress regardless of
# which fire-word matched.
_R001_QUANTITY_OVERRIDE = frozenset({
    'duration', 'length', 'time', 'count', 'index', 'hours', 'minutes',
    'seconds', 'days', 'weeks', 'months', 'amount', 'size', 'limit',
    'max', 'min', 'rate', 'percent', 'percentage',
})

# Matches the variable/property name immediately receiving the random() call:
#   const sessionId = ...   /   let token = ...   /   password = ...
#   clientId: Math.random()...   (object-literal property)
_R001_ASSIGN_TARGET = re.compile(
    r'^\s*(?:export\s+)?(?:const|let|var)?\s*([A-Za-z_]\w*)\s*[:=]\s*(?!=)'
)


def _split_identifier_words(name: str) -> list[str]:
    """Split camelCase/PascalCase/snake_case into lowercase sub-words, so
    'sessionId' -> ['session', 'id'] and 'pin_count' -> ['pin', 'count']."""
    spaced = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', name)
    spaced = spaced.replace('_', ' ').replace('-', ' ')
    return [w.lower() for w in spaced.split() if w]


def _is_security_sensitive_target(name: str) -> bool:
    """True only if `name` (a variable or object-literal property) contains a
    security-sensitive word. Default is False — R001 should not fire just
    because an unrelated security word happens to appear somewhere nearby."""
    words = _split_identifier_words(name)
    if any(w in _R001_QUANTITY_OVERRIDE for w in words):
        return False  # measurement/quantity, not an identifier or secret
    if any(w in _R001_FIRE_WORDS for w in words):
        return True
    if ('key' in words or 'id' in words) and any(w in _R001_ID_KEY_QUALIFIERS for w in words):
        return True
    return False

# NOTE: do NOT add bare "sample" here — it collides with random.sample() the function.
# "sample" would silently skip `password = random.sample(chars, 12)` which is a real finding.
# Use compound forms like "sample_data" or "sample_value" if you need to cover demo fixtures.
_WEAK_RANDOM_SAFE_CONTEXT = re.compile(
    r'(?i)(test|spec|mock|sample_data|sample_value|demo|example|game|color|shuffle.*display|animation)',
)


# Crypto availability guard patterns — Math.random() used as fallback when
# crypto API is unavailable (e.g. old browsers). Not a security issue because
# the safe path is taken when the API is present.
_CRYPTO_FALLBACK_PATTERNS = [
    re.compile(r'crypto\.randomUUID\s*\?'),
    re.compile(r'crypto\.getRandomValues\s*\?'),
    re.compile(r'window\.crypto'),
    re.compile(r'self\.crypto'),
    re.compile(r'globalThis\.crypto'),
]

# Variable names used for analytics/tracking IDs — low-entropy IDs for telemetry,
# not for security tokens. Downgrade to LOW instead of HIGH.
_ANALYTICS_VARS = re.compile(
    r'(?i)\b(visitorId|visitor_id|analyticsId|analytics_id|'
    r'trackingId|tracking_id|anonymousId|anonymous_id|'
    r'tempId|temp_id|draftId|draft_id|formId|form_id|instanceId|instance_id)\b'
)

# Draft / temporary context — IDs with no security implication
_DRAFT_TEMP_CONTEXT = re.compile(
    r'(?i)\b(draft|temp|temporary|preview|cache_?bust|cache_?key|idempotency)\b'
)

# useState exclusion for PRBL-R001: Math.random() inside useState() is a
# common React pattern for generating a component key to force remounts.
# This is legitimate UI code, not a security issue.
# We only suppress if the receiving variable name is not security-sensitive.
_USESTATE_RANDOM = re.compile(r'useState\s*\(')
_USESTATE_VAR = re.compile(r'(?:const|let|var)\s+\[(\w+)')


def check_weak_randomness(lines: list[str], language: str) -> list[RuleMatch]:
    findings = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(('#', '//', '*')):
            continue
        if _WEAK_RANDOM_SAFE_CONTEXT.search(line):
            continue
        for pattern, fn_name in _WEAK_RANDOM_PATTERNS:
            if re.search(pattern, line):
                # Exclusion: Math.random() / random.* inside useState() is a React
                # component-key pattern — not security-sensitive unless the state
                # variable itself has a security name (token, secret, password, etc.)
                if _USESTATE_RANDOM.search(line):
                    var_match = _USESTATE_VAR.search(line)
                    var_name = var_match.group(1) if var_match else ''
                    if not _is_security_sensitive_target(var_name):
                        continue  # suppress — React key, not a secret

                # Exclusion: crypto API availability guard — Math.random() used only
                # when window.crypto / globalThis.crypto is unavailable (old browsers).
                window_start = max(0, i - 3)
                window_end = min(len(lines), i + 2)
                window = '\n'.join(lines[window_start:window_end])
                if any(p.search(window) for p in _CRYPTO_FALLBACK_PATTERNS):
                    continue

                # Fix 3: gate on the variable/property actually receiving the
                # random() output, not on loose keyword presence in the window.
                target_match = _R001_ASSIGN_TARGET.search(line)
                target_name = target_match.group(1) if target_match else ''
                if not _is_security_sensitive_target(target_name):
                    continue

                fix_js = "Use crypto.randomBytes(32).toString('hex') or crypto.randomUUID()"
                fix_py = "Use secrets.token_hex(32) or secrets.token_urlsafe(32)"
                fix = fix_py if language == "python" else fix_js

                # Downgrade analytics/tracking IDs and draft/temp context to LOW
                if _ANALYTICS_VARS.search(line) or _DRAFT_TEMP_CONTEXT.search(window):
                    sev = "low"
                    detail = (
                        f"{fn_name} is not cryptographically secure, but this appears to be "
                        "an analytics/tracking identifier where predictability is low-risk. "
                        "Use a cryptographic source if this ID is used for access control or "
                        "deduplication with security implications."
                    )
                else:
                    sev = "high"
                    detail = (
                        f"{fn_name} is not cryptographically secure. Its output is predictable — "
                        "an attacker who observes a few values can reconstruct the internal state "
                        "and predict all future outputs, including tokens and session IDs."
                    )

                findings.append(_match(
                    rule_id="PRBL-R001",
                    vuln_class="weak_randomness",
                    line_number=i,
                    line=stripped,
                    title=f"Weak randomness for security-sensitive value: {fn_name}",
                    detail=detail,
                    fix=fix,
                    severity=sev,
                ))
                break
    return findings


# ── 2b. TIMING-SAFE COMPARISON (PRBL-R002) ────────────────────────────────────

_DIGEST_CALL = re.compile(
    r'(?i)(\.hexdigest\s*\(|\.digest\s*\(|createHmac\s*\(|hmac\.new\s*\(|hashlib\.\w+\s*\()'
)
# HMAC-specific pattern: createHmac / hmac.new are authentication MACs that always
# need timing-safe comparison regardless of whether request taint is visible in the window.
_HMAC_CALL = re.compile(
    r'(?i)(createHmac\s*\(|hmac\.new\s*\(|hmac\.digest\s*\()'
)
_TIMING_SAFE_PRESENT = re.compile(
    r'(?i)(timingSafeEqual|compare_digest|secrets\.compare_digest|hmac\.compare_digest)'
)
_TIMING_UNSAFE_CMP = re.compile(
    r'(?:===|==|!==|!=)'
)
_TIMING_WEBHOOK_VARS_RAW = (
    r'\b(verification_token|webhook_secret|webhook_token|expected_signature|'
    r'computed_signature|x_hub_signature|x_signature|hmac_signature|'
    r'open_verification_token|signature_token|api_signature|request_signature|'
    r'callback_token|hook_secret|hook_token)\b'
)
_TIMING_WEBHOOK_VARS = re.compile(r'(?i)' + _TIMING_WEBHOOK_VARS_RAW)
_TIMING_REQUEST_TAINT = re.compile(
    r'(?i)(req\.(body|headers|query|params)|request\.(args|headers|form|json|values))'
)
_TIMING_STRING_LITERAL = re.compile(
    r"""(?:===|!==|==|!=)\s*["']|["']\s*(?:===|!==|==|!=)"""
)


def check_timing_comparison(lines: list[str], language: str) -> list[RuleMatch]:
    findings = []
    digest_vars: set[str] = set()   # track variable names assigned any digest result
    hmac_vars: set[str] = set()     # subset: variables assigned HMAC-specific results

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(('#', '//', '*')):
            continue

        # Track variables assigned digest/HMAC results
        if _DIGEST_CALL.search(line):
            # Match: var = ..., const/let/var name = ..., or name: type = ...
            assign_m = re.search(r'(?:const|let|var)\s+(\w+)\s*=|^\s*(\w+)\s*=\s*', line)
            if assign_m:
                var_name = assign_m.group(1) or assign_m.group(2)
                if var_name:
                    digest_vars.add(var_name)
                    # Track as HMAC var if:
                    # 1. The line directly calls createHmac/hmac.new (e.g. createHmac(...).update(...).digest(...))
                    # 2. The right side of the assignment uses a previously-tracked HMAC var
                    #    (e.g. const sig = hmacObj.update(payload).digest('hex') where hmacObj is in hmac_vars)
                    is_hmac_assignment = bool(_HMAC_CALL.search(line))
                    if not is_hmac_assignment and hmac_vars:
                        # Check if any tracked hmac var appears on the RHS of this assignment
                        rhs = line[assign_m.end():]
                        for hvar in hmac_vars:
                            if re.search(rf'\b{re.escape(hvar)}\b', rhs):
                                is_hmac_assignment = True
                                break
                    if is_hmac_assignment:
                        hmac_vars.add(var_name)

        # Build 5-line window
        window_start = max(0, i - 3)
        window_end = min(len(lines), i + 3)
        window = '\n'.join(lines[window_start:window_end])

        # Skip if safe comparison is present in window
        if _TIMING_SAFE_PRESENT.search(window):
            continue

        # Skip type guards
        if re.search(r'typeof\s+\w+\s*(?:===|==)', line):
            continue

        # String-literal-only check: a line whose ONLY comparisons involve string literals
        # is a routing/enum check. But if the line ALSO contains webhook var + request taint,
        # there are multiple comparisons — the token comparison is still unsafe.
        line_has_string_literal_cmp = bool(_TIMING_STRING_LITERAL.search(line))

        fired = False

        # Sub-pattern A: digest output compared with === or ==
        # String literal on the same line doesn't suppress — the digest comparison is distinct.
        if _TIMING_UNSAFE_CMP.search(line):
            # Direct: hmac.new(...).hexdigest() == value on same line
            if _DIGEST_CALL.search(line):
                fired = True
            # Indirect: previously-tracked digest var compared.
            # For HMAC vars (createHmac/hmac.new), fire without requiring request taint —
            # HMAC comparisons are always authentication-critical.
            # For non-HMAC digest vars (createHash, hashlib.*), require request taint in
            # window to avoid flagging PKCE/hash-comparison patterns where both sides are
            # derived values with no secret involved (e.g. PKCE codeChallenge comparison).
            elif digest_vars:
                for var in digest_vars:
                    if re.search(rf'\b{re.escape(var)}\b', line) and _TIMING_UNSAFE_CMP.search(line):
                        is_hmac_var = var in hmac_vars
                        has_request_taint_in_window = bool(_TIMING_REQUEST_TAINT.search(window))
                        if is_hmac_var or has_request_taint_in_window:
                            fired = True
                            break

        # Sub-pattern B: webhook/signature token compared with request-derived value
        if not fired and _TIMING_UNSAFE_CMP.search(line):
            has_webhook_var = bool(_TIMING_WEBHOOK_VARS.search(line))
            # Request taint can be on the comparison line or in the 5-line window
            has_request_taint = bool(_TIMING_REQUEST_TAINT.search(line)) or bool(_TIMING_REQUEST_TAINT.search(window))
            if has_webhook_var and has_request_taint:
                # Only suppress if there's a string literal AND no webhook var + request taint
                # combination that survives the literal check (i.e., purely a routing line)
                fired = True

        # If the only trigger was a string-literal comparison with no qualifying webhook/digest context,
        # suppress. Specifically: if line has a string literal cmp and fired only via sub-pattern A
        # without a digest call (which is already not possible above), do nothing extra.
        # The key suppression: if we fired via sub-pattern B but the line ONLY has string literals
        # (no real webhook var or request taint beyond the literal), don't fire.
        # Since we already require webhook_var AND request_taint, the only remaining FP is a line
        # where webhook_secret is compared to a string literal — but that's caught by the
        # string literal guard applied specifically when there's no non-literal operand.
        # Check: if line has string literal cmp and no non-literal comparison with webhook var
        if fired and line_has_string_literal_cmp:
            # Check if the webhook var is directly adjacent to a string literal comparison
            # Pattern: webhook_var === 'literal' or 'literal' === webhook_var
            webhook_vs_literal = re.search(
                r'(?:' + _TIMING_WEBHOOK_VARS_RAW + r')\s*(?:===|!==|==|!=)\s*["\']'
                r'|["\'\s]*(?:===|!==|==|!=)\s*(?:' + _TIMING_WEBHOOK_VARS_RAW + r')',
                line, re.IGNORECASE
            )
            # If webhook var is directly compared to a string literal (and no request taint on line),
            # suppress — it's a feature flag / routing check
            if webhook_vs_literal and not _TIMING_REQUEST_TAINT.search(line):
                fired = False

        if fired:
            fix_py = "Use hmac.compare_digest(a, b) instead of ==. Ensure both values are bytes or both are str."
            fix_js = "Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) instead of ===. Ensure both Buffers are the same length first."
            fix = fix_py if language == 'python' else fix_js
            findings.append(_match(
                rule_id="PRBL-R002",
                vuln_class="timing_comparison",
                line_number=i,
                line=stripped,
                title="Insecure equality comparison on security-critical value",
                detail=(
                    "A security-critical value (HMAC digest, webhook signature, or verification token) "
                    "is being compared with `==` or `===`. String equality short-circuits on the first "
                    "differing byte, leaking timing information. An attacker making thousands of requests "
                    "can reconstruct the expected value one byte at a time — bypassing webhook signature "
                    "verification or token authentication without knowing the secret."
                ),
                fix=fix,
                severity="high",
            ))

    return findings


# ── 2c. AES-GCM DECIPHER WITHOUT AUTH TAG LENGTH (PRBL-R003) ─────────────────

_AES_GCM_DECIPHER = re.compile(
    r'createDecipheriv\s*\(\s*[\'"]aes-(?:128|192|256)-gcm[\'"]',
    re.IGNORECASE,
)
_AES_GCM_AUTH_TAG_LENGTH = re.compile(r'setAuthTagLength\s*\(', re.IGNORECASE)


def check_aes_gcm_auth_tag(lines: list[str], language: str, file_path: str = '') -> list[RuleMatch]:
    """
    PRBL-R003: createDecipheriv() with AES-GCM mode where setAuthTagLength()
    is not called within the following 20 lines.
    """
    if language not in ('javascript', 'typescript'):
        return []
    if _is_test_file(file_path):
        return []
    code = '\n'.join(lines)
    if _is_minified_file(file_path, code):
        return []

    findings = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip comment lines
        if stripped.startswith(('//', '*', '/*')):
            continue
        if not _AES_GCM_DECIPHER.search(line):
            continue
        # Collect 20-line lookahead window (lines after the trigger line)
        lookahead_end = min(len(lines), i + 20)
        lookahead = '\n'.join(lines[i:lookahead_end])
        if _AES_GCM_AUTH_TAG_LENGTH.search(lookahead):
            continue  # setAuthTagLength present in window — correctly configured
        findings.append(_match(
            rule_id="PRBL-R003",
            vuln_class="crypto_misconfiguration",
            line_number=i,
            line=stripped,
            title="AES-GCM decipher created without authentication tag length verification",
            detail=(
                "crypto.createDecipheriv() is called with an AES-GCM mode but "
                "setAuthTagLength() is not called on the resulting decipher object. "
                "Without explicit tag length enforcement, an attacker can supply a "
                "truncated authentication tag — for example 4 bytes instead of 16 — "
                "and Node.js will verify only those bytes, dramatically weakening "
                "GCM's integrity guarantee and enabling authentication bypass."
            ),
            fix=(
                "Call `decipher.setAuthTagLength(16)` immediately after `createDecipheriv()`. "
                "This enforces that the authentication tag must be exactly 16 bytes, "
                "preventing truncated-tag authentication bypass."
            ),
            severity="high",
        ))
    return findings


# ── 3. INJECTION PATTERNS ─────────────────────────────────────────────────────

_USER_INPUT_VARS = re.compile(
    r'(?i)(req\.(body|query|params|headers)|request\.(args|form|json|data|values|get_json)|'
    r'sys\.argv|os\.environ|getenv|input\(|flask\.request|django.*request)',
)

# Additional taint sources that are only relevant in a SQL context.
# settings.* / config.* / environ[ can carry schema names, table names, or
# other operator-controlled values that make SQL strings exploitable.
# These are NOT checked by _has_taint() directly; instead they are tested
# in a separate helper that is only invoked after _SQL_CONTEXT_SIGNALS passes.
_SQL_SETTINGS_TAINT = re.compile(
    r'(?i)(settings\.\w+|config\.\w+|os\.environ\[|environ\[)',
)

_FN_SIG = re.compile(r'\bdef\s+\w+\s*\(([^)]+)\)')
# JS/TS equivalents: function declarations, function expressions, arrow functions
_FN_SIG_JS = re.compile(
    r'(?:\bfunction\s*\w*\s*\(([^)]+)\)|(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?\(([^)]+)\)\s*=>)'
)


def _has_taint(window: str) -> bool:
    """
    Return True if the code window contains a user-controlled value.

    Accepts two sources:
      1. Web-framework taint: req.body, request.args, sys.argv, os.environ, etc.
      2. Function parameter taint: any non-self parameter from the enclosing def
         that also appears elsewhere in the window (i.e. is used in the expression).

    The second source catches library-style functions like get_user_by_name(username)
    or convert_file(filename, output_format) where the caller controls the input but
    there is no explicit web-framework reference in the surrounding lines.
    """
    if _USER_INPUT_VARS.search(window):
        return True
    fn_param = _FN_SIG.search(window)
    if fn_param:
        for p in fn_param.group(1).split(','):
            name = p.strip().split(':')[0].strip().split('=')[0].strip()
            if name and name != 'self' and name in window:
                return True
    js_param = _FN_SIG_JS.search(window)
    if js_param:
        params = js_param.group(1) or js_param.group(2) or ''
        for p in params.split(','):
            name = p.strip().split(':')[0].strip().split('=')[0].strip()
            # Skip framework response/next params — only caller-supplied data is taint
            if name and name not in ('res', 'response', 'next', 'callback', 'cb', 'done', 'err', 'error') and name in window:
                return True
    return False

# Tagged template literals used by SQL ORMs produce parameterized queries — safe.
# These tags appear immediately before the backtick: sql`SELECT...`, $queryRaw`...`
_SAFE_SQL_TAGS = re.compile(
    r'(?i)(?:^|[\s.(])(?:sql|Prisma\.sql|\$queryRaw|\$executeRaw|drizzle\.sql|sql\.raw|slonik\.sql|'
    r'postgres\.sql|pg)\s*`'
)

# Browser dialog methods that match SQL patterns on variable names: confirm/alert/prompt
# are never injection sinks regardless of what they contain.
_BROWSER_DIALOGS = re.compile(
    r'(?i)\b(window\.)?(confirm|alert|prompt)\s*\('
)

_SQL_INJECTION_PATTERNS = [
    # Single-line: SQL keyword + string concatenation.
    # Negative lookbehind for '.' prevents matching ORM method calls:
    #   User.findOne({email}).select("+password")  →  .select() is NOT SQL
    #   db.create(), model.update(), session.delete()  →  same
    r'(?i)(?<!\.)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE).{0,100}[`"\'\+].*\+',
    # Single-line: Python f-string with SQL keyword and variable interpolation
    r'(?i)f["\'].*SELECT.*\{',
    r'(?i)f["\'].*INSERT.*\{',
    r'(?i)f["\'].*WHERE.*\{',
    r'(?i)f["\'].*\bCREATE\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW)\b.*\{',
    r'(?i)f["\'].*\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW)\b.*\{',
    # Single-line: Python %-string formatting with SQL keyword
    # Catches: cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
    # and:     cursor.execute("SELECT ... WHERE name = '%s'" % name)
    r'(?i)["\'].*SELECT.*["\']\s*%\s',
    r'(?i)["\'].*INSERT.*["\']\s*%\s',
    r'(?i)["\'].*WHERE.*["\']\s*%\s',
    # Single-line: JS template literal with SQL keyword.
    # \b word boundaries required — prevents matching substrings like LAST_SELECTED_FEED
    # (which contains "SELECT") or "UPDATED_AT" (which contains "UPDATE").
    # (?<!\.) excludes method calls: cipher.update(), model.delete() are not SQL
    r'(?i)["\'\`].*\$\{.*(?<!\.)\b(SELECT|INSERT|UPDATE|DELETE)\b',
    r'(?i)`(?<!\.)\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b.*\$\{',
    # Single-line: query/sql variable assigned string + concatenation
    r'(?i)(query|sql)\s*=\s*["\'\`].*\+',
    r'(?i)(query|sql)\s*=\s*f["\']',
    # Multi-line build: query/sql variable appended to with concatenation.
    # Catches: sql += "WHERE name = '" + name + "'"  even when SELECT is on a prior line.
    # User input check (10-line window) still required — this alone isn't enough to flag.
    r'(?i)(query|sql|stmt)\s*\+=\s*.+\+',
    r'(?i)(query|sql|stmt)\s*\+=\s*f["\']',
    # Multi-line: variable re-assigned by appending user-controlled fragment
    r'(?i)(query|sql|stmt)\s*=\s*(query|sql|stmt)\s*\+',
    # SQLAlchemy text() sink with string concatenation or f-string interpolation.
    # Only fires when text() contains an interpolated/concatenated expression —
    # bare text("SELECT ...") with no + or { is safe and is excluded by the taint gate.
    r'(?i)\btext\s*\(\s*f["\'].*\{',
    r'(?i)\btext\s*\([^)]*\+',
    # Python .format() string SQL injection.
    # "SELECT * FROM users WHERE id = {}".format(uid)  is unsafe — same as %-format.
    # The string must contain a SQL keyword, then .format( call on it.
    r'(?i)["\'].*SELECT.*["\']\.format\s*\(',
    r'(?i)["\'].*INSERT.*["\']\.format\s*\(',
    r'(?i)["\'].*WHERE.*["\']\.format\s*\(',
]

# Secondary gate for SQL injection: at least one of these signals must appear in
# a 10-line window around the flagged line. This prevents false positives on
# template literals that construct storage keys, paths, or identifiers — those
# won't have any of these signals nearby.
_SQL_CONTEXT_SIGNALS = re.compile(
    r'(?i)('
    r'\.query\s*\(|\.execute\s*\(|\.raw\s*\('           # common DB driver methods
    r'|\.prepare\s*\(|\.all\s*\(|\.run\s*\('            # sqlite3 / better-sqlite3
    r'|\bquery\b|\bexecute\b|\bcursor\b'                 # variable / method names
    r'|\bpool\b|\bdb\b|\bconn\b|\bconnection\b'          # DB handle names
    r'|knex|sequelize|prisma|typeorm|pg\.|mysql'          # ORM/driver names (mongoose excluded — NoSQL, not SQL)
    r'|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b'     # SQL keywords (word-bounded)
    r'|\bFROM\b|\bWHERE\b|\bJOIN\b|\bINTO\b'
    r')'
)

# Fix 3: SQL execution sink — must be present in the file before firing I001
_SQL_EXECUTION_SINKS = re.compile(
    r'(?i)(\.execute\s*\(|cursor\.|db\.query\s*\(|db\.run\s*\(|conn\.execute\s*\(|'
    r'connection\.execute\s*\(|session\.execute\s*\(|\.raw\s*\(|knex\.|sequelize\.|'
    r'prisma\.\w+\.(findMany|create|update|delete|findFirst|executeRaw|queryRaw)\s*\()'
)


def _file_has_sql_sink(code: str) -> bool:
    return bool(_SQL_EXECUTION_SINKS.search(code))


# Fix 5: Variable-tracking SQL injection — catches the multi-line f-string pattern:
#   query = f'INSERT INTO books ... VALUES ("{title}", ...)'
#   cur.execute(query)
# when taint is more than 5 lines above the assignment.

_EXEC_WITH_VAR = re.compile(
    r'(?i)(?:\.execute|\.query|\.run|\.all)\s*\(\s*(\w+)\s*[\),]'
)
_FSTRING_ASSIGN_WITH_SQL = re.compile(
    r'(?i)(\w+)\s*=\s*f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|INTO)'
)
_STR_CONCAT_ASSIGN_WITH_SQL = re.compile(
    r'(?i)(\w+)\s*(?:\+=|=)\s*.*["\'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|INTO).*["\'].*\+'
)


def _check_variable_sql_injection(lines: list[str], i: int) -> Optional[str]:
    """
    Fix 5: If line i calls execute(varname), look back up to 15 lines for
    `varname = f'...SQL...'` — catches multi-line f-strings where taint is
    further up the function and not in the 5-line window.
    Returns the assignment line if found, else None.
    """
    exec_line = lines[i - 1]
    var_m = _EXEC_WITH_VAR.search(exec_line)
    if not var_m:
        return None
    varname = var_m.group(1)
    # Skip parameterized query variables — '?' or '%s' in a plain string is safe
    start = max(0, i - 15)
    for j in range(i - 2, start - 1, -1):
        assignment_line = lines[j]
        m = _FSTRING_ASSIGN_WITH_SQL.search(assignment_line)
        if m and m.group(1) == varname:
            return assignment_line
        m2 = _STR_CONCAT_ASSIGN_WITH_SQL.search(assignment_line)
        if m2 and m2.group(1) == varname:
            return assignment_line
    return None


_CMD_INJECTION_PATTERNS = [
    r'(?i)(exec|spawn|execFile|spawnSync|system|popen|subprocess\.call|subprocess\.run|os\.system)\s*\([^)]*\+',
    r'(?i)(exec|spawn|execFile|spawnSync)\s*\(`[^`]*\$\{',
    # shell=True is only a finding when user input is verifiably present in the same window.
    # Do NOT flag shell=True alone — subprocess.run(['ls'], shell=True) is bad practice
    # but not injection without user-controlled data flowing in.
    r'(?i)shell\s*=\s*True',
]

_CODE_INJECTION_PATTERNS = [
    # Bare eval/exec — not method calls like db.eval() or session.exec()
    # Negative lookbehind for '.' to exclude ORM/driver method calls
    r'(?<!\.)(?<!\w)\beval\s*\(',
    r'(?<!\.)\bexec\s*\(',
    r'\bnew\s+Function\s*\(',
    r'(?i)__import__\s*\(',
    r'(?i)compile\s*\(.*exec',
    # importlib.import_module() with user-controlled module name — AI-generated plugin loaders
    r'(?i)importlib\.import_module\s*\(',
]

# Eval-in-string-literal pattern: eval() appears inside a quoted string, not as an actual call.
# e.g. "eval() is not supported in this environment" — an error message, not injection.
# Matches: "...eval()..." or '...eval()...' — eval( preceded by any non-quote text after a quote.
_EVAL_IN_STRING = re.compile(
    r'''['""][^'"]*\beval\s*\([^'"]*['"]'''
    r'''|['][^']*\beval\s*\([^']*[']'''
    r'''|["][^"]*\beval\s*\([^"]*["]''',
)

# Fix 2a: Playwright's page.$$eval()/$eval() — a DOM query API, unrelated to JS eval().
# The bare-eval pattern's word boundary still matches "eval(" inside "$$eval(" since
# "$" is a non-word character, so this needs an explicit exclusion.
_PLAYWRIGHT_EVAL = re.compile(r'\$\$?eval\s*\(')

# Shell-wrapper function definition pattern: the window contains a function whose
# *name* is a shell/exec trigger word. Used to suppress I002/I003 when the code is
# defining an exec abstraction (e.g. export function exec(command)), not invoking
# one with user-controlled data.
_SHELL_WRAPPER_FN_RE = re.compile(
    r'(?:function|const|let|var|export\s+(?:async\s+)?function|export\s+const)\s+'
    r'(exec|spawn|shell|system|run_command|run_cmd|exec_cmd|execute|sh)\s*[\s(=]',
    re.IGNORECASE,
)

# Fix 2b: Python `def exec(...)`/`def eval(...)` shadows the builtin name. Unlike
# `def run_cmd(...)` (a descriptive name a developer chose, giving no signal about
# safety), a function literally named `exec`/`eval` is almost always self-recursive
# or otherwise unrelated to the dangerous builtin — e.g. AlphaFold3's
# `def exec(b, a): return exec(blocks[s:e], a)` is plain recursion, not code
# execution. Scoped to just these two builtin names so real vulnerable functions
# with descriptive names (run_cmd, execute, shell) are still caught.
_PYTHON_BUILTIN_SHADOW_RE = re.compile(
    r'\bdef\s+(exec|eval)\s*\(',
)


def _shadows_python_builtin(window: str) -> bool:
    return bool(_PYTHON_BUILTIN_SHADOW_RE.search(window))

# Fix 2c: importlib.import_module("literal.module.path") — a hardcoded string
# argument can never be attacker-controlled, unlike importlib.import_module(module_path)
# where the argument is a variable that might (even if rarely) carry tainted input.
_IMPORTLIB_LITERAL_ARG = re.compile(
    r'importlib\.import_module\s*\(\s*["\'][^"\']*["\']\s*\)'
)


def _inside_shell_wrapper(window: str) -> bool:
    """Return True if the window contains a function definition whose name is a
    shell/exec trigger word. Suppresses I002/I003 when the code is defining an
    exec abstraction rather than invoking one with user-controlled taint."""
    return bool(_SHELL_WRAPPER_FN_RE.search(window))


_INJECTION_SAFE_CONTEXT = re.compile(
    r'(?i)^\s*(print\s*\(|console\.(log|warn|error|info|debug)\s*\('
    r'|log(?:ger)?\.(debug|info|warning|warn|error|critical|exception)\s*\('
    r'|logging\.(debug|info|warning|warn|error|critical|exception)\s*\('
    r'|raise\s+\w*Error\s*\(|raise\s+\w*Exception\s*\('
    r'|assert\s+)',
)


def check_injection(lines: list[str], language: str) -> list[RuleMatch]:
    findings = []
    # Fix 3: I001 — require a SQL execution sink present in the file before checking.
    # Frontend TS/JS files that use fetch('/todos/${id}') have no SQL sink and should
    # never fire I001. Compute once per file call.
    code = '\n'.join(lines)
    file_has_sql = _file_has_sql_sink(code)

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(('#', '//', '*')):
            continue
        # Skip logging, print statements, and exception raises — these are not
        # injection sinks even if they contain SQL keywords or string concatenation
        if _INJECTION_SAFE_CONTEXT.match(line):
            continue

        # SQL injection
        for pattern in _SQL_INJECTION_PATTERNS:
            if re.search(pattern, line):
                # Skip ORM tagged template literals — these produce parameterized queries
                if _SAFE_SQL_TAGS.search(line):
                    break
                # Skip browser dialog methods — confirm/alert/prompt are not SQL sinks
                if _BROWSER_DIALOGS.search(line):
                    break
                window_start = max(0, i - 5)
                window_end = min(len(lines), i + 5)
                window = '\n'.join(lines[window_start:window_end])
                # Secondary gate: require at least one SQL context signal within
                # a 10-line window. Template literals that build state-management
                # keys, cache keys, or path strings have no SQL signals nearby.
                ctx_start = max(0, i - 5)
                ctx_end = min(len(lines), i + 5)
                ctx_window = '\n'.join(lines[ctx_start:ctx_end])
                if not _SQL_CONTEXT_SIGNALS.search(ctx_window):
                    break
                # Fix 3: require a SQL execution sink in the file — prevents frontend
                # files with fetch('/api/${id}') from firing I001.
                if not file_has_sql:
                    break
                # settings.*/config.*/environ[ as secondary taint source — Python only.
                # In JS/TS, config.* is too common in framework/webpack code to use as taint.
                sql_settings_taint = (language == "python" and _SQL_SETTINGS_TAINT.search(window))
                if _has_taint(window) or sql_settings_taint:
                    findings.append(_match(
                        rule_id="PRBL-I001",
                        vuln_class="injection",
                        line_number=i,
                        line=stripped,
                        title="SQL injection: user input concatenated into query",
                        detail=(
                            "User-controlled input is being interpolated directly into a SQL query. "
                            "An attacker can craft input that escapes the query context and executes "
                            "arbitrary SQL — dumping tables, bypassing auth, or deleting data."
                        ),
                        fix="Use parameterized queries or a query builder. Never interpolate user input into SQL strings.",
                        severity="high",
                    ))
                    break

        # Fix 5: Variable-tracking SQL injection check.
        # Catches: query = f'INSERT ... {val}' \n cur.execute(query)
        # when the taint (request.get_json() etc.) is more than 5 lines above.
        # Only run if file has a SQL sink (Fix 3 already gates at file level).
        if file_has_sql and not any(f.line_number == i for f in findings if f.rule_id == 'PRBL-I001'):
            assign_line = _check_variable_sql_injection(lines, i)
            if assign_line is not None:
                # Expand window to 20 lines above this line to find taint
                wide_window = '\n'.join(lines[max(0, i - 20):i + 2])
                if _has_taint(wide_window) or (language == "python" and _SQL_SETTINGS_TAINT.search(wide_window)):
                    findings.append(_match(
                        rule_id="PRBL-I001",
                        vuln_class="injection",
                        line_number=i,
                        line=stripped,
                        title="SQL injection: user input concatenated into query (via variable)",
                        detail=(
                            "User-controlled input is being interpolated directly into a SQL query "
                            "that is then executed. Even though the f-string assignment and the "
                            "execute call are on separate lines, the injection is equally exploitable."
                        ),
                        fix="Use parameterized queries or a query builder. Never interpolate user input into SQL strings.",
                        severity="high",
                    ))

        # Command injection
        for pattern in _CMD_INJECTION_PATTERNS:
            if re.search(pattern, line):
                window_start = max(0, i - 5)
                window_end = min(len(lines), i + 5)
                window = '\n'.join(lines[window_start:window_end])
                if _has_taint(window):
                    # Suppress: the enclosing function IS the shell abstraction being defined
                    if _inside_shell_wrapper(window):
                        break
                    findings.append(_match(
                        rule_id="PRBL-I002",
                        vuln_class="injection",
                        line_number=i,
                        line=stripped,
                        title="Command injection: user input passed to shell",
                        detail=(
                            "User-controlled input is being passed to a shell command. "
                            "An attacker can inject shell metacharacters to execute arbitrary "
                            "commands on the server."
                        ),
                        fix="Use subprocess with a list of arguments (never shell=True with user input). Validate and allowlist input before passing to any shell command.",
                        severity="high",
                    ))
                    break

        # Code injection
        for pattern in _CODE_INJECTION_PATTERNS:
            if re.search(pattern, line):
                # Suppress: eval() appears inside a string literal (error message, not a call)
                if _EVAL_IN_STRING.search(line):
                    break
                # Fix 2a: Playwright's $eval()/$$eval() DOM query API, not JS eval()
                if _PLAYWRIGHT_EVAL.search(line):
                    break
                # Fix 2c: importlib.import_module() with a hardcoded string literal —
                # cannot be attacker-controlled, unlike a variable argument.
                if _IMPORTLIB_LITERAL_ARG.search(line):
                    break
                window_start = max(0, i - 5)
                window_end = min(len(lines), i + 5)
                window = '\n'.join(lines[window_start:window_end])
                if _has_taint(window):
                    # Suppress: the enclosing function IS the shell/eval abstraction being defined
                    if _inside_shell_wrapper(window):
                        break
                    # Fix 2b: Python function literally named exec/eval — self-recursive
                    # or otherwise unrelated to the builtin, not a real eval/exec call.
                    # Uses a wider backward-only window than the taint check: nested
                    # function definitions (a helper defined inside the shadowing
                    # function) can put the actual call well outside a +/-5 window —
                    # e.g. AlphaFold3's checkpointing.py nests `exec_sliced` 7+ lines
                    # inside `def exec(b, a):`.
                    shadow_window = '\n'.join(lines[max(0, i - 20):i + 3])
                    if _shadows_python_builtin(shadow_window):
                        break
                    findings.append(_match(
                        rule_id="PRBL-I003",
                        vuln_class="injection",
                        line_number=i,
                        line=stripped,
                        title="Code injection: user input passed to eval/exec",
                        detail=(
                            "User-controlled input is being evaluated as code. "
                            "This gives an attacker full code execution on the server."
                        ),
                        fix="Never pass user input to eval(), exec(), new Function(), or compile(). Redesign to use a safe data structure instead.",
                        severity="high",
                    ))
                    break

    return findings


# ── 4. MISSING ACCESS CONTROL ─────────────────────────────────────────────────

_INLINE_AUTH_CALLS = [
    re.compile(r) for r in [
        r'requireAuth\s*\(',
        r'requireUser\s*\(',
        r'requireSession\s*\(',
        r'requirePro\s*\(',
        r'requireAdmin\s*\(',
        r'getServerSession\s*\(',
        r'getSession\s*\(',
        r'auth\(\)',
        r'verifySession\s*\(',
        r'checkAuth\s*\(',
        r'authenticate\s*\(',
        r'getCurrentUser\s*\(',
        r'requireApiKey\s*\(',
    ]
]

_DEMO_CONTENT_PATHS = [
    'remotion/',
    'heroanimation',
    'heroscanner',
    'heroplayer',
    '/animations/',
    '/demo/',
    '/marketing/',
    '/examples/',
    # Next.js / landing page root — page.tsx in the app root is typically the
    # marketing landing page, not application logic
    'app/page.tsx',
    'pages/index.',
    'src/pages/index.',
]

_ROUTE_PATTERNS = {
    "javascript": [
        r'(?i)(app|router)\.(get|post|put|patch|delete)\s*\(\s*["\']',
        # Fastify method-style: fastify.get('/path', handler)
        r'(?i)fastify\.(route|get|post|put|patch|delete)\s*\(',
        # Fastify object-config style: fastify.route({ method, url, handler })
        r'(?i)(app|router)\.(route|get|post|put|patch|delete)\s*\(\s*\{',
        # Hono: app.get('/path', handler) — same pattern as Express, explicit coverage
        r'(?i)(app|router)\.(get|post|put|patch|delete)\s*\(\s*["\']',
    ],
    "typescript": [
        r'(?i)(app|router)\.(get|post|put|patch|delete)\s*\(\s*["\']',
        r'@(Get|Post|Put|Patch|Delete)\(',
    ],
    "python": [
        r'@(app|router|blueprint)\.(route|get|post|put|patch|delete)\(',
        r'@api_view\(',
        # Django/DRF CBVs — only match when first arg after self is `request`
        # to avoid catching data-layer methods like def delete(self, db, obj_id)
        r'def (get|post|put|patch|delete)\(self,\s*request',
    ],
}

# Serverless handler patterns — match the export line, scan whole file for context.
# These are file-level handlers: Vercel, Next.js Pages Router, Netlify, AWS Lambda,
# and Next.js App Router named exports.
_SERVERLESS_PATTERNS = [
    # Vercel / Next.js Pages Router (CJS)
    r'module\.exports\s*=\s*async\s*\(req,\s*res\)',
    r'module\.exports\s*=\s*function\s*\(req,\s*res\)',
    r'module\.exports\s*=\s*async\s*function\s*\w*\s*\(req,\s*res\)',
    # Next.js Pages Router (ESM)
    r'export\s+default\s+async\s+function\s+\w*\s*\(\s*req',
    r'export\s+default\s+function\s+\w*\s*\(\s*req',
    # Next.js App Router named HTTP method exports
    r'export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\s*\(',
    r'export\s+function\s+(GET|POST|PUT|PATCH|DELETE)\s*\(',
    # Netlify / AWS Lambda
    r'exports\.handler\s*=\s*async\s+function',
    r'exports\.handler\s*=\s*async\s*\(',
]

_SERVERLESS_COMPILED = [re.compile(p) for p in _SERVERLESS_PATTERNS]

_AUTH_INDICATORS = re.compile(
    r'(?i)(requireAuth|isAuthenticated|authenticate|auth_required|login_required|'
    r'verify_token|check_permission|hasRole|isAdmin|middleware\s*=|@login_required|'
    r'@permission_required|@jwt_required|@auth|req\.user|request\.user|session\[|current_user|'
    r'get_current_user|Depends\(|Security\(|authorization|\.headers.*auth|'
    r'authHeader|bearerToken|validateToken|verifyJwt|getUser\(|getUserId\(|'
    # DRF (Django REST Framework) — permission_classes covers all auth levels
    # including AllowAny (explicit decision) and IsAuthenticated (enforced)
    r'permission_classes|authentication_classes|'
    # FastAPI / Starlette
    r'oauth2_scheme|get_current_active_user|HTTPBearer|HTTPBasic|'
    # General decorator patterns
    r'@requires_auth|@authenticated|@protected|'
    # Common Express/Node.js middleware naming conventions — often passed inline
    # as route arguments: router.get('/path', protect, handler)
    r'protect\b|authMiddleware|verifyToken|verifyJwt|requireLogin|ensureAuth|'
    r'isAuth\b|tokenRequired|requireOrgMembership|checkAuth|passportAuth|'
    r'passport\.authenticate|jwtMiddleware|authGuard|roleGuard|guardRoute|'
    # camelCase and domain-specific auth middleware names frequently seen in MERN stacks
    r'authRequired|requiresAuth|verifyAuth|ensureAuthenticated|ensureLoggedIn|'
    r'adminAuth|userAuth|jwtAuth|bearerAuth|isLoggedIn|checkToken|'
    r'tokenMiddleware|sessionAuth|cookieAuth|'
    # NestJS guards — @UseGuards() at class or method level, RolesGuard, JwtAuthGuard
    r'UseGuards|JwtAuthGuard|AuthGuard|RolesGuard|@Roles\(|AccessTokenGuard|'
    r'TokenGuard|BearerGuard|ApiKeyGuard|OrganizationActionGuard|'
    # NestJS @Public() decorator — explicit opt-out of auth. If the developer
    # intentionally marked a route public, it's an explicit access control decision.
    # Suppress PRBL-A001 — this is the right outcome either way.
    r'@Public\b|IsPublic\b|SkipAuth\b|AllowAnonymous\b|'
    # Stripe webhook signature verification — constructEvent validates the payload signature,
    # which is the correct auth mechanism for webhook endpoints
    r'constructEvent\s*\(|webhooks\.constructEvent)',
)

# Auth indicators that are only safe to check on the ROUTE LINE ITSELF.
# These are too short/generic to search in surrounding context (would cause
# false negatives on files that happen to use 'auth' as an import name).
# On a route declaration line, a bare identifier like `auth` between the path
# and the handler is unambiguously a middleware argument.
_ROUTE_LINE_AUTH = re.compile(
    r'''(?x)
    ,\s*auth\s*[,)]          # ,auth,  or  ,auth)  — bare auth middleware arg
    |,\s*gate\s*[,)]         # ,gate,  — Laravel/custom gate middleware
    |,\s*verify\s*[,)]       # ,verify, — generic verify middleware
    |,\s*secured\s*[,)]      # ,secured,
    |,\s*authenticated\s*[,)]
    ''',
    re.IGNORECASE,
)

_SENSITIVE_OPERATIONS = re.compile(
    r'(?i)(\.find|\.findOne|\.findById|\.query|\.filter|\.get\(|\.update|\.delete|'
    r'\.create|\.save|\.insert|\.remove|stripe\.|payment|charge|transfer|'
    r'admin|user\..*=|password|email)',
)

# Outbound-only auth markers — these mean the file is authenticating TO a service,
# not authenticating the incoming caller. Don't count them as access control.
_OUTBOUND_AUTH_ONLY = re.compile(
    r'(?i)(Authorization:\s*`Bearer\s*\$\{|headers.*Authorization.*Bearer.*\$\{|'
    r'apikey:\s*\w+|api_key\s*=\s*\w+)',
)


def _is_serverless_handler(lines: list[str]) -> Optional[int]:
    """Returns the line number (1-indexed) of the serverless export, or None."""
    for i, line in enumerate(lines, 1):
        if any(p.search(line) for p in _SERVERLESS_COMPILED):
            return i
    return None


# Intentionally public infrastructure routes — health checks, API docs, JWKS,
# root landing pages, metrics. Flagging these as missing auth is always a FP;
# they must be unauthenticated by design.
# Pattern matches the path prefix inside any quote style — no closing-quote anchor,
# so "/health/detail" and "/.well-known/jwks.json" both match.
_PUBLIC_ROUTE_RE = re.compile(
    r'''['"]('''
    r'''/\.well-known'''           # JWKS, OpenID Connect discovery
    r'''|/health'''                # /health, /healthz, /health/live, etc.
    r'''|/ping'''
    r'''|/ready'''
    r'''|/live'''
    r'''|/status'''
    r'''|/metrics'''
    r'''|/version'''
    r'''|/docs'''                  # FastAPI/Swagger UI
    r'''|/redoc'''
    r'''|/openapi\.json'''
    r'''|/swagger'''
    r'''|/favicon\.ico'''
    r'''|/robots\.txt'''
    r'''|/public(?![a-zA-Z0-9_-])'''   # /public exactly or /public/sub — not /public-data, /publicKey
    r'''|/api-docs'''                  # /api-docs/swagger.json, /api-docs/openapi.yaml
    # Auth flow endpoints — always unauthenticated by design
    r'''|/login'''
    r'''|/logout'''
    r'''|/signin'''
    r'''|/signout'''
    r'''|/signup'''
    r'''|/register'''
    r'''|/forgot-password'''
    r'''|/reset-password'''
    r'''|/verify-email'''
    r'''|/confirm-email'''
    r'''|/auth/'''                 # /auth/google, /auth/callback, etc.
    r'''|/oauth/'''                # /oauth/github, /oauth/callback, etc.
    r'''|/api/auth/'''             # /api/auth/signin, /api/auth/signup, etc.
    r'''|/?["\')]'''               # bare root: "/" alone or empty path
    r''')''',
    re.IGNORECASE,
)


# Routes whose names signal they are intentionally public-facing with no auth requirement.
# When a route path or handler function name contains one of these, downgrade to LOW.
_INTENTIONALLY_PUBLIC_ROUTES = re.compile(
    r'(?i)[/"](free[-_]?trial|freetrial|demo[-_]?request|analytics|tracking|telemetry|'
    r'beacon|webhook|webhooks|callback|oauth|health[-_]?check|'
    r'public[-_]|open[-_])[/"\'$]?'
)

# Rate-limiting signals in a 20-line window — suggests the developer is aware of
# unauthenticated access and is controlling it via rate limiting instead of auth.
_RATE_LIMIT_SIGNALS = re.compile(
    r'(?i)(rateLimit|rate_limit|rateLimiter|checkRateLimit|applyRateLimit|'
    r'too many requests|Too Many Requests|X-RateLimit|Retry-After)'
)

# Explicit annotation comment indicating the developer chose public access
_PUBLIC_ANNOTATION = re.compile(
    r'(?i)//\s*(@public|public endpoint|no auth required|intentionally unauthenticated)'
)

# A001 utility path suppression — framework helper files that define base classes,
# pagination utilities, response schemas, and mixins are not route handlers and
# should not be flagged for missing access control.
_A001_UTILITY_PATHS = re.compile(
    r'(?i)/(common|utils|helpers|schemas|mixins|base|pagination|response_schema)/',
)
_A001_UTILITY_FILES = re.compile(
    r'(?i)(pagination|response_schema|base_view|mixin|schema_util)\.(py|ts|js)$',
)

# Known-safe route paths — intentionally unauthenticated by design across all frameworks.
# Applies both to route line path strings and Next.js App Router file paths.
# Matches bare paths (/health) and API-prefixed paths (/api/health, /api/status, etc.)
_A001_PUBLIC_ROUTES = re.compile(
    r'(?i)["\']/?(?:api/)?(?:health|healthz|ping|status|ready|readyz|live|liveness|'
    r'metrics|favicon\.ico|robots\.txt|sitemap\.xml|\.well-known/)["\']',
)
# Next.js App Router: file path contains /api/health/, /api/ping/, /api/status/
_A001_PUBLIC_FILE_PATH = re.compile(
    r'(?i)/api/(?:health|ping|status|ready|live|liveness|healthz|readyz)/',
)


def _has_django_settings(file_path: str) -> bool:
    """
    Return True if a settings.py (or settings/ package) exists anywhere in the
    repo containing the given file. Used to detect DRF projects where
    DEFAULT_PERMISSION_CLASSES may be set globally rather than per-view.
    """
    if not file_path:
        return False
    try:
        current = Path(file_path).resolve().parent
    except (OSError, ValueError):
        return False
    root = Path(current.root)
    for _ in range(10):
        # Stop before hitting the filesystem root — avoids globbing /
        if current == root or str(current) in ("/", ""):
            break
        try:
            if (current / "settings.py").exists():
                return True
            # settings package: settings/__init__.py or settings/base.py
            settings_dir = current / "settings"
            if settings_dir.is_dir() and any(settings_dir.glob("*.py")):
                return True
            # One level deeper (common Django layout: project/settings.py)
            for child in current.iterdir():
                if child.is_dir() and not child.name.startswith('.'):
                    if (child / "settings.py").exists():
                        return True
                    s_dir = child / "settings"
                    if s_dir.is_dir() and any(s_dir.glob("*.py")):
                        return True
        except (OSError, PermissionError):
            pass
        parent = current.parent
        if parent == current:
            break
        current = parent
    return False


def check_missing_access_control(lines: list[str], language: str, file_path: str = "") -> list[RuleMatch]:
    findings = []

    # Suppress A001 entirely for framework utility / helper files — these define
    # base classes, pagination helpers, response schemas, and mixins that look like
    # routes to the pattern matcher but are not route handlers.
    if file_path:
        fp_lower = file_path.replace('\\', '/')
        if _A001_UTILITY_PATHS.search(fp_lower) or _A001_UTILITY_FILES.search(fp_lower):
            return findings
        # Next.js App Router: suppress A001 for known public endpoint directories
        if _A001_PUBLIC_FILE_PATH.search(fp_lower):
            return findings

    full_text = '\n'.join(lines)

    # --- Serverless file-level handler check ---
    if language in ("javascript", "typescript"):
        handler_line = _is_serverless_handler(lines)
        if handler_line is not None:
            has_sensitive = bool(_SENSITIVE_OPERATIONS.search(full_text))
            # Real inbound auth: auth indicators present AND not only outbound API key usage
            has_auth = bool(_AUTH_INDICATORS.search(full_text))
            # Strip outbound-only matches to avoid false negatives
            if has_auth:
                # Remove outbound-only spans and re-check
                stripped_text = _OUTBOUND_AUTH_ONLY.sub('', full_text)
                has_auth = bool(_AUTH_INDICATORS.search(stripped_text))

            if has_sensitive and not has_auth:
                # Check for inline auth calls in the first 10 lines after the handler export
                body_start = handler_line  # 0-indexed: handler_line is 1-indexed line number
                body_window = '\n'.join(lines[body_start:body_start + 10])
                if any(p.search(body_window) for p in _INLINE_AUTH_CALLS):
                    return findings  # inline auth found — not a real finding

                handler_line_str = lines[handler_line - 1].strip()
                findings.append(_match(
                    rule_id="PRBL-A001",
                    vuln_class="missing_access_control",
                    line_number=handler_line,
                    line=handler_line_str,
                    title="Missing access control on serverless handler with sensitive operation",
                    detail=(
                        "This serverless function performs a sensitive operation (database access, "
                        "user data, or financial action) with no visible authentication check on "
                        "the incoming request. Any unauthenticated caller can invoke it."
                    ),
                    fix="Verify the caller's identity before processing the request — check a Bearer token, session cookie, or API key against your auth provider.",
                    severity="medium",
                ))
            return findings  # File is a serverless handler — don't also run Express patterns

    # --- Express / Flask / Django route pattern check ---
    route_patterns = _ROUTE_PATTERNS.get(language, _ROUTE_PATTERNS["javascript"])

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Skip comment lines and JSDoc — route patterns in comments are not real routes
        if stripped.startswith(('//', '*', '#', '/*')):
            i += 1
            continue

        is_route = any(re.search(p, line) for p in route_patterns)
        if not is_route:
            i += 1
            continue

        # Skip wildcard catch-all routes — not a protected resource endpoint
        if re.search(r'''['"]\*''', line) or re.search(r'''['"]/\*''', line):
            i += 1
            continue

        # Skip intentionally public infrastructure endpoints and auth flow routes.
        if _PUBLIC_ROUTE_RE.search(line):
            i += 1
            continue
        # Skip known-safe health/ping/status/metrics endpoints — always unauthenticated by design.
        if _A001_PUBLIC_ROUTES.search(line):
            i += 1
            continue
        # include_in_schema=False marks internal/doc routes explicitly hidden
        # from the public API schema — not production data endpoints.
        if 'include_in_schema=False' in line or 'include_in_schema = False' in line:
            i += 1
            continue

        # Look ahead up to 30 lines for auth check or sensitive operation
        lookahead = lines[i:min(len(lines), i + 30)]
        lookahead_text = '\n'.join(lookahead)

        # Also look backward up to 60 lines — catches class-level auth attributes
        # (e.g. DRF `permission_classes` defined at class level before the methods)
        lookback_start = max(0, i - 60)
        # Only look back to the nearest class definition to avoid crossing class boundaries
        lookback_lines = lines[lookback_start:i]
        # Find the last class definition within lookback window and use from there
        last_class_idx = None
        for j, lb_line in enumerate(lookback_lines):
            if re.match(r'\s*class\s+\w+', lb_line):
                last_class_idx = j
        if last_class_idx is not None:
            lookback_lines = lookback_lines[last_class_idx:]
        lookback_text = '\n'.join(lookback_lines)

        # Also check the route declaration line itself — Express middleware is often
        # passed as an inline argument on the same line as the route definition:
        #   router.get('/path', authMiddleware, controller)
        #   router.post('/add', protect, addExpense)
        #   router.delete('/:id', auth, handler)        ← bare 'auth' identifier
        # The surrounding context windows don't include this line, so we check it
        # explicitly here. We also allow bare `auth` on the route line itself — too
        # generic for lookahead/lookback but unambiguous when it's a route argument.
        has_auth = (
            bool(_AUTH_INDICATORS.search(line)) or
            bool(_ROUTE_LINE_AUTH.search(line)) or
            bool(_AUTH_INDICATORS.search(lookahead_text)) or
            bool(_AUTH_INDICATORS.search(lookback_text)) or
            any(p.search('\n'.join(lines[i + 1:i + 11])) for p in _INLINE_AUTH_CALLS)
        )

        # NestJS: class-level @UseGuards() decorator sits ABOVE the class declaration.
        # Our lookback is trimmed to start at the class definition line, which excludes
        # the class decorators. Re-check the 10 lines just before the class boundary.
        if not has_auth and last_class_idx is not None:
            pre_class_start = max(0, last_class_idx - 10)
            pre_class_text = '\n'.join(lines[lookback_start + pre_class_start:lookback_start + last_class_idx])
            has_auth = bool(_AUTH_INDICATORS.search(pre_class_text))
        has_sensitive = bool(_SENSITIVE_OPERATIONS.search(lookahead_text))

        if has_sensitive and not has_auth:
            # Skip: developer explicitly annotated this endpoint as public
            route_context = '\n'.join(lines[max(0, i - 3):i + 1])
            if _PUBLIC_ANNOTATION.search(route_context):
                i += 1
                continue

            # Check if this is an intentionally public route by path/name pattern
            is_public_by_name = bool(_INTENTIONALLY_PUBLIC_ROUTES.search(line))

            # Check if rate limiting is present in a 20-line window (signals
            # the developer is aware of unauthenticated access)
            rl_window = '\n'.join(lines[max(0, i - 10):min(len(lines), i + 10)])
            has_rate_limit = bool(_RATE_LIMIT_SIGNALS.search(rl_window))

            # Settings-aware confidence downgrade for Django/DRF views.
            # A DRF view without explicit permission_classes may be protected by
            # DEFAULT_PERMISSION_CLASSES in settings.py — which Prbl does not yet
            # parse. When a settings.py file is detected in the repo, downgrade
            # from MEDIUM to LOW and surface a targeted message asking the developer
            # to verify their global permission configuration.
            drf_global_perms = language == "python" and _has_django_settings(file_path)
            if drf_global_perms:
                sev = "low"
                detail = (
                    "This endpoint has no explicit permission_classes declaration. "
                    "If DEFAULT_PERMISSION_CLASSES in settings.py is not set to "
                    "IsAuthenticated or stricter, this endpoint may be unprotected. "
                    "Review your global permission configuration."
                )
                fix = (
                    "Verify that REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES'] in settings.py "
                    "includes IsAuthenticated. For endpoints that must be public (e.g. registration, "
                    "login), add permission_classes = [AllowAny] explicitly so the intent is clear."
                )
            elif is_public_by_name or has_rate_limit:
                sev = "low"
                detail = (
                    "This route performs a sensitive operation with no visible authentication check. "
                    + ("The route name suggests it may be intentionally public. " if is_public_by_name else "")
                    + ("Rate limiting is present, which reduces exposure. " if has_rate_limit else "")
                    + "Confirm this endpoint is intentionally unauthenticated and add an explicit "
                    "// @public annotation or AllowAny permission class to document the decision."
                )
                fix = (
                    "If intentionally public, add `// @public` to document the decision. "
                    "If not, add authentication middleware before this route."
                )
            else:
                sev = "medium"
                detail = (
                    "This route performs a sensitive operation (database access, user data, "
                    "or financial action) with no visible authentication or authorization check. "
                    "Any unauthenticated caller can access it — IDOR attacks work by simply "
                    "changing an ID parameter in the URL."
                )
                fix = "Add authentication middleware and verify the caller is authorized to access the specific resource (not just logged in)."

            findings.append(_match(
                rule_id="PRBL-A001",
                vuln_class="missing_access_control",
                line_number=i + 1,
                line=stripped,
                title="Missing access control on route with sensitive operation",
                detail=detail,
                fix=fix,
                severity=sev,
            ))

        i += 1

    return findings


# ── 5. NOSQL INJECTION (PRBL-I004) ───────────────────────────────────────────

_NOSQL_PATTERNS = [
    # $where with string concatenation or template interpolation — JS evaluated server-side
    r'\$where["\']?\s*:\s*["\'`].*(\+|\$\{)',
    r'\$where["\']?\s*:\s*(req\.|request\.)',
    # User-controlled object passed straight into a Mongo query operator position:
    #   User.find(req.body)  /  collection.findOne(req.query)
    r'\.(find|findOne|findOneAndUpdate|findOneAndDelete|deleteOne|deleteMany|updateOne|updateMany|count|countDocuments)\s*\(\s*(req\.(body|query|params)|request\.(json|args|form))\b',
    # mapReduce with interpolated JS
    r'mapReduce\s*\(\s*["\'`].*(\+|\$\{)',
    # pymongo dict-value injection: collection.find({"field": request.args[...]})
    # The current patterns only catch request.* as the direct argument.
    # This sub-pattern catches user input as a *value inside* the dict literal.
    r'\.(find|findOne|findOneAndUpdate|findOneAndDelete|deleteOne|deleteMany|updateOne|updateMany|count|countDocuments)\s*\(\s*\{[^}]*request\.(args|form|json|values|get_json)',
]

_NOSQL_COMPILED = [re.compile(p) for p in _NOSQL_PATTERNS]


def check_nosql_injection(lines: list[str], language: str) -> list[RuleMatch]:
    findings = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(('#', '//', '*')):
            continue
        for pattern in _NOSQL_COMPILED:
            if pattern.search(line):
                window = '\n'.join(lines[max(0, i - 5):min(len(lines), i + 5)])
                if not _has_taint(window):
                    continue
                findings.append(_match(
                    rule_id="PRBL-I004",
                    vuln_class="injection",
                    line_number=i,
                    line=stripped,
                    title="NoSQL injection: user input in MongoDB query",
                    detail=(
                        "User-controlled input flows into a MongoDB query operator. "
                        "Operator injection ({'$gt': ''} bypasses login checks) and $where "
                        "string interpolation (arbitrary JS executed inside MongoDB) both "
                        "let an attacker read or modify data they shouldn't reach."
                    ),
                    fix=(
                        "Never pass req.body/req.query objects directly into a query. "
                        "Extract and validate each field explicitly (e.g. {email: String(req.body.email)}), "
                        "and avoid $where entirely — express the condition with standard query operators."
                    ),
                    severity="high",
                ))
                break
    return findings


# ── 6. HARDCODED SESSION/COOKIE SECRET (PRBL-C002) ───────────────────────────

# secret: '...' inside session()/cookieParser()/jwt.sign() config. The generic
# PRBL-C001 assignment pattern misses object-literal syntax (colon, not equals).
# Matches secret:, cookieSecret:, sessionSecret:, jwt_secret:, etc.
_SESSION_SECRET = re.compile(
    r'''(?i)\b[a-z_]*secret\s*:\s*["'][^"']{4,}["']''',
)
_COOKIE_PARSER_SECRET = re.compile(
    r'''cookieParser\s*\(\s*["'][^"']{4,}["']\s*\)''',
)
# Flask/Django style: app.secret_key = '...' / SECRET_KEY = '...' / SECRET_KEY_BASE = '...'
_PY_SECRET_KEY = re.compile(
    r'''(?i)(secret_key(?:_base)?)\s*=\s*["'][^"']{4,}["']''',
)
# Fix 4: Flask dict-assignment form: app.config['SECRET_KEY'] = 'literal'
_PY_APP_CONFIG_SECRET = re.compile(
    r'''(?i)app\.config\s*\[\s*["']SECRET_KEY["']\s*\]\s*=\s*["']([^"']{4,})["']''',
)
# Context that makes the session-secret window relevant
_SESSION_CONTEXT = re.compile(
    r'(?i)(session\s*\(|express-session|cookie-session|cookieParser|jwt\.sign|jsonwebtoken|app\.secret_key|SECRET_KEY|'
    r'DJANGO_SECRET_KEY|SECRET_KEY_BASE|'
    r'cookie_?secret|session_?secret|jwt_?secret|token_?secret|signing_?secret)',
)


def check_session_secret(lines: list[str], language: str) -> list[RuleMatch]:
    findings = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(('#', '//', '*')):
            continue

        # Fix 4: app.config['SECRET_KEY'] = 'literal' — check BEFORE _CRED_SAFE_CONTEXT
        # because _CRED_SAFE_CONTEXT matches 'config[' which is present on this line.
        # Only fire if the value is not from os.environ/getenv.
        if language == "python":
            app_config_m = _PY_APP_CONFIG_SECRET.search(line)
            if app_config_m:
                secret_val = app_config_m.group(1)
                # Skip if value comes from env var (covered by _CRED_SAFE_CONTEXT normally)
                if not re.search(r'(?i)(os\.environ|getenv|process\.env)', line):
                    if not _FALLBACK_SAFE_VALUE.match(secret_val):
                        findings.append(_match(
                            rule_id="PRBL-C002",
                            vuln_class="hardcoded_credentials",
                            line_number=i,
                            line=stripped,
                            title="Hardcoded session/signing secret",
                            detail=(
                                "The session or token-signing secret is a literal string in source code. "
                                "Anyone with repo access can forge valid session cookies or JWTs for any "
                                "user — full account takeover with no other vulnerability required. "
                                "AI-generated Express and Flask boilerplate ships this constantly."
                            ),
                            fix=(
                                "Load the secret from an environment variable and fail fast if missing: "
                                "`app.config['SECRET_KEY'] = os.environ['SECRET_KEY']`. "
                                "Rotate the leaked value — it is compromised the moment it was committed."
                            ),
                            severity="high",
                        ))
                continue  # handled — don't fall through to the generic checks

        if _CRED_SAFE_CONTEXT.search(line):
            continue  # process.env / os.environ — secret comes from config
        if _CRED_SAFE_VARNAME.search(line):
            continue

        hit = (
            _SESSION_SECRET.search(line)
            or _COOKIE_PARSER_SECRET.search(line)
            or (language == "python" and _PY_SECRET_KEY.search(line))
        )
        if not hit:
            continue
        # Require session/JWT context on the line or in the 5 lines above —
        # avoids flagging unrelated object fields that happen to be named secret
        window = '\n'.join(lines[max(0, i - 5):i + 1])
        if not _SESSION_CONTEXT.search(window):
            continue
        # Skip obvious placeholder values
        value_m = _STRING_VALUE.search(hit.group(0))
        if value_m and _FALLBACK_SAFE_VALUE.match(value_m.group(1)):
            continue
        if value_m and _CRED_PLACEHOLDER_VALUES.match(value_m.group(1)):
            continue
        if value_m and (_is_non_ascii(value_m.group(1)) or value_m.group(1).lower() in _STATUS_WORDS):
            continue
        if value_m and _BCRYPT_HASH.match(value_m.group(1)):
            continue
        # Suppress C002 when the value is an all-uppercase env-var name (config schema label)
        if value_m and _ENV_VAR_NAME_VALUE.match(value_m.group(1)):
            continue
        findings.append(_match(
            rule_id="PRBL-C002",
            vuln_class="hardcoded_credentials",
            line_number=i,
            line=stripped,
            title="Hardcoded session/signing secret",
            detail=(
                "The session or token-signing secret is a literal string in source code. "
                "Anyone with repo access can forge valid session cookies or JWTs for any "
                "user — full account takeover with no other vulnerability required. "
                "AI-generated Express and Flask boilerplate ships this constantly."
            ),
            fix=(
                "Load the secret from an environment variable and fail fast if missing: "
                "`secret: process.env.SESSION_SECRET` / `app.secret_key = os.environ['SECRET_KEY']`. "
                "Rotate the leaked value — it is compromised the moment it was committed."
            ),
            severity="high",
        ))
    return findings


# ── 7. PATH TRAVERSAL (PRBL-T001) ────────────────────────────────────────────

_PATH_SINKS = re.compile(
    r'(?i)\b(sendFile|createReadStream|createWriteStream|readFile|readFileSync|'
    r'writeFile|writeFileSync|unlink|unlinkSync|open|send_file|send_from_directory|'
    r'FileResponse|read_text|read_bytes|write_text|write_bytes)\s*\('
    r'|\bshutil\.(copy|move|rmtree)\s*\(',
)
# User input used in the sink argument: concatenation, template literal, f-string,
# os.path.join with a request value
_PATH_TAINT_ON_LINE = re.compile(
    r'(req\.(params|query|body)|request\.(args|form|values|json)|'
    r'\$\{|f["\']|\+\s*\w|os\.path\.join)',
)
# Sanitization signals — basename() or a traversal check nearby means handled
_PATH_SANITIZED = re.compile(
    r'(?i)(basename|path\.resolve.*startsWith|normalize.*startsWith|'
    r'\.\.[\'"/\\]?\s*(in|includes)|includes\s*\(\s*["\']\.\.|secure_filename|safe_join)',
)


_T001_PACKAGING_FILES = re.compile(
    r'(?i)(setup\.py|setup\.cfg|pyproject\.toml|MANIFEST\.in|conftest\.py)$',
)


# ── PRBL-I005: Prototype Pollution via tainted bracket assignment ─────────────

# Matches: obj[key] = value — captures the object expression and key expression.
# Key must be a single identifier or req.* expression (no commas, spaces, or
# array-destructuring patterns like [a, b]).
_BRACKET_ASSIGN = re.compile(
    r'(\w[\w.]*)\s*\[(\w[\w.]*(?:\[[\'"]\w+[\'"]\])?)\]\s*='
)

# Direct request taint in the key expression — always fire (Shape 1)
_REQ_KEY_TAINT = re.compile(
    r'^req\.(params|query|body|headers)\.'
)

# Object names that are safe receivers — skip to avoid FP
_SAFE_OBJ_NAMES = re.compile(
    r'(?i)\b(map|cache|store|registry|lookup|dict|headers|env)\b'
)

# Key variable names that are loop indices — skip
_LOOP_INDEX_NAMES = re.compile(r'^(i|j|k|n|idx|index)$')

# Sanitization guard — hasOwnProperty check nearby → skip
_HAS_OWN_PROP = re.compile(
    r'hasOwnProperty\s*\(|Object\.prototype\.hasOwnProperty\.call\s*\('
)

# Allowlist check guard — if/includes(key) or ALLOWED.has(key) in window → skip
_ALLOWLIST_CHECK = re.compile(
    r'(?i)(\.includes\s*\(\s*\w+\s*\)|\.has\s*\(\s*\w+\s*\)|ALLOW|whitelist)'
)

# TypeScript typed object: const obj: SomeType = — if type is specific (not any/Record/[) skip
_TS_TYPED_OBJ = re.compile(
    r'(?:const|let)\s+(\w+)\s*:\s*([A-Z]\w*(?:<[^>]*>)?)\s*='
)

# Null-prototype safe object
_NULL_PROTO = re.compile(r'Object\.create\s*\(\s*null\s*\)')

# Map/Set target in lookback
_MAP_SET_NEW = re.compile(r'new\s+(Map|Set)\s*\(')

# for...of / for...in iterating array or object → skip bracket assignment inside
_FOR_LOOP = re.compile(r'\bfor\s*\(')


def check_prototype_pollution(lines: list[str], language: str, file_path: str = '') -> list[RuleMatch]:
    """
    PRBL-I005: Prototype pollution via bracket assignment with tainted key.
    Fires when obj[key] = value and key traces to external input.
    """
    if language not in ('javascript', 'typescript'):
        return []
    if _is_test_file(file_path):
        return []
    code = '\n'.join(lines)
    if _is_minified_file(file_path, code):
        return []

    findings = []

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip comment lines
        if stripped.startswith(('//', '*', '/*')):
            continue

        m = _BRACKET_ASSIGN.search(line)
        if not m:
            continue

        obj_expr = m.group(1)
        key_expr = m.group(2).strip()

        # FP guard #1: string literal key
        if key_expr and key_expr[0] in ('"', "'", '`'):
            continue

        # FP guard #2: numeric literal key
        if key_expr.isdigit():
            continue

        # FP guard #3: loop index variable names
        if _LOOP_INDEX_NAMES.match(key_expr):
            continue

        # FP guard #4: safe object names (map, cache, store, etc.)
        if _SAFE_OBJ_NAMES.search(obj_expr):
            continue

        # Build 15-line lookback window
        window_start = max(0, i - 16)
        window = '\n'.join(lines[window_start:i])

        # FP guard #5: hasOwnProperty check nearby
        if _HAS_OWN_PROP.search(window):
            continue

        # FP guard #6: allowlist check (includes/has/ALLOW) in lookback
        if _ALLOWLIST_CHECK.search(window):
            continue

        # FP guard #7: null-prototype object in lookback
        if _NULL_PROTO.search(window):
            continue

        # FP guard #8: Map/Set target in lookback
        if _MAP_SET_NEW.search(window):
            # Only skip if the map/set variable name matches the obj being assigned
            map_m = re.search(r'(?:const|let|var)\s+(\w+)\s*=\s*new\s+(?:Map|Set)\s*\(', window)
            if map_m and map_m.group(1) == obj_expr.split('.')[0]:
                continue

        # FP guard #9: TypeScript typed object (non-any, non-Record, non-index-sig)
        for ts_m in _TS_TYPED_OBJ.finditer(window):
            ts_var = ts_m.group(1)
            ts_type = ts_m.group(2)
            if ts_var == obj_expr.split('.')[0]:
                # If type doesn't contain any/Record/[, skip
                if not re.search(r'any|Record|Partial|Required|\[', ts_type):
                    break
        else:
            ts_m = None  # no typed object found

        # Re-check: if we found a typed object and broke (safe), skip
        # We need to restructure: use a flag
        is_ts_safe = False
        for ts_m in _TS_TYPED_OBJ.finditer(window):
            ts_var = ts_m.group(1)
            ts_type = ts_m.group(2)
            if ts_var == obj_expr.split('.')[0]:
                if not re.search(r'any|Record|Partial|Required|\[', ts_type):
                    is_ts_safe = True
                    break
        if is_ts_safe:
            continue

        # Skip process.env and known safe receivers by full name
        if obj_expr in ('process.env', 'headers', 'res.headers', 'response.headers'):
            continue

        # Shape 1: key expression IS a direct request taint (req.params.*, etc.)
        if _REQ_KEY_TAINT.match(key_expr):
            tainted = True
        elif _USER_INPUT_VARS.search(window):
            # Shape 2: variable key traced to req.* / request.* in lookback
            tainted = True
        else:
            # Shape 3: function parameter key — only fire if function signature
            # contains request-handler parameters (req, request, ctx, context)
            # to avoid flagging internal library utility functions.
            has_request_handler_sig = bool(re.search(
                r'function\s*\w*\s*\([^)]*\b(req|request|ctx|context)\b',
                window
            ))
            tainted = has_request_handler_sig and _has_taint(window)

        if not tainted:
            continue

        findings.append(_match(
            rule_id="PRBL-I005",
            vuln_class="prototype_pollution",
            line_number=i,
            line=stripped,
            title="Prototype pollution: bracket assignment with tainted key",
            detail=(
                "An externally-controlled key is used in a bracket assignment (`obj[key] = value`). "
                "If the key is `__proto__`, `constructor`, or `prototype`, the assignment modifies "
                "Object.prototype — affecting every object in the process. This is prototype pollution "
                "(CWE-1321). Real-world exploits have bypassed auth, injected properties, and achieved "
                "RCE via this pattern (lodash, mongoose, express)."
            ),
            fix=(
                "Option A — Allowlist: `if (ALLOWED_KEYS.has(key)) { obj[key] = value; }`. "
                "Option B — Use Map: `const map = new Map(); map.set(key, value);`. "
                "Option C — Null-prototype: `const safe = Object.create(null); safe[key] = value;`. "
                "Option D — Sanitize key: reject '__proto__', 'constructor', 'prototype'."
            ),
            severity="high",
        ))

    return findings


def check_path_traversal(lines: list[str], language: str, file_path: str = "") -> list[RuleMatch]:
    # Python packaging scripts (setup.py, pyproject.toml) read their own source tree
    # using os.path.join with hard-coded package names — never user-controlled paths.
    # Flagging these creates noise and trains developers to dismiss T001 findings.
    if file_path and _T001_PACKAGING_FILES.search(file_path):
        return []

    findings = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(('#', '//', '*')):
            continue
        if not _PATH_SINKS.search(line):
            continue
        if not _PATH_TAINT_ON_LINE.search(line):
            continue
        window = '\n'.join(lines[max(0, i - 6):min(len(lines), i + 6)])
        if not _has_taint(window):
            continue
        if _PATH_SANITIZED.search(window):
            continue
        findings.append(_match(
            rule_id="PRBL-T001",
            vuln_class="path_traversal",
            line_number=i,
            line=stripped,
            title="Path traversal: user input in filesystem path",
            detail=(
                "A user-controlled value is used to build a filesystem path. "
                "Input like '../../etc/passwd' or '..\\\\..\\\\.env' escapes the intended "
                "directory and reads (or overwrites) arbitrary files — including your "
                ".env file with every secret in it."
            ),
            fix=(
                "Resolve the final path and verify it stays inside the allowed directory: "
                "`const p = path.resolve(base, name); if (!p.startsWith(base + path.sep)) throw ...` "
                "— or use path.basename()/secure_filename() to strip directory components."
            ),
            severity="high",
        ))
    return findings



# ── 8. JWT DECODED WITHOUT SIGNATURE VERIFICATION (PRBL-A002) ────────────────

# JS: jsonwebtoken library import signal
_JWT_IMPORT_JS = re.compile(
    r'(?i)(require\s*\(\s*["\']jsonwebtoken["\']\s*\)|'
    r'from\s+["\']jsonwebtoken["\']\s*import|'
    r'import\s+.+\s+from\s+["\']jsonwebtoken["\'])',
)

# JS: jwt.decode() call (the unsafe one in jsonwebtoken)
_JWT_DECODE_JS = re.compile(r'(?i)\bjwt\.decode\s*\(')

# JS: jwt.verify() call (the safe one — if present in file, suppress)
_JWT_VERIFY_JS = re.compile(r'(?i)\bjwt\.verify\s*\(')

# Python: unsafe jwt.decode forms — explicit bypass flags
_JWT_DECODE_PY_UNSAFE = re.compile(
    r'(?i)jwt\.decode\s*\([^)]*(?:'
    r'verify_signature["\'\s]*:\s*False|'
    r'algorithms\s*=\s*\[["\']none["\']\]'
    r')',
)

# Python: jwt.decode() with exactly one positional arg (the token) — no key
_JWT_DECODE_PY_NO_KEY = re.compile(
    r'(?i)\bjwt\.decode\s*\(\s*\w+\s*\)',
)


def check_jwt_no_verify(lines: list, language: str, file_path: str = '') -> list:
    findings = []
    code = '\n'.join(lines)

    if language in ('javascript', 'typescript'):
        # Only check files that import jsonwebtoken
        if not _JWT_IMPORT_JS.search(code):
            return findings
        # If jwt.verify() is present anywhere in the file, suppress —
        # the developer may be using decode() for inspection only alongside a verify path.
        if _JWT_VERIFY_JS.search(code):
            return findings
        # Flag each jwt.decode() call
        for i, line in enumerate(lines, 1):
            if _JWT_DECODE_JS.search(line):
                findings.append(_match(
                    "PRBL-A002",
                    vuln_class="insecure-jwt",
                    line_number=i,
                    line=line.rstrip(),
                    title="JWT decoded without signature verification",
                    detail=(
                        "jwt.decode() in jsonwebtoken never verifies the signature — "
                        "use jwt.verify(token, secret, { algorithms: ['HS256'] }) instead. "
                        "An attacker can forge any JWT payload and bypass authentication entirely."
                    ),
                    fix="Replace jwt.decode() with jwt.verify(token, secret, { algorithms: ['HS256'] })",
                    severity="high",
                ))

    elif language == 'python':
        for i, line in enumerate(lines, 1):
            if _JWT_DECODE_PY_UNSAFE.search(line) or _JWT_DECODE_PY_NO_KEY.search(line):
                findings.append(_match(
                    "PRBL-A002",
                    vuln_class="insecure-jwt",
                    line_number=i,
                    line=line.rstrip(),
                    title="JWT decoded without signature verification",
                    detail=(
                        "jwt.decode() called without signature verification. "
                        "Use jwt.decode(token, secret, algorithms=['HS256']) to verify the signature. "
                        "An attacker can forge any JWT payload and bypass authentication entirely."
                    ),
                    fix="Add the signing key and algorithms parameter: jwt.decode(token, SECRET, algorithms=['HS256'])",
                    severity="high",
                ))

    return findings


# ── 9. TLS/CERTIFICATE VERIFICATION DISABLED (PRBL-C003) ─────────────────────

_TLS_REJECT_UNAUTH_JS = re.compile(
    r'rejectUnauthorized\s*[=:]\s*false',
)
_TLS_NODE_REJECT_ENV_JS = re.compile(
    r'NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*["\']?0["\']?',
)
_TLS_VERIFY_FALSE_PY = re.compile(
    r'(?i)requests\.\w+\s*\([^)]*verify\s*=\s*False',
)
_TLS_VERIFY_SESSION_PY = re.compile(
    r'(?i)\.verify\s*=\s*False',
)
_TLS_SSL_UNVERIFIED_PY = re.compile(
    r'(?i)ssl\._create_unverified_context\s*\(\s*\)',
)
_TLS_SSL_CERT_NONE_PY = re.compile(
    r'(?i)ssl\.CERT_NONE\b',
)
_TLS_DEV_GUARD = re.compile(
    r'(?i)('
    # JS: checking for dev/test environment (safe direction)
    r'NODE_ENV\s*[!=]=+\s*["\'](?:development|dev|test|staging)["\']|'
    r'NODE_ENV\s*!==?\s*["\']production["\']|'       # !== 'production' = safe
    r'process\.env\.NODE_ENV\s*!==?\s*["\']production["\']|'
    # JS: checking dev flag
    r'if\s*\(\s*(?:dev|isDev|isDevMode|development)\s*[\)&|]|'
    r'isDevelopment\s*&&|'
    r'isTest\s*&&|'
    # Python: dev/debug flags
    r'if\s+DEBUG\s*:|'
    r'if\s+settings\.DEBUG\s*:|'
    r'if\s+app\.debug\s*:|'
    r'if\s+os\.getenv\(["\']DEBUG["\']|'
    r'if\s+os\.environ\.get\(["\']DEBUG["\']'
    r')',
)


def check_tls_disabled(lines, language, file_path=''):
    if _is_test_file(file_path):
        return []
    findings = []

    for i, line in enumerate(lines):
        stripped_line = line.strip()
        if stripped_line.startswith(('#', '//', '*')):
            continue
        matched = False
        title = "TLS certificate verification disabled"
        detail = (
            "TLS certificate verification is disabled, enabling man-in-the-middle attacks. "
            "An attacker on the network can intercept and modify traffic to/from this connection."
        )
        fix_js = (
            "Remove rejectUnauthorized: false (the default is true). "
            "If using a self-signed certificate, add the CA certificate instead: "
            "new https.Agent({ ca: fs.readFileSync('ca.crt') })"
        )
        fix_py = (
            "Remove verify=False and use ssl.create_default_context() instead. "
            "If using a self-signed cert, add it: ssl.create_default_context(cafile='ca.crt')"
        )
        fix = fix_js

        if language in ('javascript', 'typescript'):
            if _TLS_REJECT_UNAUTH_JS.search(line):
                matched = True
                fix = fix_js
            elif _TLS_NODE_REJECT_ENV_JS.search(line):
                matched = True
                fix = fix_js
                detail = (
                    "NODE_TLS_REJECT_UNAUTHORIZED=0 disables certificate verification globally "
                    "for all HTTPS connections in this process, enabling MITM attacks."
                )
        elif language == 'python':
            if (_TLS_VERIFY_FALSE_PY.search(line) or
                    _TLS_VERIFY_SESSION_PY.search(line) or
                    _TLS_SSL_UNVERIFIED_PY.search(line) or
                    _TLS_SSL_CERT_NONE_PY.search(line)):
                matched = True
                fix = fix_py

        if not matched:
            continue

        # Check 5-line window for dev-only guard (2 before + 2 after)
        window_start = max(0, i - 2)
        window_end = min(len(lines), i + 3)
        window = '\n'.join(lines[window_start:window_end])

        severity = "high"
        if _TLS_DEV_GUARD.search(window):
            severity = "low"
            detail += (" — NOTE: appears to be disabled only in development; "
                       "verify this guard is correct before deploying to production.")

        findings.append(_match(
            "PRBL-C003",
            vuln_class="tls-verification-disabled",
            line_number=i + 1,
            line=line.rstrip(),
            title=title,
            detail=detail,
            fix=fix,
            severity=severity,
        ))

    return findings


# ── Minified-file detection ───────────────────────────────────────────────────

def _is_minified_file(file_path: str, code: str) -> bool:
    """Return True if the file is a minified or bundled output that should be skipped."""
    if file_path.endswith(('.min.js', '.min.css', '.min.ts')):
        return True
    # Compiled/dist/build output directories — even when line-wrapped, these are
    # generated artifacts not authored code. Covers: packages/next/src/compiled/,
    # dist/, build/, .next/, __pycache__/, etc.
    fp_normalized = file_path.replace('\\', '/')
    if any(f'/{seg}/' in fp_normalized for seg in ('compiled', 'dist', 'build', '.next', '__pycache__')):
        return True
    # Any single line over 500 chars → treat as minified/bundled
    return any(len(line) > 500 for line in code.splitlines())


# ── Test-file detection ───────────────────────────────────────────────────────

# Directory components that mark a file as test scaffolding
_TEST_DIRS = {"test", "tests", "testing", "spec", "specs", "__tests__", "__mocks__", "playwright", "e2e", "benchmark", "benchmarks", "bench", "example", "examples", "seed", "seeds", "seeders", "seed-data", "fixtures", "fixture", "factory", "factories", "fakers", "faker", "vendor", "vendors", "upstream", "third_party", "third-party", "extern", "external", "externals", "thirdparty"}

# Filename patterns that mark a file as a test (stem checks, not substring)
_TEST_FILENAME = re.compile(
    r'^(test_.+|.+_test|.+\.spec|.+\.test|.+\.e2e|.+\.e2e-spec|runtests|run_tests|seed|seed-.+)$',
    re.IGNORECASE,
)


def _is_test_file(file_path: str) -> bool:
    """
    Return True only for files that are clearly test scaffolding:
      - Any path component (directory name) is exactly: test, tests, testing, spec, specs
      - Filename stem matches: test_*, *_test, *.spec, *.test
    A file named contest.py or latest.py is NOT a test file.
    """
    if not file_path:
        return False
    path = Path(file_path)
    # Check each directory component for exact test-dir names
    for part in path.parts[:-1]:  # exclude the filename itself
        if part.lower() in _TEST_DIRS:
            return True
    # Check the filename stem
    stem = path.stem
    if _TEST_FILENAME.match(stem):
        return True
    return False


# ── DISPATCH ──────────────────────────────────────────────────────────────────

_VENDOR_DIRS = {"vendor", "vendors", "upstream", "third_party", "third-party", "extern", "external", "externals", "thirdparty"}


def _is_vendor_file(file_path: str) -> bool:
    """Return True if any directory component of the path is a known vendor/upstream dir."""
    if not file_path:
        return False
    path = Path(file_path)
    for part in path.parts[:-1]:
        if part.lower() in _VENDOR_DIRS:
            return True
    return False


def run_all_rules(code: str, language: str, file_path: str = "") -> list[RuleMatch]:
    # Fix 1: Skip minified/bundled files entirely
    if _is_minified_file(file_path, code):
        return []

    # Skip vendored/upstream source trees entirely — third-party code is not
    # the developer's responsibility and generates high noise volumes.
    if _is_vendor_file(file_path):
        return []

    # Skip Prbl's own rewriter prompt-template module entirely. This file's sole
    # purpose is to hold "Before:"/"After:" vulnerability examples for every rule
    # (TLS verification disabled, JWT decode without verify, hardcoded secrets,
    # SQL injection, etc.) so the AI rewriter knows what each fix looks like. It
    # is documentation-as-prompt-text, not application code — every line will
    # superficially match the exact patterns these rules look for, by design.
    if file_path and Path(file_path.replace('\\', '/')).as_posix().endswith("rewriter/prompt.py"):
        return []

    lines = code.splitlines()
    findings = []

    is_test = _is_test_file(file_path)
    is_demo = file_path and any(p in file_path.lower() for p in _DEMO_CONTENT_PATHS)

    # PRBL-C001: skip hardcoded credential findings in test/spec files.
    # password='Secure123' in tests/test_views.py is a test fixture, not a
    # production secret. Seed scripts and management commands are NOT test
    # files and remain in scope.
    if not is_test:
        cred_findings = check_hardcoded_credentials(lines)
        if is_demo:
            # Demo/animation/marketing files: downgrade PRBL-C001 to LOW instead of skipping.
            # If a string here is a real credential used in app logic elsewhere, it still
            # needs to be addressed there — but flagging it HIGH in a Remotion animation is noise.
            for m in cred_findings:
                if m.rule_id == "PRBL-C001":
                    m.severity = "low"
                    m.detail = (
                        "This file appears to be demo, marketing, or animation content. "
                        "If this string is a real credential used in application logic elsewhere, "
                        "it should still be addressed there."
                    )
        findings += cred_findings
    else:
        # Still catch real credential formats (AWS keys, Stripe live keys,
        # hardcoded JWTs) even in test files — those are always wrong.
        # Exception: example/examples directories contain intentionally demo
        # credentials (supabase anon keys, tutorial JWTs) — skip the passthrough
        # entirely for those dirs.
        fp_parts_lower = {p.lower() for p in Path(file_path).parts[:-1]} if file_path else set()
        if not (fp_parts_lower & {"example", "examples"}):
            creds = check_hardcoded_credentials(lines)
            findings += [
                m for m in creds
                if m.rule_id == "PRBL-C001"
                and any(sig in m.line for sig in ("AKIA", "sk_live_", "rk_live_", "eyJ", "ghp_", "github_pat_"))
            ]

    fp_lower = file_path.replace('\\', '/').lower() if file_path else ''
    is_benchmark = any(f'/{seg}/' in fp_lower for seg in ('benchmark', 'benchmarks', 'bench'))

    weak_rand = check_weak_randomness(lines, language)
    if is_benchmark:
        # Benchmark files use Math.random() / random.* for perf simulation — not security.
        # These are intentional low-entropy values in performance test fixtures; suppressing
        # them avoids noise on timing-sensitive benchmark data generators.
        weak_rand = [f for f in weak_rand if f.rule_id != "PRBL-R001"]
    findings += weak_rand
    findings += check_timing_comparison(lines, language)
    findings += check_aes_gcm_auth_tag(lines, language, file_path=file_path)
    findings += check_jwt_no_verify(lines, language, file_path=file_path)
    findings += check_tls_disabled(lines, language, file_path=file_path)
    injection_findings = check_injection(lines, language)
    if is_benchmark:
        # Benchmark directories: suppress I003 (eval/exec in benchmark runners is not
        # user-controlled execution — it runs controlled performance payloads).
        injection_findings = [f for f in injection_findings if f.rule_id != "PRBL-I003"]
    if is_test:
        # Test runner scripts (runtests.py, run_tests.py) that call subprocess with
        # sys.argv[1:] are forwarding developer CLI args to known tools (flake8, pytest).
        # This pattern fires I002 but is not injection — the operator controls sys.argv.
        injection_findings = [f for f in injection_findings if f.rule_id != "PRBL-I002"]
    findings += injection_findings
    findings += check_nosql_injection(lines, language)
    findings += check_prototype_pollution(lines, language, file_path=file_path)
    findings += check_path_traversal(lines, language, file_path)

    # PRBL-C002: session secrets follow the same test-file policy as PRBL-C001
    if not is_test:
        findings += check_session_secret(lines, language)

    # PRBL-A001: skip entirely for test/spec files — test scaffolding routes
    # are not production endpoints and generate noise, not signal.
    if not is_test:
        a001 = check_missing_access_control(lines, language, file_path)
        # Deduplicate: report at most 1 finding per file.
        # Multiple route handlers in the same file represent the same pattern —
        # the developer needs to add middleware at the router level, not fix
        # each handler individually. Reporting 7x the same medium finding from
        # one file inflates counts without adding information.
        if a001:
            findings.append(a001[0])

    return findings


def _file_has_auth_model(code: str) -> bool:
    """
    Fix 2: Return True if this file contains any route handler with auth indicators.
    Used for repo-level A001 suppression: if ZERO files in a repo have auth,
    the repo has no auth model at all and A001 findings are suppressed.
    """
    return bool(_AUTH_INDICATORS.search(code))


def filter_a001_if_no_repo_auth(all_file_findings: list, all_file_codes: list[str]) -> list:
    """
    Fix 2: Post-processing step. If zero files in the repo have any auth indicators,
    suppress all PRBL-A001 findings — the repo has no auth model at all
    (e.g. TodoMVC, demo apps, Astro marketing sites).

    Parameters
    ----------
    all_file_findings : list of list[RuleMatch]
        Per-file rule match results (as returned by run_all_rules).
    all_file_codes : list of str
        Raw code content of each file (same order as all_file_findings).
    """
    repo_has_auth = any(_file_has_auth_model(code) for code in all_file_codes)
    if repo_has_auth:
        return all_file_findings
    # No auth anywhere in the repo — drop all A001 findings
    filtered = []
    for file_findings in all_file_findings:
        filtered.append([f for f in file_findings if f.rule_id != "PRBL-A001"])
    return filtered
