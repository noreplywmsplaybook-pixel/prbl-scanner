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
    severity: str  # "high" | "medium" | "low"


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

# Safe variable name — if the *left side* of the assignment contains placeholder
# language the value is intentionally fake. Check only the variable name, not the
# value — "AKIAIOSFODNN7EXAMPLE" contains "example" but it's a real key format.
_CRED_SAFE_VARNAME = re.compile(
    r'(?i)^[^=:]*?(placeholder|example[_\s]|your[_-]|dummy|fake|sample|test[_-]key|demo)',
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

        # ── Fallback secret check ─────────────────────────────────────────────
        # Must run BEFORE the _CRED_SAFE_CONTEXT guard, because fallback lines
        # intentionally contain process.env / os.environ and would otherwise be
        # whitelisted. These patterns are unambiguous enough not to need the guard.
        fallback_found = False
        for regex in (_FALLBACK_JS, _FALLBACK_PY):
            m = regex.search(line)
            if not m:
                continue
            # _FALLBACK_PY now captures (env_var_name, fallback_value)
            # _FALLBACK_JS captures only (fallback_value) — env var in the expression itself
            if regex is _FALLBACK_PY:
                env_var_name = m.group(1)
                fallback_value = m.group(2).strip()
                # Only flag if the env var name looks like a credential
                if not _CRED_VAR_NAME.search(env_var_name):
                    continue
            else:
                fallback_value = m.group(1).strip()
                # For JS, check the full expression for credential var names
                if not _CRED_VAR_NAME.search(line):
                    continue
            if _FALLBACK_SAFE_VALUE.match(fallback_value):
                continue  # empty / boolean / numeric / algorithm — not a secret
            findings.append(RuleMatch(
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
        for pattern, description in _CRED_PATTERNS:
            if re.search(pattern, line):
                # Check each string value on the line — if it looks like a UI
                # validation message rather than a secret, skip it.
                string_values = _STRING_VALUE.findall(line)
                if any(_CRED_VALIDATION_MSG.search(v) for v in string_values):
                    break
                findings.append(RuleMatch(
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
    # Python
    (r'\brandom\.random\(\)', "random.random()"),
    (r'\brandom\.randint\(', "random.randint()"),
    (r'\brandom\.choice\(', "random.choice()"),
    (r'\brandom\.uniform\(', "random.uniform()"),
    (r'\brandom\.shuffle\(', "random.shuffle()"),
    (r'\brandom\.sample\(', "random.sample()"),
]

_WEAK_RANDOM_SECURITY_CONTEXT = re.compile(
    r'(?i)(token|secret|password|session|nonce|otp|pin|csrf|api_key|auth_key|salt|uuid|'
    r'reset_code|verify_code|access_token|refresh_token)',
)

# NOTE: do NOT add bare "sample" here — it collides with random.sample() the function.
# "sample" would silently skip `password = random.sample(chars, 12)` which is a real finding.
# Use compound forms like "sample_data" or "sample_value" if you need to cover demo fixtures.
_WEAK_RANDOM_SAFE_CONTEXT = re.compile(
    r'(?i)(test|spec|mock|sample_data|sample_value|demo|example|game|color|shuffle.*display|animation)',
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
                    if not _WEAK_RANDOM_SECURITY_CONTEXT.search(var_name):
                        continue  # suppress — React key, not a secret

                # Check surrounding 5 lines for security context
                window_start = max(0, i - 3)
                window_end = min(len(lines), i + 2)
                window = '\n'.join(lines[window_start:window_end])
                if not _WEAK_RANDOM_SECURITY_CONTEXT.search(window):
                    continue
                fix_js = "Use crypto.randomBytes(32).toString('hex') or crypto.randomUUID()"
                fix_py = "Use secrets.token_hex(32) or secrets.token_urlsafe(32)"
                fix = fix_py if language == "python" else fix_js
                findings.append(RuleMatch(
                    rule_id="PRBL-R001",
                    vuln_class="weak_randomness",
                    line_number=i,
                    line=stripped,
                    title=f"Weak randomness for security-sensitive value: {fn_name}",
                    detail=(
                        f"{fn_name} is not cryptographically secure. Its output is predictable — "
                        "an attacker who observes a few values can reconstruct the internal state "
                        "and predict all future outputs, including tokens and session IDs."
                    ),
                    fix=fix,
                    severity="high",
                ))
                break
    return findings


# ── 3. INJECTION PATTERNS ─────────────────────────────────────────────────────

_USER_INPUT_VARS = re.compile(
    r'(?i)(req\.(body|query|params|headers)|request\.(args|form|json|data|values|get_json)|'
    r'sys\.argv|os\.environ|getenv|input\(|flask\.request|django.*request)',
)

_FN_SIG = re.compile(r'\bdef\s+\w+\s*\(([^)]+)\)')


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
    return False

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
    # Single-line: JS template literal with SQL keyword.
    # \b word boundaries required — prevents matching substrings like LAST_SELECTED_FEED
    # (which contains "SELECT") or "UPDATED_AT" (which contains "UPDATE").
    r'(?i)["\'\`].*\$\{.*\b(SELECT|INSERT|UPDATE|DELETE)\b',
    r'(?i)`\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b.*\$\{',
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
    r'|knex|sequelize|prisma|mongoose|typeorm|pg\.|mysql' # ORM/driver names
    r'|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b'     # SQL keywords (word-bounded)
    r'|\bFROM\b|\bWHERE\b|\bJOIN\b|\bINTO\b'
    r')'
)

_CMD_INJECTION_PATTERNS = [
    r'(?i)(exec|spawn|system|popen|subprocess\.call|subprocess\.run|os\.system)\s*\([^)]*\+',
    r'(?i)(exec|spawn)\s*\(`[^`]*\$\{',
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
]


_INJECTION_SAFE_CONTEXT = re.compile(
    r'(?i)^\s*(print\s*\(|console\.(log|warn|error|info|debug)\s*\('
    r'|log(?:ger)?\.(debug|info|warning|warn|error|critical|exception)\s*\('
    r'|logging\.(debug|info|warning|warn|error|critical|exception)\s*\('
    r'|raise\s+\w*Error\s*\(|raise\s+\w*Exception\s*\('
    r'|assert\s+)',
)


def check_injection(lines: list[str], language: str) -> list[RuleMatch]:
    findings = []
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
                if _has_taint(window):
                    findings.append(RuleMatch(
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

        # Command injection
        for pattern in _CMD_INJECTION_PATTERNS:
            if re.search(pattern, line):
                window_start = max(0, i - 5)
                window_end = min(len(lines), i + 5)
                window = '\n'.join(lines[window_start:window_end])
                if _has_taint(window):
                    findings.append(RuleMatch(
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
                window_start = max(0, i - 5)
                window_end = min(len(lines), i + 5)
                window = '\n'.join(lines[window_start:window_end])
                if _has_taint(window):
                    findings.append(RuleMatch(
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

_ROUTE_PATTERNS = {
    "javascript": [
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
    r'@Public\b|IsPublic\b|SkipAuth\b|AllowAnonymous\b)',
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
    r'''|/?["\')]'''               # bare root: "/" alone or empty path
    r''')''',
    re.IGNORECASE,
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
                handler_line_str = lines[handler_line - 1].strip()
                findings.append(RuleMatch(
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
            bool(_AUTH_INDICATORS.search(lookback_text))
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
            else:
                sev = "medium"
                detail = (
                    "This route performs a sensitive operation (database access, user data, "
                    "or financial action) with no visible authentication or authorization check. "
                    "Any unauthenticated caller can access it — IDOR attacks work by simply "
                    "changing an ID parameter in the URL."
                )
                fix = "Add authentication middleware and verify the caller is authorized to access the specific resource (not just logged in)."

            findings.append(RuleMatch(
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


# ── Test-file detection ───────────────────────────────────────────────────────

# Directory components that mark a file as test scaffolding
_TEST_DIRS = {"test", "tests", "testing", "spec", "specs"}

# Filename patterns that mark a file as a test (stem checks, not substring)
_TEST_FILENAME = re.compile(
    r'^(test_.+|.+_test|.+\.spec|.+\.test)$',
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

def run_all_rules(code: str, language: str, file_path: str = "") -> list[RuleMatch]:
    lines = code.splitlines()
    findings = []

    is_test = _is_test_file(file_path)

    # PRBL-C001: skip hardcoded credential findings in test/spec files.
    # password='Secure123' in tests/test_views.py is a test fixture, not a
    # production secret. Seed scripts and management commands are NOT test
    # files and remain in scope.
    if not is_test:
        findings += check_hardcoded_credentials(lines)
    else:
        # Still catch real credential formats (AWS keys, Stripe live keys,
        # hardcoded JWTs) even in test files — those are always wrong.
        creds = check_hardcoded_credentials(lines)
        findings += [
            m for m in creds
            if m.rule_id == "PRBL-C001"
            and any(sig in m.line for sig in ("AKIA", "sk_live_", "rk_live_", "eyJ", "ghp_", "github_pat_"))
        ]

    findings += check_weak_randomness(lines, language)
    findings += check_injection(lines, language)

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
