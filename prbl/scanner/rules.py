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
    "PRBL-R001": ("CWE-338",    "A04 — Cryptographic Failures",  4),
    "PRBL-I001": ("CWE-89",     "A05 — Injection",               5),
    "PRBL-I002": ("CWE-78",     "A05 — Injection",               5),
    "PRBL-I003": ("CWE-94/95",  "A05 — Injection",               5),
    "PRBL-A001": ("CWE-862",    "A01 — Broken Access Control",   1),
    "PRBL-P001": ("Emerging — no CWE", "A03 — Supply Chain Failures", 3),
    "PRBL-I004": ("CWE-943",    "A05 — Injection",               5),
    "PRBL-C002": ("CWE-798",    "A07 — Authentication Failures", 7),
    "PRBL-T001": ("CWE-22",     "A01 — Broken Access Control",   1),
    "PRBL-R002": ("CWE-208",    "A02 — Cryptographic Failures",  2),
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
                    if not _WEAK_RANDOM_SECURITY_CONTEXT.search(var_name):
                        continue  # suppress — React key, not a secret

                # Exclusion: crypto API availability guard — Math.random() used only
                # when window.crypto / globalThis.crypto is unavailable (old browsers).
                window_start = max(0, i - 3)
                window_end = min(len(lines), i + 2)
                window = '\n'.join(lines[window_start:window_end])
                if any(p.search(window) for p in _CRYPTO_FALLBACK_PATTERNS):
                    continue

                if not _WEAK_RANDOM_SECURITY_CONTEXT.search(window):
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
_TIMING_WEBHOOK_VARS = re.compile(
    r'(?i)\b(verification_token|webhook_secret|webhook_token|expected_signature|'
    r'computed_signature|x_hub_signature|x_signature|hmac_signature|'
    r'open_verification_token|signature_token|api_signature|request_signature|'
    r'callback_token|hook_secret|hook_token)\b'
)
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
                r'(?:' + _TIMING_WEBHOOK_VARS.pattern + r')\s*(?:===|!==|==|!=)\s*["\']'
                r'|["\']s*(?:===|!==|==|!=)\s*(?:' + _TIMING_WEBHOOK_VARS.pattern + r')',
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
                window_start = max(0, i - 5)
                window_end = min(len(lines), i + 5)
                window = '\n'.join(lines[window_start:window_end])
                if _has_taint(window):
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



# ── Minified-file detection ───────────────────────────────────────────────────

def _is_minified_file(file_path: str, code: str) -> bool:
    """Return True if the file is a minified or bundled output that should be skipped."""
    if file_path.endswith(('.min.js', '.min.css', '.min.ts')):
        return True
    # Any single line over 500 chars → treat as minified/bundled
    return any(len(line) > 500 for line in code.splitlines())


# ── Test-file detection ───────────────────────────────────────────────────────

# Directory components that mark a file as test scaffolding
_TEST_DIRS = {"test", "tests", "testing", "spec", "specs", "__tests__", "__mocks__", "playwright", "e2e", "benchmark", "benchmarks", "bench", "example", "examples", "seed", "seeds"}

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

def run_all_rules(code: str, language: str, file_path: str = "") -> list[RuleMatch]:
    # Fix 1: Skip minified/bundled files entirely
    if _is_minified_file(file_path, code):
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
