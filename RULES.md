# Prbl Scanner — Rule Reference

This document explains every detection rule in the Prbl static analysis engine. All rules are regex-based, run fully offline, and produce no network calls.

---

## How the scanner works

For each file it receives, the scanner:

1. Detects the language (Python, JavaScript, TypeScript) from the file extension.
2. Skips the file entirely if it is a test/spec file (see [Test file policy](#test-file-policy)).
3. Runs each rule against the file's lines.
4. Returns a list of findings, each with a rule ID, severity, location, explanation, and fix.

Findings are deduplicated where noted — for example, PRBL-A001 reports at most one finding per file to avoid flooding a report with the same pattern repeated across many routes.

---

## Rules

### PRBL-C001 — Hardcoded Credential

**CWE-798 · OWASP A07 — Authentication Failures**

Detects secrets written directly into source code. There are three distinct sub-patterns:

#### 1. Raw hardcoded assignment

Looks for assignments where a variable with a credential-sounding name is assigned a string literal value. Examples:

```python
password = "hunter2"
api_key = "sk-abc123..."
auth_token = "eyJ..."
```

Recognized variable names: `password`, `passwd`, `pwd`, `secret`, `api_key`, `apikey`, `auth_token`, `access_token`, `private_key`.

Also matches well-known credential formats regardless of variable name:
- Stripe live secret keys (`sk_live_...`)
- Stripe restricted keys (`rk_live_...`)
- AWS access key IDs (`AKIA...`)
- AWS secret access keys
- GitHub personal access tokens (`ghp_...`)
- GitHub fine-grained PATs (`github_pat_...`)
- Hardcoded hex tokens/keys (32+ hex characters in a `token`, `key`, or `secret` variable)
- Hardcoded JWTs (three base64url segments)

**Safe contexts (not flagged):**
- Any line containing `process.env`, `os.environ`, `getenv`, `config[`, `secrets.`, `vault.`, `<`, `>`, or `${` — the value comes from config, not source.
- Variable name contains placeholder language: `placeholder`, `your-`, `dummy`, `fake`, `sample`, `demo`, `example_`.
- String value looks like a UI validation message ("is required", "must be", "please enter", etc.).
- The canonical jwt.io example JWT (`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`) — appears in every tutorial.
- Swagger/OpenAPI `example:` fields and `@ApiProperty` decorators — documentation, not live credentials.

#### 2. Fallback secret in env-var lookup

Detects the AI-generated antipattern where a working fallback value is provided for a missing environment variable:

```javascript
// JS/TS
const secret = process.env.JWT_SECRET || 'my-secret-key'
const secret = process.env.JWT_SECRET ?? 'my-secret-key'
```

```python
# Python
secret = os.environ.get('JWT_SECRET', 'my-secret-key')
secret = os.getenv('JWT_SECRET', 'my-secret-key')
```

This is the most common AI-generated credential mistake. The app works locally, the developer ships it, and every deployment that doesn't explicitly set the environment variable gets a known, predictable production secret.

Only flagged when the environment variable name itself sounds like a credential (same list as above). Non-credential variables like `LOG_LEVEL`, `DB_HOST`, `PORT` are not flagged.

Fallback values that are clearly not secrets are excluded: `None`, `null`, `true`/`false`, plain integers, URLs, localhost addresses, JWT algorithm names (`HS256`, etc.), hash algorithm names, SQLite paths, log level names, TTL durations (`15m`, `7d`), and common placeholder phrases (`your-secret-here`, `change-me`, etc.).

**Severity:** HIGH for raw credentials, MEDIUM for fallback secrets.

#### Demo/marketing content downgrade

Files in demo, animation, or marketing paths have PRBL-C001 findings downgraded to **LOW** instead of being skipped. The finding message explains the context and notes that if the string is a real credential used in application logic elsewhere, it still needs to be addressed there.

Affected paths (case-insensitive): `remotion/`, files named `HeroAnimation`, `HeroScanner`, `HeroPlayer`, `/animations/`, `/demo/`, `/marketing/`, `/examples/`, `app/page.tsx` (landing page root), `pages/index.*`.

---

### PRBL-C002 — Hardcoded Session or Signing Secret

**CWE-798 · OWASP A07 — Authentication Failures**

Specifically targets secrets used to sign sessions, cookies, or JWTs — a distinct pattern from general credential detection because these use object-literal syntax (colon, not equals):

```javascript
// Express-session
session({ secret: 'my-hardcoded-secret' })

// JWT
jwt.sign(payload, 'my-hardcoded-secret')

// cookie-parser
cookieParser('my-hardcoded-secret')
```

```python
# Flask
app.secret_key = 'my-hardcoded-secret'
SECRET_KEY = 'my-hardcoded-secret'
```

Requires session/JWT context to be present on the line or within 5 lines above — avoids flagging unrelated object fields that happen to be named `secret`.

Anyone with read access to the repository can forge valid session cookies or JWTs for any user, achieving full account takeover with no other vulnerability required.

**Severity:** HIGH.

---

### PRBL-R001 — Weak Randomness

**CWE-338 · OWASP A04 — Cryptographic Failures**

Detects use of non-cryptographic random number generators in security-sensitive contexts:

**JavaScript/TypeScript:** `Math.random()`

**Python:** `random.random()`, `random.randint()`, `random.choice()`, `random.uniform()`, `random.shuffle()`, `random.sample()`

These functions are seeded from predictable system state. An attacker who observes a handful of outputs can reconstruct the internal state and predict all future values — including tokens, session IDs, and OTPs generated with the same RNG.

**Requires security context to flag** — a nearby variable or expression must reference: `token`, `secret`, `password`, `session`, `nonce`, `otp`, `pin`, `csrf`, `api_key`, `auth_key`, `salt`, `uuid`, `reset_code`, `verify_code`, `access_token`, or `refresh_token`. Random numbers used for display, game logic, or shuffling UI elements are not flagged.

**Safe contexts (not flagged):**
- Code inside `useState()` with a non-security variable name — a common React pattern for generating component keys to force remounts.
- Code where `crypto.randomUUID`, `crypto.getRandomValues`, `window.crypto`, or `globalThis.crypto` appears nearby — indicates a crypto API availability guard where `Math.random()` is only the fallback for old browsers.
- Lines/files containing `test`, `spec`, `mock`, `demo`, or `animation` context.

**Severity downgrade to LOW:**
- Analytics and tracking ID variables (`visitorId`, `trackingId`, `anonymousId`, etc.) — predictability is low-risk for telemetry.
- Draft or temporary context (`draft`, `temp`, `preview`, `cache_bust`) nearby.

**Severity:** HIGH (or LOW for analytics/tracking IDs).

---

### PRBL-I001 — SQL Injection

**CWE-89 · OWASP A05 — Injection**

Detects user-controlled input being concatenated or interpolated into SQL query strings.

**Patterns detected:**

```javascript
// String concatenation
"SELECT * FROM users WHERE id = " + userId

// Template literal
`SELECT * FROM users WHERE name = '${name}'`

// Query variable built from parts
let query = "SELECT "
query += "WHERE name = '" + name + "'"
```

```python
# f-string interpolation
f"SELECT * FROM users WHERE id = {user_id}"
f"INSERT INTO logs WHERE {condition}"
```

**Two-gate system:** A line only triggers a finding if both of the following are true:

1. **SQL context signal** — within 10 lines, there must be a database driver method (`.query()`, `.execute()`, `.prepare()`), a known ORM/driver name (knex, sequelize, prisma, typeorm, pg, mysql), or SQL keywords (SELECT, INSERT, WHERE, JOIN, etc.). This prevents false positives from template literals that build cache keys, state-management identifiers, or logging strings that happen to contain SQL keywords. Note: `mongoose` is intentionally excluded — it is a MongoDB/NoSQL driver and belongs to PRBL-I004's domain, not SQL injection.

2. **Taint source** — within 10 lines, user-controlled input must be traceable. This includes explicit web framework sources (`req.body`, `req.query`, `request.args`, `request.form`, etc.) or function parameters from the enclosing function signature that appear in the expression (catches library-style functions like `getUser(username)` where the caller controls the input).

**Safe contexts:**
- ORM tagged template literals (`sql\`...\``, `$queryRaw\`...\``, `drizzle.sql\`...\``) — these produce parameterized queries.
- Browser dialog methods (`confirm()`, `alert()`, `prompt()`) — never SQL sinks regardless of content.
- Logging and print statements.

**Severity:** HIGH.

---

### PRBL-I002 — Command Injection

**CWE-78 · OWASP A05 — Injection**

Detects user-controlled input passed to shell command execution functions.

**Patterns detected:**

```javascript
exec("ls " + userInput)
spawn(`rm -rf ${path}`)
```

```python
os.system("grep " + pattern)
subprocess.run("convert " + filename, shell=True)
subprocess.call(user_input + " --flag")
```

`shell=True` in Python subprocess calls is flagged only when user input is traceable in the surrounding 10-line window — `subprocess.run(['ls'], shell=True)` alone is bad practice but not injection without user-controlled data flowing in.

Uses the same taint-source logic as PRBL-I001.

**Severity:** HIGH.

---

### PRBL-I003 — Code Injection

**CWE-94/95 · OWASP A05 — Injection**

Detects user-controlled input passed to code evaluation functions. This gives an attacker full code execution on the server.

**Patterns detected:**

```javascript
eval(userInput)
new Function(userInput)
```

```python
eval(user_input)
exec(user_input)
__import__(user_input)
compile(user_input, ..., 'exec')
```

Method calls like `db.eval()` or `session.exec()` are excluded (negative lookbehind for `.`).

Uses the same taint-source logic as PRBL-I001.

**Severity:** HIGH.

---

### PRBL-I004 — NoSQL Injection

**CWE-943 · OWASP A05 — Injection**

Detects user-controlled input flowing directly into MongoDB query operators.

**Patterns detected:**

```javascript
// Direct object injection — bypasses auth checks with {'$gt': ''}
User.find(req.body)
collection.findOne(req.query)

// $where string interpolation — executes arbitrary JS inside MongoDB
{ $where: "this.name == '" + name + "'" }
{ $where: `this.id == ${id}` }

// mapReduce with interpolated JS
collection.mapReduce(`function() { return ${expr} }`)
```

Passing `req.body` or `req.query` directly into a MongoDB query operator position allows operator injection — the attacker supplies `{'$gt': ''}` to bypass equality checks, gaining unauthorized access.

Uses the same taint-source logic as PRBL-I001.

**Severity:** HIGH.

---

### PRBL-A001 — Missing Access Control

**CWE-862 · OWASP A01 — Broken Access Control**

Detects route handlers and serverless functions that perform sensitive operations without any visible authentication or authorization check.

**Sensitive operations that trigger concern:** database reads/writes (`.find`, `.findOne`, `.query`, `.filter`, `.update`, `.delete`, `.create`, `.save`, `.insert`), user data access (`user.*`, `password`, `email`), and financial operations (`stripe.`, `payment`, `charge`, `transfer`).

The rule runs differently depending on the file type:

#### Serverless handlers (Next.js App Router, Vercel, Netlify, AWS Lambda)

Matches export patterns like:

```typescript
export async function GET(req: NextRequest) { ... }
export async function POST(request: Request) { ... }
export default async function handler(req, res) { ... }
exports.handler = async function(event) { ... }
```

For these files, the entire file text is searched for auth indicators. If the file has a sensitive operation but no auth indicator anywhere, it is flagged. Additionally, the first 10 lines of the function body are checked for inline auth calls (see below).

#### Express / Flask / Django routes

Matches route declaration patterns and looks ahead 30 lines and back 60 lines (to the nearest class boundary) for auth indicators.

```javascript
app.get('/users', handler)
router.post('/payments', handler)
```

```python
@app.route('/admin', methods=['POST'])
@api_view(['GET'])
def get(self, request):
```

The route declaration line itself is also checked — Express middleware passed inline as a route argument is a common pattern:

```javascript
router.get('/profile', authMiddleware, getProfile)
router.delete('/:id', protect, deleteUser)
router.post('/data', auth, handler)  // bare 'auth' identifier
```

#### Auth indicators recognized

The scanner recognizes a wide range of authentication patterns across frameworks:

- **Decorators/middleware:** `@login_required`, `@jwt_required`, `@auth`, `@permission_required`, `@UseGuards`, `@Roles`, `@Public` (explicit opt-out), `@requires_auth`, `@authenticated`, `@protected`
- **FastAPI:** `Depends()`, `Security()`, `oauth2_scheme`, `get_current_active_user`, `HTTPBearer`, `HTTPBasic`
- **NestJS guards:** `JwtAuthGuard`, `AuthGuard`, `RolesGuard`, `AccessTokenGuard`, `ApiKeyGuard`
- **Express middleware names:** `protect`, `authMiddleware`, `verifyToken`, `requireLogin`, `ensureAuth`, `isAuth`, `tokenRequired`, `jwtMiddleware`, `authGuard`, `roleGuard`, `passportAuth`
- **Session/user checks:** `req.user`, `request.user`, `session[`, `current_user`, `get_current_user`, `getUser()`, `getUserId()`
- **DRF:** `permission_classes`, `authentication_classes`
- **Stripe webhooks:** `stripe.webhooks.constructEvent()` — signature verification is the correct auth mechanism for webhook endpoints
- **Inline auth calls** (first 10 lines of function body): `requireAuth()`, `requireUser()`, `requireSession()`, `requirePro()`, `requireAdmin()`, `getServerSession()`, `getSession()`, `auth()`, `verifySession()`, `checkAuth()`, `authenticate()`, `getCurrentUser()`, `requireApiKey()`

#### Intentionally public endpoints (skipped entirely)

Infrastructure and auth flow routes are always excluded — they must be unauthenticated by design:

`/health`, `/ping`, `/ready`, `/live`, `/status`, `/metrics`, `/version`, `/docs`, `/redoc`, `/openapi.json`, `/swagger`, `/favicon.ico`, `/robots.txt`, `/public/`, `/api-docs`, `/login`, `/logout`, `/signin`, `/signout`, `/signup`, `/register`, `/forgot-password`, `/reset-password`, `/verify-email`, `/confirm-email`, `/auth/*`, and bare root `/`.

#### Severity adjustments

- **LOW** instead of MEDIUM when: the route name or path contains patterns suggesting intentional public access (`free-trial`, `demo-request`, `analytics`, `webhook`, `callback`, `oauth`, etc.), or rate limiting is present in a 20-line window (signals the developer is managing unauthenticated access deliberately).
- **LOW** for Django/DRF views when a `settings.py` is found in the repo — `DEFAULT_PERMISSION_CLASSES` may be set globally, which the scanner cannot yet parse.
- **Suppressed** when the developer has added an explicit `// @public` annotation.

Reports **at most one finding per file** to avoid inflating counts when the same pattern repeats across many route handlers in the same file.

**Severity:** MEDIUM (or LOW for public/rate-limited routes).

---

### PRBL-T001 — Path Traversal

**CWE-22 · OWASP A01 — Broken Access Control**

Detects user-controlled input used to build filesystem paths passed to file operation functions.

**Sink functions:** `sendFile`, `createReadStream`, `createWriteStream`, `readFile`, `readFileSync`, `writeFile`, `writeFileSync`, `unlink`, `unlinkSync`, `open`, `send_file`, `send_from_directory`, `FileResponse`.

**Taint on the sink line:** the function call must include user input directly: `req.params`, `req.query`, `req.body`, `request.args`, `request.form`, template literals `${`, f-strings `f"`, string concatenation `+ var`, or `os.path.join`.

Uses the same taint-source logic as injection rules to confirm user control.

**Sanitization signals (not flagged if present nearby):** `path.basename()`, `path.resolve(...).startsWith(...)`, `normalize(...).startsWith(...)`, `'..' in path`, `path.includes('..')`, `secure_filename()`, `safe_join()`.

Input like `../../etc/passwd` or `..\\..\\.env` escapes the intended directory and reads (or overwrites) arbitrary files — including the application's `.env` file containing every secret.

**Severity:** HIGH.

---

## Test file policy

Files in test directories or with test filename patterns are treated with reduced scope:

**Test directories:** any path component exactly equal to `test`, `tests`, `testing`, `spec`, or `specs` (not substrings — `contest.py` is not a test file).

**Test filenames:** stems matching `test_*`, `*_test`, `*.spec`, or `*.test`.

**What changes for test files:**
- PRBL-C001 (hardcoded credentials): most findings are suppressed — `password='Secure123'` in a test fixture is not a production secret. Exception: high-confidence credential formats are still flagged even in test files: AWS key IDs (`AKIA...`), Stripe live keys (`sk_live_`, `rk_live_`), hardcoded JWTs (`eyJ...`), and GitHub tokens (`ghp_`, `github_pat_`). These are always wrong regardless of context.
- PRBL-C002 (session secrets): fully suppressed in test files.
- PRBL-A001 (missing access control): fully suppressed in test files — test scaffolding routes are not production endpoints.
- All injection rules (PRBL-I001 through PRBL-I004) and PRBL-T001 still run — test files can import and call code in ways that mirror real usage, and injection in a test utility can be a real finding if that utility is also used in production.

---

## Severity levels

| Level | Meaning |
|---|---|
| **HIGH** | Exploitable with high confidence; fix before shipping. Includes hardcoded real credentials, SQL/command/code injection, path traversal, hardcoded session secrets. |
| **MEDIUM** | Likely exploitable but requires additional context; investigate promptly. Includes missing auth on routes with sensitive operations, hardcoded fallback secrets. |
| **LOW** | Informational; may be intentional or low-risk given context. Includes missing auth on likely-public routes, weak randomness for analytics IDs, credentials in demo/marketing content. |

---

## OWASP Top 10 coverage

Categories and rankings follow the **OWASP Top 10 2021** revision (the current stable release as of 2024).

| Rule | OWASP Category |
|---|---|
| PRBL-C001, PRBL-C002 | A07 — Identification and Authentication Failures |
| PRBL-R001 | A04 — Insecure Design (Cryptographic Failures) |
| PRBL-I001, PRBL-I002, PRBL-I003, PRBL-I004 | A05 — Injection |
| PRBL-A001, PRBL-T001 | A01 — Broken Access Control |
