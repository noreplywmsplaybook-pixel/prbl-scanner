# prbl-scanner

Open source vulnerability scanner for AI-generated code.

Prbl finds the security vulnerabilities that AI coding tools 
produce systematically — the patterns that exist because of 
how LLMs were trained, not because of developer mistakes.

## What it detects

- **PRBL-C001** — Hardcoded credentials and fallback secrets  
  `CWE-798 · OWASP A07 · #7 most critical web security risk`  
  Detects API keys, passwords, and tokens hardcoded directly in source
  code. Also catches the AI-specific fallback pattern:
  `process.env.SECRET || 'default_value'` where the fallback becomes
  the live secret for any deployment missing the environment variable.

- **PRBL-R001** — Weak randomness in security contexts  
  `CWE-338 · OWASP A04 · #4 most critical web security risk`  
  Flags Math.random(), random.random(), and related functions when used
  to generate tokens, session IDs, passwords, or OTPs. These functions
  are not cryptographically secure — their output is predictable.

- **PRBL-R002** — Insecure equality comparison on security-critical value  
  `CWE-208 · OWASP A02 · #2 most critical web security risk`  
  Detects HMAC digests, webhook signatures, and verification tokens
  compared with == or === instead of a constant-time comparison function.
  String equality short-circuits on the first differing byte, allowing
  timing attacks that reconstruct the expected value one byte at a time.

- **PRBL-I001** — SQL injection including multi-line patterns  
  `CWE-89 · OWASP A05 · #5 most critical web security risk`  
  Detects user input concatenated or interpolated into SQL queries,
  including multi-line query construction patterns that most scanners miss.

- **PRBL-I002** — Command injection  
  `CWE-78 · OWASP A05 · #5 most critical web security risk`  
  Detects user input passed to shell commands via exec, spawn, system,
  popen, subprocess.run, and shell=True.

- **PRBL-I003** — Code injection (eval/exec)  
  `CWE-94/95 · OWASP A05 · #5 most critical web security risk`  
  Detects user input passed to eval(), exec(), new Function(), or
  compile(). Gives an attacker full code execution on the server.

- **PRBL-A001** — Missing access control including serverless handlers  
  `CWE-862 · OWASP A01 · #1 most critical web security risk`  
  Detects route handlers and serverless functions that perform sensitive
  operations (database access, payment processing, user data) with no
  visible authentication or authorization check.

- **PRBL-P001** — Hallucinated package references  
  `Emerging — no CWE · OWASP A03 · Supply Chain Failures`  
  Detects imports of packages that do not exist on PyPI or npm. AI
  models invent plausible-sounding package names. An attacker who
  registers the name with a malicious payload gets code execution on
  every machine that runs install.

## Security Standards Mapping

Every Prbl rule maps to established security standards. When a developer
asks an AI tool "how serious is this finding?" — the CWE and OWASP
category give it the full context to answer accurately.

| Rule | Name | CWE | OWASP 2025 | OWASP Rank |
|------|------|-----|------------|------------|
| PRBL-C001 | Hardcoded Credentials | CWE-798 | A07 — Authentication Failures | #7 |
| PRBL-R001 | Weak Randomness | CWE-338 | A04 — Cryptographic Failures | #4 |
| PRBL-R002 | Insecure Equality Comparison | CWE-208 | A02 — Cryptographic Failures | #2 |
| PRBL-I001 | SQL Injection | CWE-89 | A05 — Injection | #5 |
| PRBL-I002 | Command Injection | CWE-78 | A05 — Injection | #5 |
| PRBL-I003 | Code Injection | CWE-94/95 | A05 — Injection | #5 |
| PRBL-A001 | Missing Access Control | CWE-862 | A01 — Broken Access Control | #1 |
| PRBL-P001 | Hallucinated Packages | Emerging — no CWE | A03 — Supply Chain Failures | #3 |

### Why PRBL-P001 has no CWE

Hallucinated package references are a new vulnerability class created
by AI coding tools. Standard CWE scanners cannot detect this by
definition — there is no CWE entry because this failure mode did not
exist before LLMs generated code at scale. Prbl is the only scanner
that catches it.

PRBL-P001 maps to OWASP A03 (Supply Chain Failures) because a
malicious actor can register the hallucinated package name on PyPI
or npm — turning every project using that AI-generated import into
an unintentional malware distribution point.

## Why open source

Security tools that scan your code should be auditable. 
These are the exact rules Prbl uses. Nothing hidden.

## Install

pip install prbl-scanner

## Usage

prbl-scanner scan ./myproject

## JSON output

Every finding includes CWE and OWASP fields for downstream tooling:

```json
{
  "rule_id": "PRBL-C001",
  "title": "Hardcoded credential: Stripe live secret key",
  "cwe": "CWE-798",
  "owasp_category": "A07 — Authentication Failures",
  "owasp_rank": 7,
  "severity": "HIGH",
  "file": "auth/stripe.py",
  "line": 14,
  "detail": "...",
  "fix": "..."
}
```

## Validated against

74 public repos across Django, FastAPI, Express, NestJS, 
and full-stack codebases. 6.25% false positive rate.

## Contributing

Found a new AI vulnerability pattern? Open a PR.
Rule format is documented in CONTRIBUTING.md.

**Every new rule must pass the validation pipeline before merging:**

1. Synthetic test suite — minimum 10 cases (true positives and false positives)
2. Batch stress test — minimum 20 real public codebases
3. False positive rate confirmed under 10% on human-written code
4. Validated against at least one enterprise-scale codebase (1000+ files)

Rules that skip this pipeline will be reverted. PRBL-S001 (SSRF) was removed
after producing a 100% false positive rate on the first production codebase it
touched — it was added without completing any of the four steps above.

## License

MIT
