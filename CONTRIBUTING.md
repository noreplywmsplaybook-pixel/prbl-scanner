# Contributing to prbl-scanner

## Rule format

All static analysis rules live in `prbl/scanner/rules.py`. Rules are regex-based
and run fully offline — no network calls, no external dependencies.

### RuleMatch dataclass

Every rule produces zero or more `RuleMatch` objects:

```python
@dataclass
class RuleMatch:
    rule_id: str       # e.g. "PRBL-C001"
    vuln_class: str    # e.g. "hardcoded_credentials"
    line_number: int   # 1-indexed
    line: str          # the raw line content (stripped)
    title: str         # short human-readable title shown in output
    detail: str        # explanation of why this is dangerous
    fix: str           # concrete remediation guidance
    severity: str      # "high" | "medium" | "low"
```

### Rule checker function signature

Each vulnerability class has a dedicated checker function:

```python
def check_<class>(lines: list[str], language: str, file_path: str = "") -> list[RuleMatch]:
    ...
```

- `lines` — the source file split by newline
- `language` — `"python"`, `"javascript"`, or `"typescript"`
- `file_path` — optional absolute path, used for repo-relative context (e.g. finding `settings.py`)

### Adding a new rule

1. **Define your patterns** — add a list of `(regex_pattern, description)` tuples near the
   top of the relevant section, or create a new section.

2. **Write a checker function** — follow the signature above. The function receives
   `lines` and returns `list[RuleMatch]`. Skip comment lines at the top of the loop:

   ```python
   if stripped.startswith(('#', '//', '*')):
       continue
   ```

3. **Use a taint window for injection-style rules** — don't flag a pattern unless
   user-controlled input is present in the surrounding lines. The existing `_has_taint()`
   helper checks for web framework input sources and function parameters:

   ```python
   window_start = max(0, i - 5)
   window_end = min(len(lines), i + 5)
   window = '\n'.join(lines[window_start:window_end])
   if _has_taint(window):
       # flag it
   ```

4. **Add safe-context guards** — always add a `re.compile()` pattern that suppresses
   findings in obviously safe contexts (test fixtures, logging statements, comments).
   See `_INJECTION_SAFE_CONTEXT` and `_CRED_SAFE_CONTEXT` for examples.

5. **Register in `run_all_rules()`** — add your checker call to the dispatch function
   at the bottom of `rules.py`. Test-file suppression logic lives here too.

### Existing rule IDs

| ID | Class | Checker |
|----|-------|---------|
| PRBL-C001 | `hardcoded_credentials` | `check_hardcoded_credentials()` |
| PRBL-R001 | `weak_randomness` | `check_weak_randomness()` |
| PRBL-I001 | `injection` (SQL) | `check_injection()` |
| PRBL-I002 | `injection` (command) | `check_injection()` |
| PRBL-I003 | `injection` (code/eval) | `check_injection()` |
| PRBL-A001 | `missing_access_control` | `check_missing_access_control()` |
| PRBL-P001 | `hallucinated_package` | `check_hallucinated_packages()` in `osv.py` |

New rules should use the next available ID in the appropriate series
(C = credentials, R = randomness, I = injection, A = access control, P = packages).

### Package registry checks (osv.py)

`prbl/scanner/osv.py` handles PRBL-P001. It:

- Extracts `import` / `require` statements using regex
- Skips Python stdlib modules and Node.js builtins
- Resolves import name → PyPI package name aliases (e.g. `PIL` → `Pillow`)
- Checks package existence against the npm or PyPI registry via `urllib`
- Caches results to disk (24-hour TTL) in the system temp directory
- Skips Django migration files entirely (auto-generated, always correct)
- Skips packages that exist as local directories/files in the same repo

To add a new import alias (import name differs from pip install name):

```python
# In osv.py, IMPORT_ALIASES dict:
"your_import_name": "pypi-package-name",
```

### Test-file handling

`rules.py` includes `_is_test_file()` which returns `True` for files in
`test/`, `tests/`, `spec/`, `specs/` directories or files named `test_*.py`,
`*_test.py`, `*.spec.js`, `*.test.ts`, etc.

In `run_all_rules()`:
- PRBL-C001 is suppressed in test files **except** for real credential formats
  (AWS keys, Stripe live keys, GitHub PATs, hardcoded JWTs) — those are always wrong.
- PRBL-A001 is suppressed entirely in test files.
- PRBL-R001, PRBL-I001/2/3 run in all files.

### Severity guide

| Severity | When to use |
|----------|-------------|
| `high` | Direct exploitability — attacker gets code execution, data exfiltration, or credential access with no preconditions |
| `medium` | Likely exploitable but requires some precondition (e.g. attacker must know the route exists) |
| `low` | Possible vulnerability that depends on configuration not visible in this file |

### Pull request checklist

- [ ] Rule fires on a real example from an AI-generated codebase (paste the snippet in the PR)
- [ ] Rule does NOT fire on an obvious false-positive counterexample
- [ ] Safe-context guards are in place for test files / logging / comments
- [ ] `RuleMatch.detail` explains *why* this is dangerous, not just *what* it is
- [ ] `RuleMatch.fix` gives a concrete code-level remediation
