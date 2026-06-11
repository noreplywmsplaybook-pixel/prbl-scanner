# Security Policy

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Email security disclosures to: **security@prbl.dev**

Include:
- Description of the vulnerability and its impact
- Steps to reproduce or proof-of-concept
- Affected versions / components

You will receive an acknowledgement within 48 hours. We aim to patch critical issues within 7 days and disclose publicly after a fix is available.

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅        |

## Known Issues

### CVE-2025-3000 — torch `jit.script` memory corruption (accepted risk)

**Package:** `torch 2.12.0`
**Status:** No fixed release exists upstream as of 2026-06-11.
**Exploitability in Prbl:** Not exploitable.

The scanner loads a bundled, read-only classifier model at startup via `torch.load()`. It never passes user-supplied input to `torch.jit.script()`, which is the affected code path. The model file is committed to the repository and is not derived from user input.

We will upgrade torch as soon as a patched release is available.

## Security Measures

- Scanner API requires a pre-shared token (`X-Scan-Token` header)
- Per-IP rate limiting (5 requests/hour) enforced in-process
- Service runs as an unprivileged system user (`prbl`)
- SSH password authentication disabled on the scanner host
- `fail2ban` active on the scanner host
- All Python dependencies audited with `pip-audit` on each release
