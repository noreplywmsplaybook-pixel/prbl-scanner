# prbl-scanner

Open source vulnerability scanner for AI-generated code.

Prbl finds the security vulnerabilities that AI coding tools 
produce systematically — the patterns that exist because of 
how LLMs were trained, not because of developer mistakes.

## What it detects

- PRBL-C001: Hardcoded credentials and fallback secrets
- PRBL-R001: Weak randomness in security contexts
- PRBL-I001: SQL injection including multi-line patterns
- PRBL-I002: Command injection
- PRBL-I003: Code injection (eval/exec)
- PRBL-A001: Missing access control including serverless handlers
- PRBL-P001: Hallucinated package references

## Why open source

Security tools that scan your code should be auditable. 
These are the exact rules Prbl uses. Nothing hidden.

## Install

pip install prbl-scanner

## Usage

prbl-scanner scan ./myproject

## Validated against

74 public repos across Django, FastAPI, Express, NestJS, 
and full-stack codebases. 6.25% false positive rate.

## Contributing

Found a new AI vulnerability pattern? Open a PR.
Rule format is documented in CONTRIBUTING.md.

## License

MIT
