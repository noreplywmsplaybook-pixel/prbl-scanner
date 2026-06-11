"""
prbl-scanner CLI — run security analysis locally against a directory.
Usage: prbl-scanner scan <path>
"""

import argparse
import sys
from pathlib import Path

from .scanner import PrblScanner

LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".next", "dist", "build",
    "venv", ".venv", "vendor", "coverage", ".pytest_cache",
}

MAX_FILE_SIZE = 200_000
MAX_FILES = 300


def scan(path: Path) -> int:
    if not path.exists():
        print(f"prbl-scanner: path not found: {path}", file=sys.stderr)
        return 1

    scanner = PrblScanner(check_packages=False)
    all_files = [
        p for p in path.rglob("*")
        if p.is_file()
        and p.suffix in LANGUAGE_MAP
        and not any(part in SKIP_DIRS for part in p.parts)
        and p.stat().st_size <= MAX_FILE_SIZE
    ][:MAX_FILES]

    total_findings = []
    for p in all_files:
        try:
            code = p.read_text(errors="ignore")
        except Exception:
            continue
        result = scanner.scan_code(code, LANGUAGE_MAP[p.suffix], file_path=str(p.relative_to(path)))
        total_findings.extend(result.findings)

    if not total_findings:
        print(f"✓ No findings in {len(all_files)} files scanned.")
        return 0

    high   = [f for f in total_findings if f.severity == "high"]
    medium = [f for f in total_findings if f.severity == "medium"]
    low    = [f for f in total_findings if f.severity == "low"]

    print(f"\nPrbl scan — {len(all_files)} files · {len(total_findings)} findings "
          f"({len(high)} HIGH, {len(medium)} MEDIUM, {len(low)} LOW)\n")

    for sev, group in [("HIGH", high), ("MEDIUM", medium), ("LOW", low)]:
        for f in group:
            print(f"  [{sev}] {f.file}:{f.line_number}  {f.rule_id}")
            print(f"         {f.title}")
            print(f"         {f.detail}")
            print(f"         Fix: {f.fix}")
            print()

    return 1 if high else 0


def main():
    parser = argparse.ArgumentParser(
        prog="prbl-scanner",
        description="AI code security scanner — finds what AI coding tools miss.",
    )
    sub = parser.add_subparsers(dest="command")

    scan_cmd = sub.add_parser("scan", help="Scan a local directory")
    scan_cmd.add_argument("path", nargs="?", default=".", help="Directory to scan (default: .)")

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(scan(Path(args.path)))
    else:
        parser.print_help()
        sys.exit(0)
