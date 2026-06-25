#!/usr/bin/env python3
"""
Re-clones and re-scans every repo that successfully scanned across all 10 HN
stress-test batches, using the fixed scanner (I005 destructuring fix + A001
centralized-auth blind spot fix). Validates that the fixes actually moved the
numbers on the full real-world dataset, not just in synthetic tests.

Output: hn-rescan-validation.json
"""

import json
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from prbl.scanner import PrblScanner  # noqa: E402

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

OUT_DIR = Path(__file__).parent.parent
OUT_FILE = OUT_DIR / "hn-rescan-validation.json"


def load_all_scanned_repos() -> list[dict]:
    """Every repo that successfully scanned across batch 1 + batches 2-10."""
    repos = []
    seen = set()
    files = ["hn-scan-raw-data.json"] + [f"hn-scan-batch-{i}.json" for i in range(2, 11)]
    for fn in files:
        path = OUT_DIR / fn
        if not path.exists():
            continue
        data = json.loads(path.read_text())
        for r in data.get("results", []):
            key = f"{r['owner']}/{r['repo']}".lower()
            if key in seen:
                continue
            seen.add(key)
            repos.append({"owner": r["owner"], "repo": r["repo"]})
    return repos


def scan_repo(owner: str, repo: str) -> dict:
    url = f"https://github.com/{owner}/{repo}.git"
    tmpdir = tempfile.mkdtemp(prefix="hnrescan_")
    try:
        clone = subprocess.run(
            ["git", "clone", "--depth=1", "--filter=blob:limit=500k", url, tmpdir],
            capture_output=True, text=True, timeout=60,
        )
        if clone.returncode != 0:
            return {"ok": False, "error": "clone_failed"}

        root = Path(tmpdir)
        all_files = [
            p for p in root.rglob("*")
            if p.is_file()
            and p.suffix in LANGUAGE_MAP
            and not any(part in SKIP_DIRS for part in p.parts)
        ]
        if not all_files:
            return {"ok": False, "error": "no_scannable_files"}

        all_files = all_files[:MAX_FILES]
        scanner = PrblScanner(check_packages=False)
        findings = []

        for p in all_files:
            if p.stat().st_size > MAX_FILE_SIZE:
                continue
            try:
                code = p.read_text(errors="ignore")
            except Exception:
                continue
            lang = LANGUAGE_MAP[p.suffix]
            result = scanner.scan_code(code, lang, file_path=str(p.relative_to(root)))
            for f in result.findings:
                findings.append({"rule_id": f.rule_id, "severity": f.severity})

        return {"ok": True, "findings": findings}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "clone_timeout"}
    except Exception as e:
        return {"ok": False, "error": f"exception: {e}"}
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    repos = load_all_scanned_repos()
    print(f"[rescan] {len(repos)} unique repos to re-scan with fixed rules")

    rule_counter = Counter()
    total = 0
    failed = 0
    repos_with_high = 0
    repos_with_medium = 0
    repos_clean = 0

    for n, r in enumerate(repos, 1):
        owner, repo = r["owner"], r["repo"]
        if n % 25 == 0:
            print(f"[rescan] {n}/{len(repos)}...")
        res = scan_repo(owner, repo)
        if not res["ok"]:
            failed += 1
            continue
        total += 1
        findings = res["findings"]
        for f in findings:
            rule_counter[f["rule_id"]] += 1
        has_high = any(f["severity"] == "high" for f in findings)
        has_med = any(f["severity"] == "medium" for f in findings)
        if has_high:
            repos_with_high += 1
        if has_med:
            repos_with_medium += 1
        if not findings:
            repos_clean += 1

    pct_high = (repos_with_high / total * 100) if total else 0
    pct_medium = (repos_with_medium / total * 100) if total else 0
    pct_clean = (repos_clean / total * 100) if total else 0

    out = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_repos_attempted": len(repos),
        "total_scanned": total,
        "failed_to_reclone": failed,
        "pct_high": round(pct_high, 1),
        "pct_medium": round(pct_medium, 1),
        "pct_clean": round(pct_clean, 1),
        "top_rules": rule_counter.most_common(10),
    }
    OUT_FILE.write_text(json.dumps(out, indent=2))

    print("\n" + "=" * 60)
    print(f"RESCAN DONE — {total} repos re-scanned, {failed} failed to re-clone")
    print(f"NEW HEADLINE — % with >=1 HIGH: {pct_high:.1f}%")
    print(f"Top rules: {rule_counter.most_common(6)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
