"""
Prbl scan API — FastAPI service on port 8000.
Accepts a public GitHub repo URL, clones it, runs PrblScanner, returns findings.
"""

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from prbl.scanner import PrblScanner
import time as _time
from collections import defaultdict
from fastapi import Request, Header

app = FastAPI(title="Prbl Scanner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://178.104.170.108"],
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type", "X-Scan-Token", "X-Client-IP"],
)

LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}

# Files/dirs to skip
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".next", "dist", "build",
    "venv", ".venv", "vendor", "coverage", ".pytest_cache",
}
MAX_FILE_SIZE = 200_000  # 200 KB per file
MAX_FILES = 300
MAX_REPO_SIZE_MB = 100


class ScanRequest(BaseModel):
    repo_url: str
    # OAuth token for private repo clones. Used once for the clone, then
    # discarded — never logged, never stored, never echoed in errors.
    github_token: Optional[str] = None


class Finding(BaseModel):
    file: str
    line: int
    rule_id: str
    severity: str
    vuln_class: str
    title: str
    detail: str
    fix: str
    code: str
    cwe: str = ""
    owasp_category: str = ""
    owasp_rank: int = 0


class ScanResponse(BaseModel):
    repo: str
    files_scanned: int
    total_findings: int
    high: int
    medium: int
    low: int
    findings: list[Finding]
    truncated: bool


def validate_github_url(url: str) -> str:
    """Return cleaned URL or raise."""
    url = url.strip().rstrip("/")
    # Allow github.com URLs only
    pattern = r"^https?://github\.com/[\w\-\.]+/[\w\-\.]+$"
    if not re.match(pattern, url):
        raise HTTPException(status_code=400, detail="Please provide a valid public GitHub repo URL (https://github.com/owner/repo)")
    # Strip .git suffix if present
    if url.endswith(".git"):
        url = url[:-4]
    return url


@app.get("/health")
def health():
    return {"status": "ok"}


# ── Auth + abuse protection ──────────────────────────────────────────────────
SCAN_TOKEN = os.environ.get("SCAN_TOKEN", "")

# Per-client-IP rate limit for the public landing-page scanner.
# The landing route forwards the visitor IP in X-Client-IP; dashboard routes
# (already rate-limited per user) do not send it and are exempt.
IP_LIMIT = 5          # scans
IP_WINDOW = 3600      # per hour
_ip_hits: dict[str, list[float]] = defaultdict(list)


@app.post("/scan", response_model=ScanResponse)
def scan_repo(
    req: ScanRequest,
    request: Request,
    x_scan_token: str = Header(default=""),
    x_client_ip: str = Header(default=""),
):
    if not SCAN_TOKEN:
        raise HTTPException(status_code=503, detail="Scanner not configured")
    if x_scan_token != SCAN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Use real socket IP for rate limiting; only trust X-Client-IP when the
    # request already passed token auth (i.e. comes from our dashboard proxy).
    real_ip = (request.client.host if request.client else None) or x_client_ip
    if real_ip:
        now = _time.time()
        hits = [t for t in _ip_hits[real_ip] if now - t < IP_WINDOW]
        if len(hits) >= IP_LIMIT:
            raise HTTPException(
                status_code=429,
                detail="Rate limit reached — 5 free scans per hour. Sign up for more.",
            )
        hits.append(now)
        _ip_hits[real_ip] = hits
    url = validate_github_url(req.repo_url)
    repo_name = "/".join(url.split("/")[-2:])

    tmpdir = tempfile.mkdtemp(prefix="prbl_")
    try:
        # Clone — shallow, no blobs for large files.
        # For private repos the token is injected into the clone URL only;
        # capture_output keeps git's stderr (which echoes the URL) out of
        # the service logs, and clone_url is dropped right after the call.
        if req.github_token:
            clone_url = url.replace(
                "https://github.com/",
                f"https://x-access-token:{req.github_token}@github.com/",
            )
        else:
            clone_url = url
        result = subprocess.run(
            ["git", "clone", "--depth=1", "--filter=blob:limit=500k",
             clone_url + ".git", tmpdir],
            capture_output=True,
            text=True,
            timeout=60,
        )
        clone_url = None
        if result.returncode != 0:
            # result.stderr may contain the tokenized URL — never include it here.
            # Distinguish common failure modes so callers can react appropriately.
            stderr_lower = result.stderr.lower() if result.stderr else ""
            if "repository not found" in stderr_lower or "not found" in stderr_lower:
                raise HTTPException(
                    status_code=404,
                    detail="Repository not found. Check the URL and ensure it is public (or that you have authorized access)."
                )
            if "authentication failed" in stderr_lower or "could not read username" in stderr_lower or "invalid credentials" in stderr_lower:
                raise HTTPException(
                    status_code=401,
                    detail="Authentication failed. For private repos, make sure your GitHub authorization grants repo access."
                )
            raise HTTPException(
                status_code=422,
                detail="Could not clone repository. Check the URL, and for private repos make sure your GitHub authorization grants repo access."
            )

        scanner = PrblScanner(check_packages=True)
        findings: list[Finding] = []
        files_scanned = 0
        truncated = False

        root = Path(tmpdir)
        all_files = []
        for path in root.rglob("*"):
            if path.is_file():
                # Skip excluded dirs
                if any(part in SKIP_DIRS for part in path.parts):
                    continue
                if path.suffix in LANGUAGE_MAP:
                    all_files.append(path)

        if len(all_files) > MAX_FILES:
            all_files = all_files[:MAX_FILES]
            truncated = True

        for path in all_files:
            if path.stat().st_size > MAX_FILE_SIZE:
                continue
            try:
                code = path.read_text(errors="ignore")
            except Exception:
                continue

            lang = LANGUAGE_MAP[path.suffix]
            rel = str(path.relative_to(root))
            file_result = scanner.scan_code(code, lang, file_path=rel)
            files_scanned += 1

            for f in file_result.findings:
                findings.append(Finding(
                    file=rel,
                    line=f.line_number,
                    rule_id=f.rule_id,
                    severity=f.severity,
                    vuln_class=f.vuln_class,
                    title=f.title,
                    detail=f.detail,
                    fix=f.fix,
                    code=f.line.strip(),
                    cwe=f.cwe,
                    owasp_category=f.owasp_category,
                    owasp_rank=f.owasp_rank,
                ))

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        return ScanResponse(
            repo=repo_name,
            files_scanned=files_scanned,
            total_findings=len(findings),
            high=high,
            medium=medium,
            low=low,
            findings=findings,
            truncated=truncated,
        )

    except HTTPException:
        raise
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Repository clone timed out. Try a smaller repo.")
    except Exception as e:
        # Redact the token if any exception message happens to embed it
        msg = str(e)
        if req.github_token:
            msg = msg.replace(req.github_token, "[REDACTED]")
        raise HTTPException(status_code=500, detail=f"Scan failed: {msg}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
