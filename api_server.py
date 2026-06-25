"""
Prbl scan API — FastAPI service on port 8000.
Accepts a public GitHub repo URL, clones it, runs PrblScanner, returns findings.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from prbl.scanner import PrblScanner
import time as _time
from collections import defaultdict
from fastapi import Request, Header

_START_TIME = _time.time()

STATS_FILE = Path(__file__).parent / "stats.json"


def _load_stats() -> dict:
    try:
        if STATS_FILE.exists():
            return json.loads(STATS_FILE.read_text())
    except Exception:
        pass
    return {"total_scans": 0, "recent": []}


def _record_scan(repo: str, findings: int, files: int) -> None:
    stats = _load_stats()
    stats["total_scans"] = stats.get("total_scans", 0) + 1
    entry = {
        "repo": repo,
        "findings": findings,
        "files": files,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    stats["recent"] = ([entry] + stats.get("recent", []))[:50]
    try:
        STATS_FILE.write_text(json.dumps(stats))
    except Exception:
        pass

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
# Async scanning removes the old 60s Vercel-timeout constraint, so this can be
# generous — the real limit is VPS CPU/memory, guarded by MAX_CONCURRENT_SCANS.
MAX_FILES = 3000
MAX_REPO_SIZE_MB = 100

# ── Async job store ──────────────────────────────────────────────────────────
# Scans run in a background thread; the dashboard polls /scan/status/{job_id}
# instead of holding one HTTP request open for the whole clone+scan duration.
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()
JOB_TTL_SECONDS = 3600  # stale job entries are swept on each /scan/start call

MAX_CONCURRENT_SCANS = 2  # matches the VPS's 2 vCPUs
_active_scans = 0
_active_scans_lock = threading.Lock()


def _sweep_old_jobs() -> None:
    cutoff = _time.time() - JOB_TTL_SECONDS
    with JOBS_LOCK:
        stale = [jid for jid, j in JOBS.items() if j.get("created_at", 0) < cutoff]
        for jid in stale:
            del JOBS[jid]


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


@app.get("/admin/stats")
def admin_stats(x_admin_token: str = Header(default="")):
    if not ADMIN_TOKEN or x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    stats = _load_stats()
    return {
        "status": "ok",
        "total_scans": stats.get("total_scans", 0),
        "recent_scans": stats.get("recent", [])[:20],
        "uptime_seconds": int(_time.time() - _START_TIME),
    }


# ── Auth + abuse protection ──────────────────────────────────────────────────
SCAN_TOKEN = os.environ.get("SCAN_TOKEN", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")

# Per-client-IP rate limit for the public landing-page scanner.
# The landing route forwards the visitor IP in X-Client-IP; dashboard routes
# (already rate-limited per user) do not send it and are exempt.
IP_LIMIT = 5          # scans
IP_WINDOW = 3600      # per hour
_ip_hits: dict[str, list[float]] = defaultdict(list)


def _run_scan(req: ScanRequest) -> ScanResponse:
    """Clone + scan. Raises HTTPException on failure. Shared by the sync
    /scan endpoint and the async /scan/start background job."""
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

        _record_scan(repo_name, len(findings), files_scanned)

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


def _check_auth_and_rate_limit(req: ScanRequest, request: Request, x_scan_token: str, x_client_ip: str) -> None:
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


@app.post("/scan", response_model=ScanResponse)
def scan_repo(
    req: ScanRequest,
    request: Request,
    x_scan_token: str = Header(default=""),
    x_client_ip: str = Header(default=""),
):
    """Synchronous scan — kept for the public landing-page scanner, which only
    handles smaller public repos and fits comfortably inside one request."""
    _check_auth_and_rate_limit(req, request, x_scan_token, x_client_ip)
    return _run_scan(req)


def _do_scan_job(job_id: str, req: ScanRequest) -> None:
    global _active_scans
    with _active_scans_lock:
        _active_scans += 1
    try:
        result = _run_scan(req)
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "done"
            JOBS[job_id]["result"] = result.model_dump()
    except HTTPException as e:
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["error"] = e.detail
            JOBS[job_id]["status_code"] = e.status_code
    except Exception as e:
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["error"] = f"Scan failed: {e}"
            JOBS[job_id]["status_code"] = 500
    finally:
        with _active_scans_lock:
            _active_scans -= 1


@app.post("/scan/start")
def scan_start(
    req: ScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    x_scan_token: str = Header(default=""),
    x_client_ip: str = Header(default=""),
):
    """Kicks off a scan in the background and returns immediately with a
    job_id. Callers poll /scan/status/{job_id} for the result. This removes
    the dependency on the caller's own HTTP timeout (e.g. Vercel's
    maxDuration) for large repos that take longer than a minute to scan."""
    _check_auth_and_rate_limit(req, request, x_scan_token, x_client_ip)

    _sweep_old_jobs()

    with _active_scans_lock:
        if _active_scans >= MAX_CONCURRENT_SCANS:
            raise HTTPException(
                status_code=503,
                detail="Scanner is at capacity — please try again in a minute.",
            )

    job_id = uuid.uuid4().hex
    with JOBS_LOCK:
        JOBS[job_id] = {
            "status": "running",
            "result": None,
            "error": None,
            "created_at": _time.time(),
        }

    background_tasks.add_task(_do_scan_job, job_id, req)
    return {"job_id": job_id, "status": "started"}


@app.get("/scan/status/{job_id}")
def scan_status(job_id: str, x_scan_token: str = Header(default="")):
    if not SCAN_TOKEN or x_scan_token != SCAN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found or expired")
    return job
