"""
Hallucinated package detection via npm and PyPI registry lookups.
Checks every import/require against the public registry — if the package
doesn't exist, it's either hallucinated or a typosquatting risk.
"""

import re
import urllib.request
import urllib.error
import json
import hashlib
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class PackageResult:
    name: str
    ecosystem: str  # "npm" | "pypi"
    exists: bool
    line_number: int
    line: str


_PYTHON_IMPORT = re.compile(
    r'^\s*(?:import|from)\s+([a-zA-Z][a-zA-Z0-9_.-]*)',
)

_JS_REQUIRE = re.compile(
    r'''(?:require|import)\s*\(?['""]([a-zA-Z@][a-zA-Z0-9/_@.-]*)['""]''',
)

# Stdlib modules to skip — not installed from a registry
_PYTHON_STDLIB = {
    "os", "sys", "re", "json", "time", "math", "random", "string", "io",
    "abc", "ast", "csv", "copy", "enum", "glob", "gzip", "hmac", "html",
    "http", "hashlib", "itertools", "logging", "pathlib", "pickle", "queue",
    "shutil", "socket", "sqlite3", "struct", "subprocess", "tempfile",
    "threading", "traceback", "typing", "unittest", "urllib", "uuid",
    "warnings", "weakref", "xml", "zipfile", "zlib", "base64", "binascii",
    "builtins", "collections", "contextlib", "dataclasses", "datetime",
    "decimal", "difflib", "email", "encodings", "errno", "functools",
    "getpass", "gettext", "inspect", "keyword", "linecache", "locale",
    "mimetypes", "numbers", "operator", "platform", "pprint", "profile",
    "pstats", "pty", "pwd", "readline", "signal", "site", "smtplib",
    "stat", "statistics", "textwrap", "token", "tokenize", "types",
    "unicodedata", "venv", "zoneinfo", "graphlib", "tomllib",
    "importlib", "pkgutil", "sysconfig", "compileall", "py_compile",
    "dis", "code", "codeop", "zipimport", "runpy",
    # Commonly missed stdlib modules
    "gc", "concurrent", "asyncio", "multiprocessing", "contextvars",
    "selectors", "ssl", "hmac", "secrets", "array", "queue",
    "heapq", "bisect", "pdb", "profile", "timeit", "cProfile",
    "copyreg", "shelve", "dbm", "lzma", "bz2", "tarfile",
    "mailbox", "imaplib", "poplib", "ftplib", "xmlrpc",
    "socketserver", "wsgiref", "html", "webbrowser",
    "colorsys", "imghdr", "sndhdr", "wave", "chunk",
    "curses", "atexit", "faulthandler", "ctypes", "posixpath",
    "ntpath", "genericpath", "fnmatch", "linecache",
}

_JS_BUILTINS = {
    "fs", "path", "http", "https", "url", "os", "crypto", "stream",
    "buffer", "events", "util", "assert", "child_process", "cluster",
    "dgram", "dns", "domain", "net", "querystring", "readline", "repl",
    "string_decoder", "timers", "tls", "tty", "v8", "vm", "worker_threads",
    "zlib", "perf_hooks", "async_hooks", "inspector",
}

# Import name → PyPI package name aliases.
# These packages install under a different name than they import as.
# Resolution order in _check_pypi: alias map → normalized lookup → PyPI API.
# If the alias target is a known-real package, the API call is skipped entirely.
IMPORT_ALIASES: dict[str, str] = {
    # Django ecosystem — import name differs from pip install name
    "rest_framework":       "djangorestframework",
    "corsheaders":          "django-cors-headers",
    "django_filters":       "django-filter",
    "ckeditor":             "django-ckeditor",
    "crispy_forms":         "django-crispy-forms",
    "allauth":              "django-allauth",
    "social_django":        "social-auth-app-django",
    "storages":             "django-storages",
    # Common packages whose import name doesn't match PyPI name
    "sklearn":              "scikit-learn",
    "cv2":                  "opencv-python",
    "PIL":                  "Pillow",
    "bs4":                  "beautifulsoup4",
    "yaml":                 "PyYAML",
    "dotenv":               "python-dotenv",
    "jwt":                  "PyJWT",
    "dateutil":             "python-dateutil",
    "jose":                 "python-jose",
    "multipart":            "python-multipart",
    # Well-known packages that exist and should never be flagged
    "celery":               "celery",
    "kombu":                "kombu",
    "stripe":               "stripe",
    "boto3":                "boto3",
    "pydantic":             "pydantic",
    "fastapi":              "fastapi",
    "uvicorn":              "uvicorn",
    "sqlalchemy":           "SQLAlchemy",
    "alembic":              "alembic",
    "passlib":              "passlib",
    # Django ecosystem extras
    "debug_toolbar":        "django-debug-toolbar",
    "phonenumber_field":    "django-phonenumber-field",
    "taggit":               "django-taggit",
    "guardian":             "django-guardian",
    "mptt":                 "django-mptt",
    "imagekit":             "django-imagekit",
    "tinymce":              "django-tinymce",
    "constance":            "django-constance",
    "import_export":        "django-import-export",
    "rosetta":              "django-rosetta",
    # Other common mismatches
    "attr":                 "attrs",
    "pkg_resources":        "setuptools",
    "google.cloud":         "google-cloud-core",
    "google.auth":          "google-auth",
    "firebase_admin":       "firebase-admin",
    "pymongo":              "pymongo",
    "motor":                "motor",
    "aiohttp":              "aiohttp",
    "httpx":                "httpx",
    "tenacity":             "tenacity",
    "rich":                 "rich",
    "click":                "click",
    "typer":                "typer",
    "loguru":               "loguru",
    "sentry_sdk":           "sentry-sdk",
    "openai":               "openai",
    "anthropic":            "anthropic",
    "langchain":            "langchain",
    "transformers":         "transformers",
    "torch":                "torch",
    "numpy":                "numpy",
    "pandas":               "pandas",
    "matplotlib":           "matplotlib",
    "seaborn":              "seaborn",
    "scipy":                "scipy",
    "redis":                "redis",
    "psycopg2":             "psycopg2-binary",
    "psycopg":              "psycopg",
    "aiomysql":             "aiomysql",
    "cryptography":         "cryptography",
    "nacl":                 "pynacl",
    "Crypto":               "pycryptodome",
    "itsdangerous":         "itsdangerous",
    "werkzeug":             "Werkzeug",
    "flask":                "Flask",
    "jinja2":               "Jinja2",
    "markupsafe":           "MarkupSafe",
    "wtforms":              "WTForms",
    "marshmallow":          "marshmallow",
    "cerberus":             "Cerberus",
    "jsonschema":           "jsonschema",
    "arrow":                "arrow",
    "pendulum":             "pendulum",
    "pytz":                 "pytz",
    "babel":                "Babel",
    "paramiko":             "paramiko",
    "fabric":               "fabric",
    "invoke":               "invoke",
    "celery":               "celery",
}


def extract_imports(code: str, language: str) -> list[tuple[int, str, str]]:
    """Returns list of (line_number, package_name, raw_line)."""
    results = []
    lines = code.splitlines()
    for i, line in enumerate(lines, 1):
        if language == "python":
            m = _PYTHON_IMPORT.match(line)
            if m:
                pkg = m.group(1).split('.')[0]  # top-level package
                if pkg not in _PYTHON_STDLIB and not pkg.startswith('_'):
                    results.append((i, pkg, line.strip()))
        else:  # js / ts
            m = _JS_REQUIRE.search(line)
            if m:
                pkg = m.group(1)
                # Skip relative imports, node builtins, and path alias prefixes
                # (@/ = Vite/TS alias, ~/ = webpack alias, #/ = subpath import)
                if not pkg.startswith('.') and not pkg.startswith('@/') and not pkg.startswith('~/') and not pkg.startswith('#/') and pkg not in _JS_BUILTINS:
                    # Strip scoped package path (e.g. @org/pkg/subpath → @org/pkg)
                    parts = pkg.split('/')
                    if pkg.startswith('@') and len(parts) >= 2:
                        pkg = '/'.join(parts[:2])
                    else:
                        pkg = parts[0]
                    results.append((i, pkg, line.strip()))
    return results


def _check_npm(package: str) -> bool:
    hit, exists = _cache_get(package, "npm")
    if hit:
        return exists
    url = f"https://registry.npmjs.org/{urllib.parse.quote(package, safe='@/')}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        urllib.request.urlopen(req, timeout=5)
        result = True
    except urllib.error.HTTPError as e:
        result = e.code != 404
    except Exception:
        return True  # Network error → assume exists (don't false-positive)
    _cache_set(package, "npm", result)
    return result


def _check_pypi(package: str) -> bool:
    # Resolve import-name aliases before any lookup.
    # e.g. 'rest_framework' → 'djangorestframework', 'PIL' → 'Pillow'
    pypi_name = IMPORT_ALIASES.get(package) or IMPORT_ALIASES.get(package.lower())
    if pypi_name is not None:
        # Alias target is a known-real package — skip the network call entirely
        # and report as existing. Cache under the original import name so
        # subsequent calls for the same import are instant.
        _cache_set(package.lower(), "pypi", True)
        return True

    normalized = package.replace('-', '_').lower()
    hit, exists = _cache_get(normalized, "pypi")
    if hit:
        return exists
    url = f"https://pypi.org/pypi/{urllib.parse.quote(normalized)}/json"
    try:
        urllib.request.urlopen(url, timeout=5)
        result = True
    except urllib.error.HTTPError as e:
        result = e.code != 404
    except Exception:
        return True
    _cache_set(normalized, "pypi", result)
    return result


import urllib.parse
import hashlib
import tempfile
import time

# Disk cache — keyed by "package:ecosystem", TTL 24 hours.
# Lives in the system temp dir so it persists across runs but clears on reboot.
_CACHE_TTL = 86400  # 24 hours
_CACHE_DIR = Path(tempfile.gettempdir()) / "prbl_pkg_cache"
_CACHE_DIR.mkdir(exist_ok=True)


def _cache_key(package: str, ecosystem: str) -> Path:
    safe = hashlib.md5(f"{package}:{ecosystem}".encode()).hexdigest()
    return _CACHE_DIR / f"{safe}.json"


def _cache_get(package: str, ecosystem: str) -> tuple[bool, bool]:
    """Returns (cache_hit, exists). cache_hit=False means not cached."""
    path = _cache_key(package, ecosystem)
    if not path.exists():
        return False, False
    try:
        data = json.loads(path.read_text())
        if time.time() - data["ts"] > _CACHE_TTL:
            path.unlink(missing_ok=True)
            return False, False
        return True, data["exists"]
    except Exception:
        return False, False


def _cache_set(package: str, ecosystem: str, exists: bool):
    path = _cache_key(package, ecosystem)
    try:
        path.write_text(json.dumps({"exists": exists, "ts": time.time()}))
    except Exception:
        pass


# Root markers — walking up from a file to find the repo root
_ROOT_MARKERS = {"pyproject.toml", "setup.py", "setup.cfg", "package.json", "requirements.txt", ".git"}


def _find_repo_root(file_path: str) -> "Optional[Path]":
    """
    Walk up from file_path's directory until a root marker is found.
    Returns the directory containing the marker, or None if not found.
    """
    if not file_path:
        return None
    current = Path(file_path).resolve().parent
    for _ in range(10):  # max 10 levels up
        if any((current / marker).exists() for marker in _ROOT_MARKERS):
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def _is_local_package(pkg: str, file_path: str) -> bool:
    """
    Return True if pkg matches a local module or package in the repo — i.e. a
    .py file or directory at the repo root, or in the same directory as file_path.
    This covers both `import utils` (same-dir module) and `from app import x`
    (top-level package directory).
    """
    repo_root = _find_repo_root(file_path)
    if repo_root is None:
        return False
    # Check for a top-level package directory
    if (repo_root / pkg).is_dir():
        return True
    # Check for a top-level .py file (e.g. main.py, utils.py, email_utils.py)
    if (repo_root / f"{pkg}.py").exists():
        return True
    # Also check the same directory as the importing file
    if file_path:
        file_dir = Path(file_path).resolve().parent
        if (file_dir / f"{pkg}.py").exists():
            return True
        if (file_dir / pkg).is_dir():
            return True
    return False


def check_hallucinated_packages(code: str, language: str, file_path: str = "") -> list[PackageResult]:
    # Skip Django migration files entirely — they're auto-generated by makemigrations
    # and import from real Django packages with stable import paths. Scanning them
    # for hallucinated packages only produces noise.
    if file_path:
        fp = Path(file_path)
        if "migrations" in fp.parts and fp.suffix == ".py":
            return []

    imports = extract_imports(code, language)
    seen = set()
    results = []

    for line_num, pkg, raw_line in imports:
        if pkg in seen:
            continue
        seen.add(pkg)

        # Skip packages that exist as local directories in the repo — they're
        # local subpackages, not hallucinated names.
        if _is_local_package(pkg, file_path):
            continue

        if language == "python":
            exists = _check_pypi(pkg)
            ecosystem = "pypi"
        else:
            exists = _check_npm(pkg)
            ecosystem = "npm"

        if not exists:
            results.append(PackageResult(
                name=pkg,
                ecosystem=ecosystem,
                exists=False,
                line_number=line_num,
                line=raw_line,
            ))

    return results
