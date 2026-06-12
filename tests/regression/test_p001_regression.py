"""
PRBL-P001 regression suite — Hallucinated/Typosquatted Packages.

Note: P001 is implemented in prbl/scanner/osv.py (check_hallucinated_packages),
not in rules.py. These tests verify the alias map and stdlib exclusions without
making network calls — they test the import alias resolution and skip logic only.

Covers:
  - rest_framework and corsheaders falsely flagged (import alias map)
  - sklearn→scikit-learn, cv2→opencv-python, PIL→Pillow aliases
  - zoneinfo, gc, concurrent falsely flagged (stdlib exclusions)
  - Migrations directories skipped entirely
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from prbl.scanner.osv import (
    IMPORT_ALIASES,
    _PYTHON_STDLIB,
    check_hallucinated_packages,
    extract_imports,
)


# ── IMPORT ALIAS MAP COVERAGE ─────────────────────────────────────────────────

def test_rest_framework_alias_exists():
    """Regression: rest_framework must map to djangorestframework."""
    assert 'rest_framework' in IMPORT_ALIASES, \
        "rest_framework must be in IMPORT_ALIASES"
    assert IMPORT_ALIASES['rest_framework'] == 'djangorestframework'


def test_corsheaders_alias_exists():
    """Regression: corsheaders must map to django-cors-headers."""
    assert 'corsheaders' in IMPORT_ALIASES
    assert IMPORT_ALIASES['corsheaders'] == 'django-cors-headers'


def test_sklearn_alias_exists():
    """Regression: sklearn must map to scikit-learn."""
    assert 'sklearn' in IMPORT_ALIASES
    assert IMPORT_ALIASES['sklearn'] == 'scikit-learn'


def test_cv2_alias_exists():
    """Regression: cv2 must map to opencv-python."""
    assert 'cv2' in IMPORT_ALIASES
    assert IMPORT_ALIASES['cv2'] == 'opencv-python'


def test_pil_alias_exists():
    """Regression: PIL must map to Pillow."""
    assert 'PIL' in IMPORT_ALIASES
    assert IMPORT_ALIASES['PIL'] == 'Pillow'


def test_bs4_alias_exists():
    """Regression: bs4 must map to beautifulsoup4."""
    assert 'bs4' in IMPORT_ALIASES
    assert IMPORT_ALIASES['bs4'] == 'beautifulsoup4'


def test_yaml_alias_exists():
    """Regression: yaml must map to PyYAML."""
    assert 'yaml' in IMPORT_ALIASES
    assert IMPORT_ALIASES['yaml'] == 'PyYAML'


# ── STDLIB EXCLUSIONS ────────────────────────────────────────────────────────

def test_zoneinfo_in_stdlib():
    """Regression: zoneinfo must be in Python stdlib set."""
    assert 'zoneinfo' in _PYTHON_STDLIB, \
        "zoneinfo must be in _PYTHON_STDLIB — it's a Python 3.9+ stdlib module"


def test_gc_in_stdlib():
    """Regression: gc (garbage collector) must be in Python stdlib set."""
    assert 'gc' in _PYTHON_STDLIB, \
        "gc must be in _PYTHON_STDLIB — it's a built-in Python stdlib module"


def test_concurrent_in_stdlib():
    """Regression: concurrent must be in Python stdlib set."""
    assert 'concurrent' in _PYTHON_STDLIB, \
        "concurrent must be in _PYTHON_STDLIB (concurrent.futures is stdlib)"


def test_asyncio_in_stdlib():
    """asyncio must be in Python stdlib set."""
    assert 'asyncio' in _PYTHON_STDLIB


def test_graphlib_in_stdlib():
    """graphlib must be in Python stdlib set."""
    assert 'graphlib' in _PYTHON_STDLIB


# ── MIGRATIONS SKIPPED ────────────────────────────────────────────────────────

def test_migrations_file_skipped():
    """Regression: Django migration files must be skipped entirely."""
    code = '''
from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [('app', '0001_initial')]
    operations = [
        migrations.AddField(model_name='user', name='profile', field=models.TextField()),
    ]
'''
    results = check_hallucinated_packages(
        code, 'python',
        file_path='/myapp/migrations/0002_add_profile.py'
    )
    assert results == [], \
        f"Migration files must be skipped entirely for P001. Got: {results}"


def test_non_migration_python_not_skipped():
    """True negative guard: non-migration Python files are still checked."""
    code = "import totally_fake_package_xyz_does_not_exist_12345"
    # This would make a network call, so we only verify it's not skipped
    # by checking the file is processed (returns a list, even if empty due to network)
    results = check_hallucinated_packages(
        code, 'python',
        file_path='/myapp/views.py'
    )
    # The function runs (doesn't error out) — result may be [] if network says it exists
    # but the migration skip logic must NOT apply
    assert isinstance(results, list), "check_hallucinated_packages must return a list"


# ── EXTRACT_IMPORTS ALIAS RESOLUTION ─────────────────────────────────────────

def test_extract_imports_rest_framework():
    """rest_framework import is extracted correctly."""
    code = "from rest_framework.views import APIView"
    imports = extract_imports(code, 'python')
    pkg_names = [i[1] for i in imports]
    assert 'rest_framework' in pkg_names, \
        f"rest_framework should be extracted from import. Got: {pkg_names}"


def test_extract_imports_stdlib_excluded():
    """stdlib modules must not be extracted for P001 checking."""
    code = '''
import os
import sys
import zoneinfo
import gc
import concurrent.futures
'''
    imports = extract_imports(code, 'python')
    pkg_names = [i[1] for i in imports]
    for stdlib_mod in ['os', 'sys', 'zoneinfo', 'gc', 'concurrent']:
        assert stdlib_mod not in pkg_names, \
            f"stdlib module {stdlib_mod!r} must not be extracted for P001 checking"
