"""
PrblScanner — orchestrates static rules + package registry checks.
Runs on top of the Phase 1 detector, adding vulnerability findings.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .rules import RuleMatch, run_all_rules
from .osv import PackageResult, check_hallucinated_packages

LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}


@dataclass
class ScanFinding:
    vuln_class: str
    rule_id: str
    severity: str
    line_number: int
    line: str
    title: str
    detail: str
    fix: str
    file: str = ""


@dataclass
class FileScanResult:
    file: str
    language: str
    findings: list[ScanFinding] = field(default_factory=list)

    @property
    def high(self) -> list[ScanFinding]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def medium(self) -> list[ScanFinding]:
        return [f for f in self.findings if f.severity == "medium"]

    @property
    def low(self) -> list[ScanFinding]:
        return [f for f in self.findings if f.severity == "low"]


class PrblScanner:
    def __init__(self, check_packages: bool = True):
        self.check_packages = check_packages

    def scan_code(self, code: str, language: str, file_path: str = "") -> FileScanResult:
        result = FileScanResult(file=file_path, language=language)

        # Static rules (offline)
        for match in run_all_rules(code, language, file_path=file_path):
            result.findings.append(ScanFinding(
                vuln_class=match.vuln_class,
                rule_id=match.rule_id,
                severity=match.severity,
                line_number=match.line_number,
                line=match.line,
                title=match.title,
                detail=match.detail,
                fix=match.fix,
                file=file_path,
            ))

        # Package registry checks (requires network)
        if self.check_packages:
            for pkg in check_hallucinated_packages(code, language, file_path=file_path):
                result.findings.append(ScanFinding(
                    vuln_class="hallucinated_package",
                    rule_id="PRBL-P001",
                    severity="high",
                    line_number=pkg.line_number,
                    line=pkg.line,
                    title=f"Package not found on {pkg.ecosystem}: '{pkg.name}'",
                    detail=(
                        f"'{pkg.name}' does not exist on {pkg.ecosystem}. "
                        "AI models invent plausible-sounding package names that don't exist. "
                        "If an attacker registers this name with a malicious payload, "
                        "anyone running install on this codebase gets code execution."
                    ),
                    fix=f"Verify the correct package name on {'npmjs.com' if pkg.ecosystem == 'npm' else 'pypi.org'} and update the import.",
                    file=file_path,
                ))

        # Sort: high severity first, then by line number
        result.findings.sort(key=lambda f: (f.severity != "high", f.severity != "medium", f.line_number))
        return result

    def scan_file(self, path: Path, check_packages: Optional[bool] = None) -> FileScanResult:
        ext = path.suffix.lower()
        language = LANGUAGE_MAP.get(ext, "python")
        code = path.read_text(encoding="utf-8", errors="ignore")
        do_pkg = check_packages if check_packages is not None else self.check_packages
        scanner = PrblScanner(check_packages=do_pkg)
        return scanner.scan_code(code, language, file_path=str(path))

    def scan_directory(
        self,
        directory: Path,
        check_packages: bool = True,
        skip_dirs: Optional[set] = None,
    ) -> list[FileScanResult]:
        if skip_dirs is None:
            skip_dirs = {"node_modules", ".venv", "venv", "env", "__pycache__",
                         ".git", "dist", "build", ".next", ".pip_pillow"}

        results = []
        for path in sorted(directory.rglob("*")):
            if not path.is_file():
                continue
            if any(skip in path.parts for skip in skip_dirs):
                continue
            if path.suffix.lower() not in LANGUAGE_MAP:
                continue
            results.append(self.scan_file(path, check_packages=check_packages))

        return [r for r in results if r.findings]  # only files with findings
