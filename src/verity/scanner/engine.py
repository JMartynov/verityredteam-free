"""Scanner engine orchestrating multi-file AST vulnerability analysis."""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from verity.scanner.models import AstFinding, ScannerSeverity, ScanReport
from verity.scanner.python_ast import scan_python_file

logger = logging.getLogger("verity.scanner.engine")

IGNORE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "artifacts",
    "build",
    "dist",
}

SEVERITY_ORDER = {
    ScannerSeverity.CRITICAL: 5,
    ScannerSeverity.HIGH: 4,
    ScannerSeverity.MEDIUM: 3,
    ScannerSeverity.LOW: 2,
    ScannerSeverity.INFO: 1,
}


class McpAstScannerEngine:
    """Orchestrator for scanning MCP server repositories and files."""

    def __init__(
        self,
        min_severity: ScannerSeverity = ScannerSeverity.INFO,
        excluded_dirs: Sequence[str] | None = None,
    ) -> None:
        self.min_severity = min_severity
        self.excluded_dirs = set(excluded_dirs) if excluded_dirs else IGNORE_DIRS

    def scan_path(
        self,
        target_path: str | Path,
        *,
        project_root: Path | None = None,
        ignore_matcher: Any | None = None,
    ) -> ScanReport:
        """Scan a specific file or recursively scan a directory for vulnerabilities."""
        if project_root is not None:
            from verity.baseline.paths import canonicalize_path

        start_time = time.perf_counter()
        target = Path(target_path).resolve()

        scanned_files: list[str] = []
        all_findings: list[AstFinding] = []
        error_count = 0

        if target.is_file():
            if ignore_matcher is not None and ignore_matcher.is_ignored(target, is_dir=False):
                files_to_scan = []
            else:
                files_to_scan = [target]
        elif target.is_dir():
            files_to_scan = []
            for p in sorted(target.rglob("*.py")):
                if ignore_matcher is not None:
                    if ignore_matcher.is_ignored(p, is_dir=False):
                        continue
                elif any(ignored in p.parts for ignored in self.excluded_dirs):
                    continue
                files_to_scan.append(p)
        else:
            return ScanReport(
                target_path=str(target_path),
                scanned_files=[],
                findings=[],
                scan_duration_ms=0.0,
                error_count=1,
            )

        min_rank = SEVERITY_ORDER[self.min_severity]

        for file_path in files_to_scan:
            scanned_files.append(
                canonicalize_path(file_path, project_root=project_root)
                if project_root is not None
                else str(file_path)
            )
            try:
                findings = scan_python_file(file_path)
                for f in findings:
                    if SEVERITY_ORDER[f.severity] >= min_rank:
                        if project_root is not None:
                            f = replace(
                                f,
                                file_path=canonicalize_path(
                                    f.file_path, project_root=project_root
                                ),
                            )
                        all_findings.append(f)
            except Exception as e:
                logger.warning(f"Error scanning file {file_path}: {e}")
                error_count += 1

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        return ScanReport(
            target_path=str(target_path),
            scanned_files=scanned_files,
            findings=all_findings,
            scan_duration_ms=duration_ms,
            error_count=error_count,
        )
