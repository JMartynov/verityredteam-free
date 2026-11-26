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

VALID_SCANNERS: frozenset[str] = frozenset(
    {"all", "config", "vuln", "secret", "ast", "taint", "typosquat", "conflict"}
)

DEFAULT_OFFLINE_SCANNERS: frozenset[str] = frozenset(
    {"config", "vuln", "secret", "ast", "typosquat", "conflict"}
)

_SBOM_FORMATS: frozenset[str] = frozenset({"cyclonedx", "spdx"})

_TAINT_CWE_MAP: dict[str, str] = {
    "COMMAND_INJECTION": "CWE-78",
    "CODE_EVALUATION": "CWE-94",
    "PATH_TRAVERSAL": "CWE-22",
    "SQL_INJECTION": "CWE-89",
    "SSRF_EGRESS": "CWE-918",
}


def parse_scanners_arg(
    raw: str | None,
    *,
    fmt: str = "terminal",
    has_path: bool = False,
) -> frozenset[str]:
    """Resolve the ``--scanners`` argument into a validated scanner set."""
    if raw is None:
        if fmt in _SBOM_FORMATS:
            return frozenset()
        scanners = set(DEFAULT_OFFLINE_SCANNERS)
        if has_path:
            scanners.add("taint")
        return frozenset(scanners)

    tokens = [t.strip().lower() for t in str(raw).split(",") if t.strip()]
    if not tokens:
        raise ValueError("Unknown scanner: (empty)")
    if "all" in tokens:
        return VALID_SCANNERS - {"all"}
    resolved: set[str] = set()
    for token in tokens:
        if token not in VALID_SCANNERS:
            raise ValueError(f"Unknown scanner: {token}")
        if token == "all":
            continue
        resolved.add(token)
    return frozenset(resolved)


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

    def scan_with_taint(
        self,
        target_path: str | Path,
        *,
        include_ast: bool = True,
        include_taint: bool = True,
    ) -> list[dict[str, Any]]:
        """Run AST and (optionally) taint scans, deduplicating with taint priority."""
        path = Path(target_path)

        ast_items: list[dict[str, Any]] = []
        if include_ast:
            report = self.scan_path(path)
            for finding in report.findings:
                ast_items.append(self._normalize_ast_item(finding, path))

        taint_items: list[dict[str, Any]] = []
        if include_taint:
            taint_items = self._collect_taint_items(path)

        merged: dict[tuple[str, int, str], dict[str, Any]] = {}
        for item in ast_items:
            merged[self._dedupe_key(item)] = item
        for item in taint_items:
            merged[self._dedupe_key(item)] = item
        return list(merged.values())

    # ---- helpers ----

    @staticmethod
    def _dedupe_key(item: dict[str, Any]) -> tuple[str, int, str]:
        raw_path = str(item.get("file_path") or "")
        resolved = raw_path
        if raw_path:
            try:
                resolved = str(Path(raw_path).resolve())
            except Exception:
                resolved = raw_path
        try:
            line = int(item.get("line_number") or 0)
        except Exception:
            line = 0
        return resolved, line, str(item.get("cwe_id") or "")

    @classmethod
    def _normalize_ast_item(cls, finding: Any, default_path: Path) -> dict[str, Any]:
        if hasattr(finding, "to_dict"):
            data = dict(finding.to_dict())
        else:  # pragma: no cover - defensive
            data = dict(getattr(finding, "__dict__", {}))
        if not data.get("file_path"):
            data["file_path"] = str(default_path)
        if data.get("line_number") in (None, ""):
            data["line_number"] = 0

        cwe_ids = data.pop("cwe_ids", None)
        if isinstance(cwe_ids, (list, tuple)) and cwe_ids:
            data["cwe_id"] = str(cwe_ids[0])
        elif not data.get("cwe_id"):
            data["cwe_id"] = ""

        severity = data.get("severity")
        data["severity"] = str(getattr(severity, "value", severity) or "INFO").upper()
        data["scanner"] = "ast"
        return data

    def _collect_taint_items(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        try:
            from mcp_vulnerabilities.analyzers.ast_taint.scanner import McpSourceScanner

            raw = McpSourceScanner(str(path)).scan()
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Taint scan failed for %s: %s", path, exc)
            return []

        items: list[dict[str, Any]] = []
        for tf in raw or []:
            category = getattr(tf, "sink_category", None)
            category_name = str(getattr(category, "name", category) or "").upper()
            cwe_id = _TAINT_CWE_MAP.get(category_name, "CWE-20")
            raw_line = next(
                (
                    getattr(tf, attr, None)
                    for attr in ("sink_line", "line_number", "line")
                    if getattr(tf, attr, None) is not None
                ),
                0,
            )
            try:
                line = int(raw_line or 0)
            except (TypeError, ValueError):
                line = 0
            file_path = str(
                getattr(tf, "file_path", None)
                or getattr(tf, "source_file", None)
                or getattr(tf, "path", None)
                or path
            )
            severity = getattr(tf, "severity", "HIGH")
            items.append(
                {
                    "scanner": "taint",
                    "rule_id": f"TAINT-{category_name or 'UNKNOWN'}",
                    "cwe_id": cwe_id,
                    "severity": str(getattr(severity, "value", severity) or "HIGH").upper(),
                    "file_path": file_path,
                    "line_number": line,
                    "title": (
                        f"Tainted {category_name.lower() or 'input'} in tool "
                        f"'{getattr(tf, 'tool_name', '')}'"
                    ),
                    "message": (
                        f"Parameter '{getattr(tf, 'parameter_name', '')}' flows into "
                        f"'{getattr(tf, 'sink_call', '')}' without sanitization."
                    ),
                    "snippet": getattr(tf, "code_snippet", ""),
                    "remediation": getattr(tf, "remediation", ""),
                    "tool_name": getattr(tf, "tool_name", ""),
                }
            )
        return items
