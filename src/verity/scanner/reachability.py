"""Transitive dependency reachability analysis."""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger("verity.scanner.reachability")

_MANIFEST_PARSERS: dict[str, str] = {
    "package.json": "parse_package_json",
    "requirements.txt": "parse_requirements_txt",
    "uv.lock": "parse_uv_lock",
    "poetry.lock": "parse_poetry_lock",
    "pyproject.toml": "parse_pyproject_toml",
}

AdvisoryLookup = Callable[[str, str | None, str], list[dict[str, Any]]]


def scan_transitive_reachability(
    source_dir: str | Path,
    manifest_path: str | Path,
    *,
    offline: bool = False,
    call_analysis: bool = True,
    reachable_only: bool = False,
    local_lookup: AdvisoryLookup | None = None,
) -> list[dict[str, Any]]:
    """Correlate manifest dependencies with advisories and code reachability."""
    src = Path(source_dir)
    manifest = Path(manifest_path)
    deps = _parse_manifest(manifest)
    if not deps:
        return []

    reachability: dict[str, Any] = {}
    if call_analysis:
        reachability = _analyze_reachability(src, deps)

    findings: list[dict[str, Any]] = []
    for name, version, ecosystem in deps:
        advisories = _lookup_advisories(
            name, version, ecosystem, offline=offline, local_lookup=local_lookup
        )
        if not advisories:
            continue

        info = reachability.get(name.lower())
        raw_status = getattr(info, "status", None)
        status = str(getattr(raw_status, "value", raw_status) or "NOT_IMPORTED")
        reached_from = list(getattr(info, "reachable_from_tools", []) or [])

        if reachable_only and status != "REACHABLE":
            continue

        for advisory in advisories:
            findings.append(
                {
                    "rule_id": f"VULN-{advisory.get('id') or 'UNKNOWN'}",
                    "scanner": "reachability",
                    "severity": _coerce_severity(advisory.get("severity")),
                    "cve_id": advisory.get("id"),
                    "package_name": name,
                    "installed_version": version,
                    "ecosystem": ecosystem,
                    "vulnerability_id": advisory.get("id"),
                    "summary": advisory.get("summary", ""),
                    "fixed_version": advisory.get("fixed_version"),
                    "cvss_score": advisory.get("cvss_score"),
                    "reachability": status,
                    "reachable_from_tools": reached_from,
                }
            )
    return findings


def _coerce_severity(raw: Any) -> str:
    text = str(getattr(raw, "value", raw) or "INFO").upper()
    return text if text in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "MEDIUM"


def _parse_manifest(manifest: Path) -> list[tuple[str, str | None, str]]:
    parser_name = _MANIFEST_PARSERS.get(manifest.name.lower())
    if parser_name is None:
        return []
    try:
        from mcp_vulnerabilities.transitive import TransitiveDependencyAuditor

        auditor = TransitiveDependencyAuditor()
        parser = getattr(auditor, parser_name, None)
        if parser is None:
            return []
        result = parser(manifest)
        return [
            (str(name), version, str(ecosystem))
            for name, version, ecosystem in (result or [])
        ]
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Manifest parse failed for %s: %s", manifest, exc)
        return []


def _analyze_reachability(
    source_dir: Path,
    deps: list[tuple[str, str | None, str]],
) -> dict[str, Any]:
    try:
        from mcp_vulnerabilities.analyzers.reachability import AstReachabilityAnalyzer

        analyzer = AstReachabilityAnalyzer()
        report = analyzer.analyze_directory(str(source_dir))
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Reachability analysis unavailable: %s", exc)
        return {}

    results: dict[str, Any] = {}
    for name, _version, _ecosystem in deps:
        try:
            results[name.lower()] = analyzer.evaluate_package(name, report)
        except Exception:
            continue
    return results


def _lookup_advisories(
    name: str,
    version: str | None,
    ecosystem: str,
    *,
    offline: bool,
    local_lookup: AdvisoryLookup | None,
) -> list[dict[str, Any]]:
    if local_lookup is not None:
        try:
            return list(local_lookup(name, version, ecosystem) or [])
        except Exception:
            return []

    if offline:
        return _query_local_engine(name, version)

    return _audit_dependencies(name, version, ecosystem)


def _query_local_engine(name: str, version: str | None) -> list[dict[str, Any]]:
    try:
        from verity.lookup.engine import VulnerabilityLookupEngine

        result = VulnerabilityLookupEngine.from_auto().query(
            identifier=name, version=version or ""
        )
    except Exception:
        return []

    advisories: list[dict[str, Any]] = []
    for match in getattr(result, "vulnerabilities", []) or []:
        advisories.append(
            {
                "id": getattr(match, "vulnerability_id", None),
                "summary": getattr(match, "summary", ""),
                "severity": getattr(match, "severity", "MEDIUM"),
                "cvss_score": getattr(match, "cvss_score", None),
                "fixed_version": getattr(match, "fixed", None),
            }
        )
    return advisories


def _audit_dependencies(
    name: str, version: str | None, ecosystem: str
) -> list[dict[str, Any]]:
    try:
        from mcp_vulnerabilities.transitive import TransitiveDependencyAuditor

        auditor = TransitiveDependencyAuditor()
        raw = auditor.audit_dependencies([(name, version, ecosystem)])
    except Exception:
        return []

    advisories: list[dict[str, Any]] = []
    for item in raw or []:
        advisories.append(
            {
                "id": getattr(item, "vulnerability_id", None),
                "summary": getattr(item, "summary", ""),
                "severity": getattr(item, "severity", "MEDIUM"),
                "cvss_score": getattr(item, "cvss_score", None),
                "fixed_version": getattr(item, "fixed_version", None),
            }
        )
    return advisories
