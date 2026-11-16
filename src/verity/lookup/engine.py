"""Core MCP Vulnerability Lookup Engine coordinating indexing, querying, and SemVer resolution."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.models import OsvVulnerability

from verity.lookup.index import VulnerabilityIndex
from verity.lookup.models import LookupResult, VulnerabilityMatch
from verity.lookup.remediation import RemediationCalculator
from verity.lookup.resolver import VersionResolver

logger = logging.getLogger("verity.lookup.engine")


class VulnerabilityLookupEngine:
    """High-performance query engine evaluating MCP server packages."""

    PURL_REGEX = re.compile(
        r"^pkg:([a-zA-Z0-9.\-_]+)/(@?[a-zA-Z0-9.\-_/]+)(?:@([a-zA-Z0-9.\-_+]+))?"
    )

    def __init__(self, index: VulnerabilityIndex | None = None) -> None:
        self.index = index or VulnerabilityIndex()

    @classmethod
    def from_directory(
        cls, directory: str | Path = "data/vulnerabilities"
    ) -> VulnerabilityLookupEngine:
        """Create and initialize a lookup engine from an OSV vulnerability directory."""
        index = VulnerabilityIndex()
        index.load_from_directory(directory)
        return cls(index=index)

    @classmethod
    def from_snapshot(
        cls, snapshot_data: dict[str, Any] | str | Path | bytes
    ) -> VulnerabilityLookupEngine:
        """Create and initialize a lookup engine directly from a consolidated snapshot."""
        index = VulnerabilityIndex()
        index.load_from_snapshot(snapshot_data)
        return cls(index=index)

    @classmethod
    def from_auto(
        cls, directory: str | Path = "data/vulnerabilities", force_refresh: bool = False
    ) -> VulnerabilityLookupEngine:
        """Create lookup engine from local directory if present, else latest public snapshot."""
        index = VulnerabilityIndex()
        index.load_auto(directory=directory, force_refresh=force_refresh)
        return cls(index=index)

    def query(
        self,
        identifier: str,
        version: str | None = None,
    ) -> LookupResult:
        """Query the vulnerability index for an MCP package identifier and version."""
        parsed_pkg, parsed_ver, parsed_purl = self._parse_target(identifier, version)

        # Retrieve candidate vulnerabilities
        candidates: list[OsvVulnerability] = []
        if parsed_purl:
            candidates.extend(self.index.get_by_purl(parsed_purl))

        if parsed_pkg:
            for vuln in self.index.get_by_package_name(parsed_pkg):
                if vuln not in candidates:
                    candidates.append(vuln)

        # If identifier matches a CVE/GHSA ID directly
        if not candidates:
            candidates.extend(self.index.get_by_id_or_alias(identifier))

        # Evaluate SemVer range matching for each candidate
        matches: list[VulnerabilityMatch] = []
        all_tools: set[str] = set()
        all_cwes: set[str] = set()
        max_cvss = 0.0
        max_severity = "NONE"
        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

        for vuln in candidates:
            # Find relevant affected package block
            for aff in vuln.affected:
                if parsed_pkg and not self._is_pkg_match(parsed_pkg, aff.package.name):
                    continue

                # Check version ranges
                is_affected = False
                introduced: str | None = None
                fixed: str | None = None
                last_affected: str | None = None

                if not parsed_ver:
                    # No version supplied: report as candidate match
                    is_affected = True
                else:
                    if not aff.ranges:
                        # No range restrictions: whole package affected
                        is_affected = True
                    else:
                        for r in aff.ranges:
                            for ev in r.events:
                                if ev.introduced:
                                    introduced = ev.introduced
                                if ev.fixed:
                                    fixed = ev.fixed
                                if ev.last_affected:
                                    last_affected = ev.last_affected

                            if VersionResolver.is_version_in_range(
                                candidate_version=parsed_ver,
                                introduced=introduced,
                                fixed=fixed,
                                last_affected=last_affected,
                            ):
                                is_affected = True
                                break

                if is_affected:
                    db = aff.database_specific
                    sev = "UNKNOWN"
                    if db and db.severity:
                        sev = db.severity.upper()
                    elif vuln.database_specific and vuln.database_specific.get("severity"):
                        sev = str(vuln.database_specific["severity"]).upper()

                    score = db.cvss_score if db else None
                    if score and score > max_cvss:
                        max_cvss = score
                    if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                        max_severity = sev

                    match_tools = db.vulnerable_tools if db else ()
                    match_cwes = db.cwe_ids if db else ()
                    for t in match_tools:
                        all_tools.add(t)
                    for c in match_cwes:
                        all_cwes.add(c)

                    match = VulnerabilityMatch(
                        vulnerability_id=vuln.id,
                        summary=vuln.summary,
                        details=vuln.details,
                        package_name=aff.package.name,
                        ecosystem=aff.package.ecosystem,
                        purl=aff.package.purl,
                        aliases=vuln.aliases,
                        severity=sev,
                        cvss_score=score,
                        cvss_vector=db.cvss_v3_vector or db.cvss_v4_vector if db else None,
                        cwe_ids=match_cwes,
                        vulnerable_tools=match_tools,
                        introduced=introduced,
                        fixed=fixed,
                        last_affected=last_affected,
                        remediation_guidance=db.remediation_guidance if db else None,
                        references=tuple(r.url for r in vuln.references),
                    )
                    matches.append(match)

        # Compute safe upgrade recommendation
        upgrade_advice = RemediationCalculator.calculate_upgrade(
            current_version=parsed_ver,
            matches=matches,
        )

        return LookupResult(
            queried_identifier=identifier,
            queried_version=parsed_ver,
            package_name=parsed_pkg,
            matched_purl=parsed_purl,
            is_vulnerable=len(matches) > 0,
            max_severity=max_severity if matches else "NONE",
            max_cvss_score=max_cvss if max_cvss > 0 else None,
            vulnerabilities=matches,
            all_vulnerable_tools=sorted(list(all_tools)),
            all_cwe_ids=sorted(list(all_cwes)),
            upgrade_advice=upgrade_advice,
        )

    def search(
        self,
        query: str,
        by_tool: str | None = None,
        by_cwe: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Perform search across packages, tools, and CWE categories."""
        results: list[dict[str, Any]] = []

        if by_tool:
            for vuln in self.index.get_by_tool(by_tool):
                results.append(vuln.to_dict())
            return results[:limit]

        if by_cwe:
            for vuln in self.index.get_by_cwe(by_cwe):
                results.append(vuln.to_dict())
            return results[:limit]

        # Grep / substring search across packages
        matched_packages = self.index.search_packages(query, limit=limit)
        for pkg_name in matched_packages:
            vulns = self.index.get_by_package_name(pkg_name)
            results.append(
                {
                    "package_name": pkg_name,
                    "vulnerability_count": len(vulns),
                    "vulnerability_ids": [v.id for v in vulns],
                    "sample_summary": vulns[0].summary if vulns else "",
                }
            )

        return results[:limit]

    def _parse_target(
        self,
        identifier: str,
        explicit_version: str | None,
    ) -> tuple[str | None, str | None, str | None]:
        """Parse identifier into (package_name, version, purl)."""
        clean = identifier.strip()
        ver = explicit_version.strip() if explicit_version else None
        purl: str | None = None
        pkg: str | None = None

        # 1. PURL format check
        purl_match = self.PURL_REGEX.match(clean)
        if purl_match:
            pkg = purl_match.group(2)
            if not ver and purl_match.group(3):
                ver = purl_match.group(3)
            purl = clean.split("@")[0]
            return pkg, ver, purl

        # 2. Package@version format check
        if "@" in clean and not clean.startswith("@"):
            parts = clean.split("@", 1)
            pkg = parts[0]
            if not ver:
                ver = parts[1]
            return pkg, ver, None

        if clean.startswith("@") and clean.count("@") >= 2:
            # Scoped package with version: @scope/pkg@ver
            idx = clean.rfind("@")
            pkg = clean[:idx]
            if not ver:
                ver = clean[idx + 1 :]
            return pkg, ver, None

        pkg = clean
        return pkg, ver, None

    def _is_pkg_match(self, queried_pkg: str, candidate_pkg: str) -> bool:
        """Compare package names with case-insensitivity and scope normalization."""
        q = queried_pkg.strip().lower()
        c = candidate_pkg.strip().lower()
        if q == c:
            return True
        if "/" in c and q == c.split("/")[-1]:
            return True
        return bool("/" in q and c == q.split("/")[-1])
