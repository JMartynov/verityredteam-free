"""Data models for MCP vulnerability lookup, matching, and safe upgrade recommendations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class VulnerabilityMatch:
    """Represents a matched vulnerability affecting a specific package version."""

    vulnerability_id: str
    summary: str
    details: str
    package_name: str
    ecosystem: str
    purl: str | None = None
    aliases: tuple[str, ...] = ()
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe_ids: tuple[str, ...] = ()
    vulnerable_tools: tuple[str, ...] = ()
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    remediation_guidance: str | None = None
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize vulnerability match to a dictionary."""
        return {
            "vulnerability_id": self.vulnerability_id,
            "summary": self.summary,
            "details": self.details,
            "package_name": self.package_name,
            "ecosystem": self.ecosystem,
            "purl": self.purl,
            "aliases": list(self.aliases),
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cwe_ids": list(self.cwe_ids),
            "vulnerable_tools": list(self.vulnerable_tools),
            "introduced": self.introduced,
            "fixed": self.fixed,
            "last_affected": self.last_affected,
            "remediation_guidance": self.remediation_guidance,
            "references": list(self.references),
        }


@dataclass(frozen=True)
class UpgradeAdvice:
    """Safe upgrade recommendation and remediation advice."""

    current_version: str
    is_vulnerable: bool
    recommended_version: str | None = None
    has_direct_fix: bool = False
    action_summary: str = ""
    mitigation_steps: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize upgrade advice to a dictionary."""
        return {
            "current_version": self.current_version,
            "is_vulnerable": self.is_vulnerable,
            "recommended_version": self.recommended_version,
            "has_direct_fix": self.has_direct_fix,
            "action_summary": self.action_summary,
            "mitigation_steps": list(self.mitigation_steps),
        }


@dataclass
class LookupResult:
    """Result of a vulnerability lookup query for an MCP package/server."""

    queried_identifier: str
    queried_version: str | None = None
    package_name: str | None = None
    matched_purl: str | None = None
    is_vulnerable: bool = False
    max_severity: str = "NONE"
    max_cvss_score: float | None = None
    vulnerabilities: list[VulnerabilityMatch] = field(default_factory=list)
    all_vulnerable_tools: list[str] = field(default_factory=list)
    all_cwe_ids: list[str] = field(default_factory=list)
    upgrade_advice: UpgradeAdvice | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize lookup result to a dictionary."""
        return {
            "queried_identifier": self.queried_identifier,
            "queried_version": self.queried_version,
            "package_name": self.package_name,
            "matched_purl": self.matched_purl,
            "is_vulnerable": self.is_vulnerable,
            "max_severity": self.max_severity,
            "max_cvss_score": self.max_cvss_score,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "all_vulnerable_tools": self.all_vulnerable_tools,
            "all_cwe_ids": self.all_cwe_ids,
            "upgrade_advice": self.upgrade_advice.to_dict() if self.upgrade_advice else None,
        }
