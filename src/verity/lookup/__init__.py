"""Public exports for the MCP Vulnerability Lookup Engine & SemVer Resolver."""

from __future__ import annotations

from verity.lookup.engine import VulnerabilityLookupEngine
from verity.lookup.index import VulnerabilityIndex
from verity.lookup.models import LookupResult, UpgradeAdvice, VulnerabilityMatch
from verity.lookup.remediation import RemediationCalculator
from verity.lookup.resolver import VersionResolver

__all__ = [
    "LookupResult",
    "RemediationCalculator",
    "UpgradeAdvice",
    "VersionResolver",
    "VulnerabilityIndex",
    "VulnerabilityLookupEngine",
    "VulnerabilityMatch",
]
