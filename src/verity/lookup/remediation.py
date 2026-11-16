"""Safe upgrade calculator and mitigation guidance generator for MCP packages."""

from __future__ import annotations

from verity.lookup.models import UpgradeAdvice, VulnerabilityMatch
from verity.lookup.resolver import VersionResolver


class RemediationCalculator:
    """Computes safe minimal non-vulnerable upgrade versions and mitigation advice."""

    @classmethod
    def calculate_upgrade(
        cls,
        current_version: str | None,
        matches: list[VulnerabilityMatch],
    ) -> UpgradeAdvice:
        """Calculate the optimal safe version and actionable remediation guidance."""
        if not matches:
            return UpgradeAdvice(
                current_version=current_version or "unspecified",
                is_vulnerable=False,
                action_summary="No known vulnerabilities detected for this package version.",
            )

        # Collect all fixed versions across matched vulnerabilities
        fixed_versions: list[str] = []
        mitigation_steps: list[str] = []

        for m in matches:
            if m.fixed:
                fixed_versions.append(m.fixed)
            if m.remediation_guidance and m.remediation_guidance not in mitigation_steps:
                mitigation_steps.append(m.remediation_guidance)

        # If current_version is provided, find minimal fixed version > current_version
        recommended_version: str | None = None
        if fixed_versions:
            sorted_fixes = sorted(
                fixed_versions,
                key=lambda f: (
                    VersionResolver.parse_version(f) or VersionResolver.clean_version_string(f)
                ),
            )
            if current_version:
                for fix in sorted_fixes:
                    if VersionResolver.compare(fix, current_version) > 0:
                        recommended_version = fix
                        break
            if not recommended_version:
                recommended_version = sorted_fixes[-1]

        has_direct_fix = recommended_version is not None

        if has_direct_fix:
            action = f"Upgrade package to version >= {recommended_version}"
        elif mitigation_steps:
            action = "Apply vendor configuration workarounds (no direct patch available)"
        else:
            action = "Review exposed tool permissions and restrict network/transport access"

        return UpgradeAdvice(
            current_version=current_version or "unspecified",
            is_vulnerable=True,
            recommended_version=recommended_version,
            has_direct_fix=has_direct_fix,
            action_summary=action,
            mitigation_steps=tuple(mitigation_steps),
        )
