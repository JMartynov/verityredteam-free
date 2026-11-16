"""Open-core plugin protocols and graceful-degradation helpers for Verity."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

__all__ = [
    "BasicConditionVerificationResult",
    "BasicResponseOracle",
    "DatabaseOracleProtocol",
    "pro_feature_required_response",
]


class DatabaseOracleProtocol(Protocol):
    """Protocol for physical database verification oracles.

    Implemented by enterprise (``verity-pro``) plugins to verify tool
    behaviour against ground-truth live database state. The open-core
    fallback is :class:`BasicResponseOracle`.
    """

    def execute_physical_verification(
        self,
        engine: str,
        query: str | dict[str, Any],
        expected_tenant: str | None = None,
    ) -> dict[str, Any]:
        """Run ``query`` against a live ``engine`` and return observed state."""
        ...

    def verify_condition(
        self,
        condition_id: str,
        tool_response: dict[str, Any],
        mcp_arguments: dict[str, Any],
        profile: str,
    ) -> Any:
        """Verify ``condition_id`` against an observed tool response."""
        ...


@dataclass
class BasicConditionVerificationResult:
    """Response-level verification result produced by the open-core oracle."""

    condition_id: str
    status: str
    details: str
    evidence: str
    observed_in_database: bool = False


class BasicResponseOracle:
    """Open-core oracle performing response-level checks only.

    Physical database verification is a Pro capability; this fallback
    returns a structured ``PRO_FEATURE_REQUIRED`` payload instead of
    raising ``ImportError`` when ``verity-pro`` is not installed.
    """

    def execute_physical_verification(
        self,
        engine: str,
        query: str | dict[str, Any],
        expected_tenant: str | None = None,
    ) -> dict[str, Any]:
        return {
            "ok": False,
            "error": "PRO_FEATURE_REQUIRED",
            "message": "Physical database verification requires verity-pro plugin.",
        }

    def verify_condition(
        self,
        condition_id: str,
        tool_response: dict[str, Any],
        mcp_arguments: dict[str, Any],
        profile: str,
    ) -> Any:
        status = "VERIFIED" if tool_response.get("ok") else "BLOCKED"
        return BasicConditionVerificationResult(
            condition_id=condition_id,
            status=status,
            details="Basic response-level verification completed.",
            evidence=str(tool_response)[:200],
            observed_in_database=False,
        )


def pro_feature_required_response(
    action: str,
    feature_desc: str | None = None,
) -> dict[str, Any]:
    """Build a structured ``PRO_FEATURE_REQUIRED`` payload for missing Pro features."""
    return {
        "ok": False,
        "action": action,
        "error": "PRO_FEATURE_REQUIRED",
        "verdict": "PRO_REQUIRED",
        "message": feature_desc
        or f"Action '{action}' requires the verity-pro enterprise plugin.",
    }
