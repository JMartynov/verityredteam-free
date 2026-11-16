"""Onboarding controller enforcing paired-connection invariants and profile lifecycle."""

from __future__ import annotations

import time
import uuid
from typing import Any

from verity.onboarding.models import (
    ConnectionAndPolicyProfile,
    McpSurfaceAssessment,
    OnboardingState,
)
from verity.ucp.engine import UnknownCapabilityProfiler


class OnboardingController:
    """Enforces dual-layer paired connection invariants and manages target lifecycle."""

    @classmethod
    def validate_paired_connection(
        cls,
        mcp_conn: dict[str, Any],
        db_conn: dict[str, Any] | None,
    ) -> tuple[bool, str]:
        """Validate both MCP transport and database connections."""
        if not mcp_conn.get("authenticated", False):
            return False, "MCP_AUTH_FAILED: MCP server connection failed to authenticate."

        if db_conn is None or not db_conn.get("authenticated", False):
            return (
                False,
                (
                    "MISSING_DB_CONNECTION: Database target was not provided "
                    "or failed to authenticate."
                ),
            )

        return True, "PAIRED_CONNECTION_VALID"

    @classmethod
    def onboard_target(
        cls,
        mcp_conn: dict[str, Any],
        db_conn: dict[str, Any] | None,
        tools: list[dict[str, Any]],
        operator_approval: bool = False,
        read_authorized: bool = True,
        mutation_authorized: bool = False,
    ) -> ConnectionAndPolicyProfile | McpSurfaceAssessment:
        """Onboard an MCP server and paired database target."""
        is_paired, reason = cls.validate_paired_connection(mcp_conn, db_conn)

        if not is_paired and (db_conn is None or not db_conn.get("authenticated", False)):
            # Generate incomplete-onboarding surface assessment
            tool_names = tuple(str(t.get("name", "")) for t in tools)
            declarations = {t.get("name", ""): t.get("description", "") for t in tools}
            return McpSurfaceAssessment(
                mcp_endpoint=str(mcp_conn.get("endpoint", "stdio")),
                discovered_tools=tool_names,
                untrusted_declarations=declarations,
                hypotheses=(
                    "Unverified MCP tools observed without database ground-truth validation.",
                ),
                missing_capabilities=(
                    "DATABASE_VERIFICATION",
                    "TENANT_GROUND_TRUTH_ISOLATION",
                ),
                status=OnboardingState.INCOMPLETE_PREFLIGHT,
            )

        if not is_paired:
            raise ValueError(f"Onboarding rejected: {reason}")

        if not operator_approval:
            raise PermissionError(
                "Explicit operator scope approval is required before target can be ONBOARDED."
            )

        # Compute canonical tool hashes via UCP
        tool_profiles = UnknownCapabilityProfiler.profile_toolset(tools)
        tool_hashes = {name: profile.canonical_hash for name, profile in tool_profiles.items()}

        profile_id = f"prof_{uuid.uuid4().hex[:12]}"
        assert db_conn is not None

        return ConnectionAndPolicyProfile(
            profile_id=profile_id,
            version=1,
            mcp_endpoint=str(mcp_conn.get("endpoint", "stdio")),
            mcp_transport=str(mcp_conn.get("transport", "stdio")),
            database_target=str(db_conn.get("target_id", "default_db")),
            database_type=str(db_conn.get("database_type", "mongodb")),
            authorized_tool_hashes=tool_hashes,
            read_authorized=read_authorized,
            mutation_authorized=mutation_authorized,
            status=OnboardingState.ONBOARDED,
            created_at=str(int(time.time())),
        )

    @classmethod
    def revalidate_profile(
        cls,
        profile: ConnectionAndPolicyProfile,
        live_tools: list[dict[str, Any]],
        live_db_conn: dict[str, Any],
    ) -> tuple[bool, str]:
        """Revalidate an existing profile before executing scans or queries."""
        if profile.status == OnboardingState.REVOKED:
            return False, "PROFILE_REVOKED: Target authorization was revoked by operator."

        # Check DB connectivity
        if not live_db_conn.get("authenticated", False):
            return False, "DATABASE_UNAVAILABLE: Paired database re-authentication failed."

        # Check for rug pulls
        drift_results = UnknownCapabilityProfiler.detect_rug_pull(
            authorized_hashes=profile.authorized_tool_hashes,
            current_tools=live_tools,
        )

        rug_pulls = [r for r in drift_results if r.is_rug_pull]
        if rug_pulls:
            details = "; ".join(r.details for r in rug_pulls)
            return False, f"RUG_PULL_DETECTED: {details}"

        return True, "REVALIDATION_SUCCESS"

    @classmethod
    def revoke_profile(
        cls,
        profile: ConnectionAndPolicyProfile,
    ) -> ConnectionAndPolicyProfile:
        """Revoke target authorization immediately."""
        return ConnectionAndPolicyProfile(
            profile_id=profile.profile_id,
            version=profile.version + 1,
            mcp_endpoint=profile.mcp_endpoint,
            mcp_transport=profile.mcp_transport,
            database_target=profile.database_target,
            database_type=profile.database_type,
            authorized_tool_hashes=profile.authorized_tool_hashes,
            read_authorized=False,
            mutation_authorized=False,
            status=OnboardingState.REVOKED,
            created_at=profile.created_at,
        )
