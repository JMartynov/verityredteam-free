"""Domain models for Target Onboarding and Static MCP Configuration Assessment."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class OnboardingState(StrEnum):
    """Lifecycle state of an MCP target onboarding request."""

    PENDING = "PENDING"
    ONBOARDED = "ONBOARDED"
    REJECTED = "REJECTED"
    INCOMPLETE_PREFLIGHT = "INCOMPLETE_PREFLIGHT"
    REVOKED = "REVOKED"


@dataclass(frozen=True)
class ConnectionAndPolicyProfile:
    """Reusable, versioned target connection and policy profile."""

    profile_id: str
    version: int
    mcp_endpoint: str
    mcp_transport: str  # "http", "streamable_http", "stdio"
    database_target: str
    database_type: str  # "mongodb", "postgresql", "mysql", "snowflake"
    authorized_tool_hashes: dict[str, str]  # tool_name -> canonical_hash
    read_authorized: bool
    mutation_authorized: bool
    status: OnboardingState = OnboardingState.ONBOARDED
    created_at: str = ""


@dataclass(frozen=True)
class McpSurfaceAssessment:
    """Preflight report emitted when database connection is refused or unavailable."""

    mcp_endpoint: str
    discovered_tools: tuple[str, ...]
    untrusted_declarations: dict[str, Any]
    hypotheses: tuple[str, ...]
    missing_capabilities: tuple[str, ...]
    assessment_disclaimer: str = "Database boundary not tested — database access was not provided."
    status: OnboardingState = OnboardingState.INCOMPLETE_PREFLIGHT


@dataclass(frozen=True)
class ConfigSecurityFinding:
    """A security issue detected in a static IDE or client MCP configuration file."""

    issue_id: str  # e.g., "STATIC-SECRET-INLINE-001", "STATIC-UNSAFE-STDIO-001"
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    server_name: str
    config_path: str
    description: str
    redacted_evidence: str


@dataclass(frozen=True)
class ConfigAssessmentReport:
    """Consolidated assessment report for scanned client MCP configuration files."""

    scanned_file: str
    discovered_servers: tuple[str, ...]
    findings: tuple[ConfigSecurityFinding, ...]
    is_safe: bool
