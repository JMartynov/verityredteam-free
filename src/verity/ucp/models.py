"""Data models for Unknown Capability Profiling (UCP)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class CapabilityTag(StrEnum):
    """Inferred capability tags representing tool behavioral categories."""

    DATA_READ = "DATA_READ"
    DATA_WRITE = "DATA_WRITE"
    DESTRUCTIVE_WRITE = "DESTRUCTIVE_WRITE"
    TENANT_SELECTOR = "TENANT_SELECTOR"
    IDENTIFIER_LOOKUP = "IDENTIFIER_LOOKUP"
    FILE_ACCESS = "FILE_ACCESS"
    NETWORK_ACCESS = "NETWORK_ACCESS"
    EXTERNAL_SIDE_EFFECT = "EXTERNAL_SIDE_EFFECT"


class ProvenanceLabel(StrEnum):
    """Provenance classification for target declarations."""

    UNTRUSTED_TARGET_DECLARATION = "UNTRUSTED_TARGET_DECLARATION"
    INFERRED_CAPABILITY = "INFERRED_CAPABILITY"
    VERIFIED_GROUND_TRUTH = "VERIFIED_GROUND_TRUTH"


@dataclass(frozen=True)
class InferredCapability:
    """A capability tag assigned to a tool with confidence score and rule provenance."""

    tag: CapabilityTag
    confidence: float  # 0.0 to 1.0
    contributing_rules: tuple[str, ...]


@dataclass(frozen=True)
class ToolProfile:
    """Deterministic behavioral and cryptographic profile of an unseen MCP tool."""

    tool_name: str
    canonical_hash: str  # Order-independent SHA-256
    raw_description: str
    sanitized_description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None
    untrusted_annotations: dict[str, Any]
    inferred_capabilities: tuple[InferredCapability, ...]
    has_unicode_anomalies: bool
    has_prompt_injection_indicators: bool
    is_mutating_declared: bool
    is_mutating_inferred: bool
    provenance: ProvenanceLabel = ProvenanceLabel.UNTRUSTED_TARGET_DECLARATION


@dataclass(frozen=True)
class RugPullDetectionResult:
    """Outcome of comparing live tools/list against authorized profile hashes."""

    tool_name: str
    is_rug_pull: bool
    authorized_hash: str
    current_hash: str
    changed_fields: tuple[str, ...]
    details: str


@dataclass(frozen=True)
class CWEHypothesis:
    """A prioritized vulnerability hypothesis inferred from tool schemas and semantics."""

    cwe_id: str  # e.g. "CWE-22", "CWE-94"
    name: str  # e.g. "Path Traversal"
    confidence: float  # 0.0 to 1.0
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    affected_tool: str
    affected_parameters: tuple[str, ...]
    suggested_check_file: str
    rationale: str


@dataclass(frozen=True)
class UnknownAuditPlan:
    """Orchestration plan generated for an unknown / custom MCP server."""

    server_id: str
    tool_profiles: dict[str, ToolProfile]
    hypotheses: tuple[CWEHypothesis, ...]
    recommended_checks: tuple[str, ...]

