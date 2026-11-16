"""Data models for the Full-Fidelity MCP Structural Fingerprint & Passport Knowledge Base.

This module re-exports models from the upstream `mcp-fingerprints` library.
"""

from __future__ import annotations

from mcp_fingerprints.models import (
    FingerprintMatchResult,
    PromptSignature,
    ResourceSignature,
    ServerPackageSpec,
    ToolContractSignature,
    VersionFingerprint,
)

__all__ = [
    "FingerprintMatchResult",
    "PromptSignature",
    "ResourceSignature",
    "ServerPackageSpec",
    "ToolContractSignature",
    "VersionFingerprint",
]
