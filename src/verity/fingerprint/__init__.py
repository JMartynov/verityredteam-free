"""Public exports for the MCP Structural Fingerprint Knowledge Base & Matcher."""

from __future__ import annotations

from verity.fingerprint.canonicalizer import (
    build_version_fingerprint,
    canonicalize_json,
    compute_sha256,
    compute_toolset_canonical_hash,
    extract_tool_signature,
)
from verity.fingerprint.crawler import FingerprintGenerator
from verity.fingerprint.distance import (
    compute_capability_similarity,
    compute_tool_topology_similarity,
    compute_version_topology_similarity,
    jaccard_similarity,
    levenshtein_similarity,
)
from verity.fingerprint.index import FingerprintFastIndex
from verity.fingerprint.matcher import FingerprintMatcher
from verity.fingerprint.models import (
    FingerprintMatchResult,
    PromptSignature,
    ResourceSignature,
    ServerPackageSpec,
    ToolContractSignature,
    VersionFingerprint,
)
from verity.fingerprint.schema_validator import PassportSchemaValidator
from verity.fingerprint.synchronizer import PassportSynchronizer
from verity.fingerprint.validator import McpServerValidator

__all__ = [
    "FingerprintFastIndex",
    "FingerprintGenerator",
    "FingerprintMatchResult",
    "FingerprintMatcher",
    "McpServerValidator",
    "PassportSchemaValidator",
    "PassportSynchronizer",
    "PromptSignature",
    "ResourceSignature",
    "ServerPackageSpec",
    "ToolContractSignature",
    "VersionFingerprint",
    "build_version_fingerprint",
    "canonicalize_json",
    "compute_capability_similarity",
    "compute_sha256",
    "compute_tool_topology_similarity",
    "compute_toolset_canonical_hash",
    "compute_version_topology_similarity",
    "extract_tool_signature",
    "jaccard_similarity",
    "levenshtein_similarity",
]
