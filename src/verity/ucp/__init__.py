"""Unknown Capability Profiler (UCP) module for Verity RedTeam."""

from __future__ import annotations

from verity.ucp.canonicalizer import (
    canonicalize_json,
    compute_sha256,
    compute_tool_canonical_hash,
)
from verity.ucp.engine import UnknownCapabilityProfiler
from verity.ucp.inference import CapabilityInferenceEngine
from verity.ucp.models import (
    CapabilityTag,
    InferredCapability,
    ProvenanceLabel,
    RugPullDetectionResult,
    ToolProfile,
)
from verity.ucp.normalizer import MetadataNormalizer

__all__ = [
    "CapabilityInferenceEngine",
    "CapabilityTag",
    "InferredCapability",
    "MetadataNormalizer",
    "ProvenanceLabel",
    "RugPullDetectionResult",
    "ToolProfile",
    "UnknownCapabilityProfiler",
    "canonicalize_json",
    "compute_sha256",
    "compute_tool_canonical_hash",
]
