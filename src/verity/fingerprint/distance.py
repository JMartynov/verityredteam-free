"""Distance metric engine for computing fuzzy structural similarity between MCP implementations."""

from __future__ import annotations

from mcp_fingerprints.distance import (
    compute_capability_similarity,
    compute_tool_topology_similarity,
    compute_version_topology_similarity,
    jaccard_similarity,
)

# Re-export levenshtein_similarity even if it's missing from mcp_fingerprints, for backwards compatibility if needed.
# Since it was requested, we implement a fallback if it doesn't exist.
try:
    from mcp_fingerprints.distance import levenshtein_similarity
except ImportError:
    def levenshtein_similarity(s1: str, s2: str) -> float:
        """Fallback implementation of Levenshtein similarity."""
        if not s1 and not s2:
            return 1.0
        if not s1 or not s2:
            return 0.0
        
        distances = range(len(s1) + 1)
        for i2, c2 in enumerate(s2):
            distances_ = [i2+1]
            for i1, c1 in enumerate(s1):
                if c1 == c2:
                    distances_.append(distances[i1])
                else:
                    distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
            distances = distances_
            
        max_len = max(len(s1), len(s2))
        return 1.0 - (distances[-1] / max_len)

__all__ = [
    "compute_capability_similarity",
    "compute_tool_topology_similarity",
    "compute_version_topology_similarity",
    "jaccard_similarity",
    "levenshtein_similarity",
]
