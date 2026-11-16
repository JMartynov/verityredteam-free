"""Order-independent canonical JSON serialization and cryptographic tool hashing."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonicalize_json(obj: Any) -> str:
    """Canonicalize a JSON-serializable Python data structure.

    Keys in dictionaries are sorted recursively.
    Separators are compact (',' and ':') without extraneous whitespace.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_sha256(data: str | bytes) -> str:
    """Compute standard sha256:<hex> digest of input string or bytes."""
    payload = data.encode("utf-8") if isinstance(data, str) else data
    digest = hashlib.sha256(payload).hexdigest()
    return f"sha256:{digest}"


def extract_canonical_tool_payload(tool_def: dict[str, Any]) -> dict[str, Any]:
    """Extract and normalize the core semantic fields of an MCP tool definition."""
    return {
        "name": tool_def.get("name", ""),
        "description": tool_def.get("description", ""),
        "inputSchema": tool_def.get("inputSchema", {}),
        "outputSchema": tool_def.get("outputSchema"),
        "annotations": tool_def.get("annotations", {}),
    }


def compute_tool_canonical_hash(tool_def: dict[str, Any]) -> str:
    """Compute immutable, order-independent SHA-256 canonical hash of a tool definition."""
    payload = extract_canonical_tool_payload(tool_def)
    canonical_str = canonicalize_json(payload)
    return compute_sha256(canonical_str)
