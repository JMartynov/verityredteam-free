"""Deterministic clean stdio MCP server fixture for Verity E2E verification."""

from __future__ import annotations

import json
import sys
from typing import Any

BENIGN_TOOLS: list[dict[str, Any]] = [
    {
        "name": "add_numbers",
        "description": "Add two integers and return their sum.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "a": {"type": "integer"},
                "b": {"type": "integer"},
            },
        },
    },
]


def handle(request: dict[str, Any]) -> dict[str, Any] | None:
    """Handle a single JSON-RPC request, returning None for notifications."""
    method = request.get("method", "")
    req_id = request.get("id")

    if method.startswith("notifications/") or "id" not in request:
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "clean-stdio-mcp", "version": "1.0.0"},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": BENIGN_TOOLS}}

    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"prompts": []}}

    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": []}}

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method '{method}' not supported"},
    }


def main() -> None:
    """Read newline-delimited JSON-RPC from stdin and write responses to stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = handle(request)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
