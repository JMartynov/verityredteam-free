"""Locked ATDD tests for Free MCP database guard Pro gating (M43 / TASK-109-FREE)."""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from verity.fingerprint.matcher import FingerprintMatcher
from verity.lookup.engine import VulnerabilityLookupEngine
from verity.mcp_server.bootstrap import ServerContext
from verity.mcp_server.server import VerityDiscoveryMcpServer
from verity.mcp_server.tools import VerityToolDispatcher


def _make_context() -> ServerContext:
    """Build an empty in-memory ServerContext (no network or on-disk data needed)."""
    return ServerContext(FingerprintMatcher(), VulnerabilityLookupEngine())


def _parse_tool_result(resp: dict[str, Any]) -> dict[str, Any]:
    """Decode the JSON text payload emitted by tools/call."""
    content = resp["result"]["content"]
    return json.loads(content[0]["text"])


def test_pro_feature_required_and_free_action_benign(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-43.1: Pro-only NoSQL filter action returns PRO_FEATURE_REQUIRED; SQL query succeeds."""
    monkeypatch.delitem(sys.modules, "verity.mcp_library.filters", raising=False)
    dispatcher = VerityToolDispatcher(_make_context(), load_plugins=False)
    assert "nosql_filter" not in dispatcher._guards

    for payload in (
        {
            "action": "validate_nosql_filter",
            "options": {
                "filter_obj": {"customer_id": {"$ne": ""}},
                "session_tenant": "tenant-a",
            },
        },
        {
            "action": "validate_nosql_filter",
            "filter_obj": {"customer_id": {"$ne": ""}},
            "session_tenant": "tenant-a",
        },
    ):
        res = dispatcher.execute_tool("verity_database_guard", payload)
        assert res["ok"] is False
        assert res["error"] == "PRO_FEATURE_REQUIRED"
        assert res["feature"] == "validate_nosql_filter"
        assert res["action"] == "validate_nosql_filter"
        assert res["verdict"] == "PRO_REQUIRED"
        assert "verity.mcp_library.filters" not in sys.modules

    for sql_action in ("validate_sql_query", "validate_query"):
        benign = dispatcher.execute_tool(
            "verity_database_guard",
            {
                "action": sql_action,
                "options": {
                    "sql_query": "SELECT id, name FROM users WHERE id = :id",
                },
            },
        )
        assert benign["ok"] is True
        assert benign["action"] == sql_action
        assert benign["verdict"] == "ALLOWED"


def test_enforce_volume_policy_gated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-43.2: Volume enforcement is gated with PRO_FEATURE_REQUIRED and server stays live."""
    monkeypatch.delitem(sys.modules, "verity.mcp_library.volume", raising=False)
    dispatcher = VerityToolDispatcher(_make_context(), load_plugins=False)
    assert "volume_policy" not in dispatcher._guards

    res = dispatcher.execute_tool(
        "verity_database_guard",
        {
            "action": "enforce_volume_policy",
            "options": {
                "records": [{"id": 1}],
                "requested_limit": 50000,
            },
        },
    )
    assert res["ok"] is False
    assert res["error"] == "PRO_FEATURE_REQUIRED"
    assert res["feature"] == "enforce_volume_policy"
    assert res["action"] == "enforce_volume_policy"
    assert res["verdict"] == "PRO_REQUIRED"
    assert "records" not in res
    assert "verity.mcp_library.volume" not in sys.modules

    server = VerityDiscoveryMcpServer(_make_context())
    server.dispatcher = dispatcher

    gated_resp = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "verity_database_guard",
                "arguments": {
                    "action": "enforce_volume_policy",
                    "records": [{"id": 1}],
                    "requested_limit": 50000,
                },
            },
        }
    )
    assert gated_resp is not None
    assert "result" in gated_resp
    assert gated_resp["result"].get("isError") is True
    gated_payload = _parse_tool_result(gated_resp)
    assert gated_payload["ok"] is False
    assert gated_payload["error"] == "PRO_FEATURE_REQUIRED"
    assert gated_payload["feature"] == "enforce_volume_policy"
    assert gated_payload["action"] == "enforce_volume_policy"
    assert gated_payload["verdict"] == "PRO_REQUIRED"
    assert "records" not in gated_payload
    assert "verity.mcp_library.volume" not in sys.modules

    sql_resp = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "verity_database_guard",
                "arguments": {
                    "action": "validate_sql_query",
                    "options": {
                        "sql_query": "SELECT id, name FROM users WHERE id = :id",
                    },
                },
            },
        }
    )
    assert sql_resp is not None
    assert sql_resp["result"].get("isError") is False
    sql_payload = _parse_tool_result(sql_resp)
    assert sql_payload["ok"] is True
    assert sql_payload["verdict"] == "ALLOWED"
