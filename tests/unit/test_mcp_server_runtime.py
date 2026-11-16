"""Runtime tests for VerityDiscoveryMcpServer JSON-RPC protocol handling."""

from __future__ import annotations

import json
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


@pytest.fixture()
def server() -> VerityDiscoveryMcpServer:
    return VerityDiscoveryMcpServer(_make_context())


def _parse_tool_result(resp: dict[str, Any]) -> dict[str, Any]:
    """Decode the JSON text payload emitted by tools/call."""
    content = resp["result"]["content"]
    return json.loads(content[0]["text"])


def test_initialize(server: VerityDiscoveryMcpServer) -> None:
    resp = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert resp is not None
    assert resp["id"] == 1
    assert "result" in resp
    assert resp["result"]["serverInfo"]["name"] == "verity-discovery-security-mcp-server"


def test_tools_list(server: VerityDiscoveryMcpServer) -> None:
    resp = server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert resp is not None
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "verity_database_guard" in names
    assert "verity_database_oracle" in names
    assert "verity_remediation_ops" in names


def test_database_guard_validate_sql_query(server: VerityDiscoveryMcpServer) -> None:
    resp = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "verity_database_guard",
                "arguments": {
                    "action": "validate_sql_query",
                    "options": {
                        "sql_query": "SELECT id, name FROM users WHERE id = :id",
                        "timeout_ms": 5000,
                    },
                },
            },
        }
    )
    assert resp is not None
    result = _parse_tool_result(resp)
    assert result.get("ok") is True
    assert result.get("verdict") == "ALLOWED"
    assert resp["result"].get("isError") is False


def test_remediation_explain_vulnerability_remediation(
    server: VerityDiscoveryMcpServer,
) -> None:
    resp = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "verity_remediation_ops",
                "arguments": {
                    "action": "explain_vulnerability_remediation",
                    "options": {"vulnerability_id": "CVE-TEST"},
                },
            },
        }
    )
    assert resp is not None
    result = _parse_tool_result(resp)
    assert result.get("ok") is True


def test_pro_feature_required_without_plugins(
    server: VerityDiscoveryMcpServer,
) -> None:
    server.dispatcher = VerityToolDispatcher(_make_context(), load_plugins=False)
    resp = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "verity_database_oracle",
                "arguments": {
                    "action": "generate_attack_proposal",
                    "options": {"package_name": "test"},
                },
            },
        }
    )
    assert resp is not None
    result = _parse_tool_result(resp)
    assert (
        result.get("error") == "PRO_FEATURE_REQUIRED"
        or result.get("verdict") == "PRO_REQUIRED"
    )
    assert resp["result"].get("isError") is True
