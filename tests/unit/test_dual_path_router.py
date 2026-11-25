"""Unit tests for DualPathRouter (Task 45 & M44 / TASK-106-FREE).

Verifies:
1. Classification threshold handling (>=0.85 KNOWN, <0.85 UNKNOWN).
2. Unknown black-box profiling and safe probe generation.
3. Batch mesh summary generation and operator consent flags.
4. Schema-driven neutral skeleton without hardcoded '1 + 1' formula payloads.
5. Preservation of caller-supplied / known-tool arguments verbatim.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from verity.scanner.dual_path_router import (
    DualPathAuditSummary,
    DualPathRouter,
    PathClassification,
    ServerRoutingType,
)
from verity.scanner.readonly_guard import ReadOnlySafetyGuard, SafetyVerdict


def test_dual_path_router_classification_threshold():
    """Verify confidence threshold determines KNOWN vs UNKNOWN routing."""
    mock_matcher = MagicMock()
    mock_vuln_engine = MagicMock()

    router = DualPathRouter(matcher=mock_matcher, vuln_engine=mock_vuln_engine)

    # 1. High confidence match (>= 0.85) -> KNOWN
    mock_matcher.match.return_value = MagicMock(
        matched=True,
        confidence=0.92,
        confidence_score=0.92,
        package_name="mcp-postgres",
        matched_version="1.2.0",
    )

    res_known = router.classify_server(
        "postgres-svc", [{"name": "read_records"}], confidence_threshold=0.85
    )
    assert res_known.routing_type == ServerRoutingType.KNOWN
    assert res_known.confidence == 0.92
    assert res_known.package_name == "mcp-postgres"

    # 2. Low confidence match (< 0.85) -> UNKNOWN
    mock_matcher.match.return_value = MagicMock(
        matched=True,
        confidence=0.74,
        confidence_score=0.74,
        package_name="mcp-postgres",
        matched_version="1.2.0",
    )

    res_unknown = router.classify_server(
        "custom-db", [{"name": "read_records"}], confidence_threshold=0.85
    )
    assert res_unknown.routing_type == ServerRoutingType.UNKNOWN

    # 3. No match -> UNKNOWN
    mock_matcher.match.return_value = MagicMock(
        matched=False,
        confidence=0.0,
        package_name=None,
        matched_version=None,
    )

    res_nomatch = router.classify_server(
        "internal-billing", [{"name": "calc"}], confidence_threshold=0.85
    )
    assert res_nomatch.routing_type == ServerRoutingType.UNKNOWN


def test_dual_path_router_synthesizes_safe_probes():
    """Verify router synthesizes non-destructive read probes and validates with safety guard."""
    router = DualPathRouter(matcher=MagicMock(), vuln_engine=MagicMock())

    tools = [
        {
            "name": "lookup_user",
            "description": "Fetch user record by account id.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": {"type": "string"},
                    "limit": {"type": "integer"},
                    "include_meta": {"type": "boolean"},
                },
            },
        },
        {
            "name": "delete_user",
            "description": "Permanently remove a user account.",
            "inputSchema": {
                "type": "object",
                "properties": {"account_id": {"type": "string"}},
            },
        },
    ]

    classification = PathClassification(
        routing_type=ServerRoutingType.UNKNOWN,
        confidence=0.0,
    )

    route_res = router.synthesize_route_result(
        server_id="crm-custom",
        url="http://127.0.0.1:8001/sse",
        tools=tools,
        classification=classification,
    )

    for probe in route_res.proposed_safe_probes:
        assert "delete" not in probe.tool_name.lower()
        verdict = ReadOnlySafetyGuard.check_call(probe.tool_name, probe.arguments)
        assert verdict.verdict == SafetyVerdict.PERMITTED


def test_dual_path_router_batch_mesh_summary():
    """Verify generate_harmless_audit_summary consolidates multiple servers and sets consent flag."""
    router = DualPathRouter()

    servers = [
        {
            "server_id": "billing-engine",
            "url": "http://127.0.0.1:8004/sse",
            "tools": [
                {
                    "name": "calculate_tax",
                    "inputSchema": {"properties": {"amount": {"type": "number"}}},
                }
            ],
        },
        {
            "server_id": "document-vault",
            "url": "http://127.0.0.1:8005/sse",
            "tools": [
                {"name": "fetch_doc", "inputSchema": {"properties": {"doc_id": {"type": "string"}}}}
            ],
        },
    ]

    summary: DualPathAuditSummary = router.generate_harmless_audit_summary(servers)

    assert summary.total_servers == 2
    assert summary.unknown_count == 2
    assert summary.known_count == 0
    assert summary.requires_operator_consent is True
    assert summary.phase_2_mutation_permitted is False
    assert summary.phase == "PHASE_1_HARMLESS_AUDIT"


def test_dual_path_router_harmless_arg_generation():
    """Verify _generate_harmless_args generates neutral safe values for schema types."""
    router = DualPathRouter()

    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "target_url": {"type": "string"},
            "file_path": {"type": "string"},
            "formula_expr": {"type": "string"},
            "count": {"type": "integer"},
            "is_valid": {"type": "boolean"},
            "tags": {"type": "array"},
            "options": {"type": "object"},
        },
    }

    args = router._generate_harmless_args(schema)
    assert args["query"] == "SELECT 1"
    assert args["target_url"] == "https://example.com"
    assert args["file_path"] == "test.txt"
    assert args["formula_expr"] != "1 + 1"
    assert isinstance(args["formula_expr"], str)
    assert args["count"] == 1
    assert args["is_valid"] is True
    assert args["tags"] == []
    assert args["options"] == {}


def test_no_hardcoded_formula_for_unknown_tool():
    """Verify unknown tools never receive hardcoded '1 + 1' and use schema skeleton or NEEDS_ARGS."""
    mock_matcher = MagicMock()
    mock_matcher.match.return_value = MagicMock(
        matched=False,
        confidence=0.0,
        package_name=None,
        matched_version=None,
    )
    router = DualPathRouter(matcher=mock_matcher, vuln_engine=MagicMock())

    discount_schema = {
        "type": "object",
        "properties": {
            "formula": {"type": "string"},
            "expression": {"type": "string"},
            "rate": {"type": "number"},
        },
        "required": ["formula"],
    }
    opaque_schema = {
        "type": "object",
        "properties": {
            "opaque_spec": {"description": "Untyped complex parameter"},
        },
        "required": ["opaque_spec"],
    }
    tools = [
        {
            "name": "calculate_custom_discount",
            "description": "Evaluate a discount rule.",
            "inputSchema": discount_schema,
        },
        {
            "name": "inspect_custom_rule",
            "description": "Inspect an opaque rule object.",
            "inputSchema": opaque_schema,
        },
    ]

    route_res = router.route_server(
        server_id="custom-discount-engine",
        url="http://127.0.0.1:9999/mcp",
        tools=tools,
    )
    assert route_res.routing_type == ServerRoutingType.UNKNOWN
    assert len(route_res.proposed_safe_probes) == 2

    # Check direct helper output as well as routed probes
    discount_args = router._generate_harmless_args(discount_schema)
    opaque_args = router._generate_harmless_args(opaque_schema)

    for arg_map in [discount_args, opaque_args] + [p.arguments for p in route_res.proposed_safe_probes]:
        assert "1 + 1" not in arg_map.values()

    discount_probe = next(
        p for p in route_res.proposed_safe_probes if p.tool_name == "calculate_custom_discount"
    )
    assert "formula" in discount_probe.arguments
    assert isinstance(discount_probe.arguments["formula"], str)
    assert discount_probe.arguments["formula"] != "1 + 1"
    assert discount_probe.arguments.get("expression") != "1 + 1"

    opaque_probe = next(
        p for p in route_res.proposed_safe_probes if p.tool_name == "inspect_custom_rule"
    )
    assert opaque_probe.arguments["opaque_spec"] == "NEEDS_ARGS"
    assert opaque_args["opaque_spec"] == "NEEDS_ARGS"


def test_known_tool_args_preserved():
    """Verify caller-supplied or known-tool arguments and schema defaults are preserved verbatim."""
    mock_matcher = MagicMock()
    mock_matcher.match.return_value = MagicMock(
        matched=True,
        confidence=0.95,
        confidence_score=0.95,
        package_name="@modelcontextprotocol/server-postgres",
        matched_version="1.0.0",
    )
    mock_vuln_engine = MagicMock()
    mock_vuln_engine.query.return_value = MagicMock(is_vulnerable=False, vulnerabilities=[])

    router = DualPathRouter(matcher=mock_matcher, vuln_engine=mock_vuln_engine)

    tools = [
        {
            "name": "get_schema",
            "description": "Inspect table schema with caller-supplied args.",
            "arguments": {
                "table": "customers_v2",
                "formula": "price * qty",
            },
            "inputSchema": {
                "type": "object",
                "properties": {
                    "table": {"type": "string"},
                    "formula": {"type": "string"},
                    "limit": {"type": "integer", "default": 25},
                },
                "required": ["table"],
            },
        }
    ]

    route_res = router.route_server(
        server_id="postgres-prod",
        url="http://127.0.0.1:5432/mcp",
        tools=tools,
    )
    assert route_res.routing_type == ServerRoutingType.KNOWN
    assert len(route_res.proposed_safe_probes) == 1

    probe = route_res.proposed_safe_probes[0]
    assert probe.tool_name == "get_schema"
    assert probe.arguments["table"] == "customers_v2"
    assert probe.arguments["formula"] == "price * qty"
    assert probe.arguments["limit"] == 25

    verdict = ReadOnlySafetyGuard.check_call(probe.tool_name, probe.arguments)
    assert verdict.verdict == SafetyVerdict.PERMITTED
