"""Unit tests for the zero-Docker synthetic red-team targets."""

from __future__ import annotations

import pytest

from verity.scanner.static_rules import StaticRuleEvaluator
from verity.targets import (
    SYNTHETIC_TARGETS,
    get_synthetic_target,
    list_synthetic_targets,
    run_all_demo_probes,
)
from verity.targets.code_exec_target import CodeExecSyntheticTarget
from verity.targets.mongo_target import MongoSyntheticTarget
from verity.targets.postgres_sqli_target import PostgresSqliSyntheticTarget
from verity.targets.sqlite_target import SqliteSyntheticTarget

TARGET_CLASSES = [
    SqliteSyntheticTarget,
    PostgresSqliSyntheticTarget,
    MongoSyntheticTarget,
    CodeExecSyntheticTarget,
]


@pytest.mark.parametrize("target_cls", TARGET_CLASSES)
def test_target_metadata(target_cls: type) -> None:
    target = target_cls()
    assert isinstance(target.target_id, str) and target.target_id
    assert isinstance(target.name, str) and target.name
    assert isinstance(target.cwe_id, str) and target.cwe_id.startswith("CWE-")


@pytest.mark.parametrize("target_cls", TARGET_CLASSES)
def test_get_tools_both_profiles(target_cls: type) -> None:
    target = target_cls()
    for profile in ("vulnerable", "secure"):
        tools = target.get_tools(profile=profile)
        assert isinstance(tools, list) and tools
        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool


@pytest.mark.parametrize("target_cls", TARGET_CLASSES)
def test_run_demo_probe(target_cls: type) -> None:
    target = target_cls()
    probe = target.run_demo_probe()
    assert probe["target_id"] == target.target_id
    assert probe["name"] == target.name
    assert probe["cwe_id"] == target.cwe_id
    assert probe["vulnerable_breached"] is True
    assert probe["secure_defended"] is True
    assert "evidence" in probe


def test_sqlite_vulnerable_returns_admin() -> None:
    target = SqliteSyntheticTarget()
    result = target.call_tool(
        "lookup_user", {"username": "' OR '1'='1"}, profile="vulnerable"
    )
    usernames = {row["username"] for row in result["rows"]}
    assert "admin" in usernames


def test_sqlite_secure_defends_injection() -> None:
    target = SqliteSyntheticTarget()
    result = target.call_tool(
        "lookup_user", {"username": "' OR '1'='1"}, profile="secure"
    )
    assert result["count"] == 0


def test_sqlite_secure_valid_lookup() -> None:
    target = SqliteSyntheticTarget()
    result = target.call_tool(
        "lookup_user", {"username": "alice"}, profile="secure"
    )
    assert result["count"] == 1
    assert result["rows"][0]["username"] == "alice"
    assert "secret" not in result["rows"][0]


def test_postgres_vulnerable_cross_tenant_leak() -> None:
    target = PostgresSqliSyntheticTarget()
    result = target.call_tool(
        "get_invoice", {"invoice_id": "inv_b_cyber"}, profile="vulnerable"
    )
    invoice = result["invoice"]
    assert invoice is not None
    assert invoice["tenant_id"] == "tenant-b"
    assert "password_hash" in invoice


def test_postgres_secure_blocks_cross_tenant() -> None:
    target = PostgresSqliSyntheticTarget()
    result = target.call_tool(
        "get_invoice", {"invoice_id": "inv_b_cyber"}, profile="secure"
    )
    assert result["invoice"] is None


def test_postgres_secure_same_tenant_projects_columns() -> None:
    target = PostgresSqliSyntheticTarget()
    result = target.call_tool(
        "get_invoice", {"invoice_id": "inv_a_100"}, profile="secure"
    )
    invoice = result["invoice"]
    assert invoice is not None
    assert invoice["tenant_id"] == "tenant-a"
    assert "password_hash" not in invoice


def test_mongo_vulnerable_operator_injection() -> None:
    target = MongoSyntheticTarget()
    result = target.call_tool(
        "find_customer",
        {"query": {"username": {"$ne": None}}},
        profile="vulnerable",
    )
    assert len(result["matches"]) >= 3
    usernames = {match["username"] for match in result["matches"]}
    assert "admin" in usernames


def test_mongo_vulnerable_gt_operator() -> None:
    target = MongoSyntheticTarget()
    result = target.call_tool(
        "find_customer",
        {"query": {"username": {"$gt": ""}}},
        profile="vulnerable",
    )
    assert len(result["matches"]) >= 3


def test_mongo_vulnerable_where_regex() -> None:
    target = MongoSyntheticTarget()
    result = target.call_tool(
        "find_customer",
        {"query": {"$where": "this.username.match(/admin/)"}},
        profile="vulnerable",
    )
    usernames = {match["username"] for match in result["matches"]}
    assert "admin" in usernames


def test_mongo_secure_rejects_operator() -> None:
    target = MongoSyntheticTarget()
    result = target.call_tool(
        "find_customer",
        {"query": {"username": {"$ne": None}}},
        profile="secure",
    )
    assert result["matches"] == []


def test_mongo_secure_scalar_lookup() -> None:
    target = MongoSyntheticTarget()
    result = target.call_tool(
        "find_customer",
        {"query": {"username": "alice"}},
        profile="secure",
    )
    assert len(result["matches"]) == 1
    assert result["matches"][0]["username"] == "alice"
    assert "secret" not in result["matches"][0]


def test_code_exec_vulnerable_eval() -> None:
    target = CodeExecSyntheticTarget()
    result = target.call_tool(
        "evaluate", {"expression": "1 + 1"}, profile="vulnerable"
    )
    assert result["result"] == 2


def test_code_exec_vulnerable_allows_import() -> None:
    target = CodeExecSyntheticTarget()
    result = target.call_tool(
        "evaluate",
        {"expression": "__import__('math').sqrt(16)"},
        profile="vulnerable",
    )
    assert result["result"] == 4.0


def test_code_exec_secure_rejects_expression() -> None:
    target = CodeExecSyntheticTarget()
    result = target.call_tool(
        "evaluate", {"expression": "1 + 1"}, profile="secure"
    )
    assert result["result"] is None
    assert "error" in result


def test_code_exec_secure_literal() -> None:
    target = CodeExecSyntheticTarget()
    result = target.call_tool(
        "evaluate", {"expression": "42"}, profile="secure"
    )
    assert result["result"] == 42


def test_code_exec_vulnerable_schema_detected() -> None:
    target = CodeExecSyntheticTarget()
    evaluator = StaticRuleEvaluator()
    findings = []
    for tool in target.get_tools(profile="vulnerable"):
        findings.extend(evaluator.scan_tool(tool))
    assert findings, "StaticRuleEvaluator should flag the vulnerable schema"
    rule_ids = {finding.rule_id for finding in findings}
    assert "VERITY-STATIC-INJECTION-OVERRIDE" in rule_ids


def test_code_exec_secure_schema_clean() -> None:
    target = CodeExecSyntheticTarget()
    evaluator = StaticRuleEvaluator()
    findings = []
    for tool in target.get_tools(profile="secure"):
        findings.extend(evaluator.scan_tool(tool))
    assert findings == []


def test_list_synthetic_targets() -> None:
    ids = list_synthetic_targets()
    assert set(ids) == {
        "sqlite-basic",
        "postgres-basic",
        "mongo-basic",
        "code-exec-basic",
    }


def test_synthetic_targets_registry() -> None:
    assert set(SYNTHETIC_TARGETS.keys()) == set(list_synthetic_targets())


def test_get_synthetic_target() -> None:
    target = get_synthetic_target("sqlite-basic")
    assert isinstance(target, SqliteSyntheticTarget)


def test_get_synthetic_target_unknown() -> None:
    with pytest.raises(KeyError):
        get_synthetic_target("does-not-exist")


def test_run_all_demo_probes_all() -> None:
    probes = run_all_demo_probes()
    assert len(probes) == 4
    for probe in probes:
        assert probe["vulnerable_breached"] is True
        assert probe["secure_defended"] is True


def test_run_all_demo_probes_single() -> None:
    probes = run_all_demo_probes(target_id="mongo-basic")
    assert len(probes) == 1
    assert probes[0]["target_id"] == "mongo-basic"
