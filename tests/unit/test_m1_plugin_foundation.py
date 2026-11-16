"""Unit tests for Task M1 Turn Group B (Core MCP Server Foundation)."""

from __future__ import annotations

import logging
from typing import Any

import pytest

from verity.mcp_server import PLUGIN_GROUP, discover_and_load_plugins
from verity.mcp_server.protocols import (
    BasicConditionVerificationResult,
    BasicResponseOracle,
    pro_feature_required_response,
)
from verity.mcp_server.schemas import UNIFIED_TOOL_DEFINITIONS

_MISSING = object()


class _FakeEntryPoint:
    """Minimal stand-in for ``importlib.metadata.EntryPoint``."""

    def __init__(self, name: str, target: Any = _MISSING) -> None:
        self.name = name
        self._target = target

    def load(self) -> Any:
        if isinstance(self._target, BaseException):
            raise self._target
        return self._target


def _patch_entry_points(monkeypatch: pytest.MonkeyPatch, entry_points: list[Any]) -> None:
    def _fake_entry_points(*args: Any, **kwargs: Any) -> list[Any]:
        return entry_points

    monkeypatch.setattr("importlib.metadata.entry_points", _fake_entry_points)


# ---------------------------------------------------------------------------
# BasicResponseOracle.verify_condition
# ---------------------------------------------------------------------------


def test_verify_condition_verified_when_response_ok() -> None:
    oracle = BasicResponseOracle()
    result = oracle.verify_condition(
        condition_id="VERITY-STATIC-TEST",
        tool_response={"ok": True},
        mcp_arguments={"arg": "value"},
        profile="vulnerable",
    )
    assert isinstance(result, BasicConditionVerificationResult)
    assert result.condition_id == "VERITY-STATIC-TEST"
    assert result.status == "VERIFIED"
    assert result.details
    assert result.evidence == str({"ok": True})[:200]
    assert result.observed_in_database is False


def test_verify_condition_blocked_when_response_not_ok() -> None:
    oracle = BasicResponseOracle()
    result = oracle.verify_condition(
        condition_id="cond-block",
        tool_response={"ok": False},
        mcp_arguments={},
        profile="secure",
    )
    assert result.status == "BLOCKED"
    assert result.observed_in_database is False


def test_verify_condition_blocked_when_ok_missing() -> None:
    oracle = BasicResponseOracle()
    result = oracle.verify_condition(
        condition_id="cond-missing",
        tool_response={"result": "data"},
        mcp_arguments={},
        profile="vulnerable",
    )
    assert result.status == "BLOCKED"
    assert result.observed_in_database is False


# ---------------------------------------------------------------------------
# BasicResponseOracle.execute_physical_verification
# ---------------------------------------------------------------------------


def test_execute_physical_verification_requires_pro() -> None:
    response = BasicResponseOracle().execute_physical_verification(
        engine="postgres",
        query="SELECT 1",
    )
    assert response["ok"] is False
    assert response["error"] == "PRO_FEATURE_REQUIRED"
    assert response["message"] == "Physical database verification requires verity-pro plugin."


def test_execute_physical_verification_ignores_tenant() -> None:
    response = BasicResponseOracle().execute_physical_verification(
        engine="snowflake",
        query={"sql": "SELECT 1"},
        expected_tenant="tenant-a",
    )
    assert response["ok"] is False
    assert response["error"] == "PRO_FEATURE_REQUIRED"


# ---------------------------------------------------------------------------
# pro_feature_required_response
# ---------------------------------------------------------------------------


def test_pro_feature_required_response_contract() -> None:
    response = pro_feature_required_response("validate_snowflake_policy")
    assert response["ok"] is False
    assert response["error"] == "PRO_FEATURE_REQUIRED"
    assert response["verdict"] == "PRO_REQUIRED"
    assert response["action"] == "validate_snowflake_policy"
    assert "validate_snowflake_policy" in response["message"]


def test_pro_feature_required_response_custom_message() -> None:
    response = pro_feature_required_response("generate_guard_patch", "Custom upgrade hint.")
    assert response["message"] == "Custom upgrade hint."
    assert response["action"] == "generate_guard_patch"
    assert response["error"] == "PRO_FEATURE_REQUIRED"


# ---------------------------------------------------------------------------
# discover_and_load_plugins
# ---------------------------------------------------------------------------


def test_plugin_group_constant() -> None:
    assert PLUGIN_GROUP == "verity.plugins"


def test_discover_and_load_plugins_uses_plugin_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def _fake_entry_points(*args: Any, **kwargs: Any) -> list[Any]:
        captured.update(kwargs)
        return []

    monkeypatch.setattr("importlib.metadata.entry_points", _fake_entry_points)
    assert discover_and_load_plugins(object()) == []
    assert captured.get("group") == PLUGIN_GROUP


def test_discover_and_load_plugins_handles_enumeration_failure(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def _fake_entry_points(*args: Any, **kwargs: Any) -> list[Any]:
        raise RuntimeError("enumeration failed")

    monkeypatch.setattr("importlib.metadata.entry_points", _fake_entry_points)
    with caplog.at_level(logging.WARNING, logger="verity.mcp_server.plugin_loader"):
        loaded = discover_and_load_plugins(object())
    assert loaded == []
    messages = [record.getMessage() for record in caplog.records]
    assert any(
        message == "Failed to enumerate verity plugins: enumeration failed"
        for message in messages
    )


def test_discover_and_load_plugins_calls_callable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoked: list[Any] = []

    def _plugin_init(dispatcher: Any) -> None:
        invoked.append(dispatcher)

    _patch_entry_points(monkeypatch, [_FakeEntryPoint("alpha", _plugin_init)])
    dispatcher = object()
    loaded = discover_and_load_plugins(dispatcher)
    assert loaded == ["alpha"]
    assert invoked == [dispatcher]


def test_discover_and_load_plugins_non_callable_is_loaded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_points(monkeypatch, [_FakeEntryPoint("beta", "not-callable")])
    assert discover_and_load_plugins(object()) == ["beta"]


def test_discover_and_load_plugins_handles_exception(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _patch_entry_points(monkeypatch, [_FakeEntryPoint("boom", ValueError("explode"))])
    with caplog.at_level(logging.WARNING, logger="verity.mcp_server.plugin_loader"):
        loaded = discover_and_load_plugins(object())
    assert loaded == []
    assert any(record.levelno == logging.WARNING for record in caplog.records)


def test_discover_and_load_plugins_continues_after_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: list[Any] = []

    def _good_init(dispatcher: Any) -> None:
        called.append(dispatcher)

    _patch_entry_points(
        monkeypatch,
        [
            _FakeEntryPoint("bad", RuntimeError("nope")),
            _FakeEntryPoint("good", _good_init),
        ],
    )
    dispatcher = object()
    loaded = discover_and_load_plugins(dispatcher)
    assert loaded == ["good"]
    assert called == [dispatcher]


# ---------------------------------------------------------------------------
# UNIFIED_TOOL_DEFINITIONS
# ---------------------------------------------------------------------------


def test_unified_tool_definitions_contains_all_tools() -> None:
    names = {tool["name"] for tool in UNIFIED_TOOL_DEFINITIONS}
    assert names == {
        "verity_security_scan",
        "verity_database_guard",
        "verity_database_oracle",
        "verity_remediation_ops",
    }


def test_unified_tool_definitions_have_action_contract() -> None:
    for tool in UNIFIED_TOOL_DEFINITIONS:
        schema = tool["inputSchema"]
        assert schema["type"] == "object"
        assert "action" in schema["required"]
