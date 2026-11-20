"""Cryptographic canary proof tests for the database oracle handlers."""

from __future__ import annotations

from typing import Any

import pytest

from verity.fingerprint.matcher import FingerprintMatcher
from verity.lookup.engine import VulnerabilityLookupEngine
from verity.mcp_server.bootstrap import ServerContext
from verity.mcp_server.handlers.database_oracle import (
    generate_signed_canary,
    verify_canary_signature,
)
from verity.mcp_server.tools import VerityToolDispatcher

_HEX_CHARS = "0123456789abcdef"


@pytest.fixture(autouse=True)
def _isolate_oracle_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VERITY_ORACLE_SECRET_KEY", raising=False)


def _make_dispatcher(pro: bool) -> VerityToolDispatcher:
    ctx = ServerContext(FingerprintMatcher(), VulnerabilityLookupEngine())
    dispatcher = VerityToolDispatcher(ctx, load_plugins=False)
    if pro:
        dispatcher.set_remediation_pro_enabled(True)
    return dispatcher


def _check(dispatcher: VerityToolDispatcher, **options: Any) -> dict[str, Any]:
    return dispatcher.execute_tool(
        "verity_database_oracle",
        {"action": "check_canary_proof", "options": options},
    )


def _assert_deception(res: dict[str, Any]) -> None:
    assert res["ok"] is True
    assert res["status"] == "NOT_CONFIRMED"
    assert res["verdict"] == "VERIFIER_DECEPTION_DETECTED"
    assert res["error_code"] == "VERIFIER_DECEPTION_DETECTED"
    assert res["deception_detected"] is True
    assert res["signature_verified"] is False
    assert res["corroborated"] is False
    assert res["details"].startswith("VERIFIER_DECEPTION_DETECTED:")


def _assert_confirmed(res: dict[str, Any], *, signature_verified: bool) -> None:
    assert res["ok"] is True
    assert res["deception_detected"] is False
    assert res["corroborated"] is True
    assert res["signature_verified"] is signature_verified
    assert res["status"] in ("CONFIRMED", "VERIFIED")


def test_generate_signed_canary_format() -> None:
    token = generate_signed_canary()
    raw_token, signature = token.rsplit(".SIG_", 1)
    assert raw_token.startswith("CANARY_")
    assert len(raw_token) == len("CANARY_") + 12
    assert len(signature) == 16
    assert all(c in _HEX_CHARS for c in signature)
    assert verify_canary_signature(token) == (True, raw_token)


def test_verify_canary_signature_is_deterministic() -> None:
    token = generate_signed_canary(secret_key=b"unit-test-key")
    first = verify_canary_signature(token, secret_key=b"unit-test-key")
    second = verify_canary_signature(token, secret_key=b"unit-test-key")
    assert first == second
    assert first[0] is True


def test_valid_signed_canary_confirmed() -> None:
    dispatcher = _make_dispatcher(pro=True)
    token = generate_signed_canary()
    _assert_confirmed(_check(dispatcher, canary_token=token), signature_verified=True)


def test_tampered_payload_or_signature_rejected() -> None:
    dispatcher = _make_dispatcher(pro=True)
    token = generate_signed_canary()
    raw_token, signature = token.rsplit(".SIG_", 1)

    _assert_deception(
        _check(dispatcher, canary_token=f"CANARY_TAMPERED_999.SIG_{signature}")
    )

    flipped = "0" if signature[-1] != "0" else "1"
    _assert_deception(
        _check(dispatcher, canary_token=f"{raw_token}.SIG_{signature[:-1]}{flipped}")
    )


@pytest.mark.parametrize(
    "token",
    [
        "CANARY_FORGED_123",
        "CANARY_EXPIRED_2024",
        "CANARY_UNAUDITED_PARTIAL_9999",
        "",
        12345,
    ],
)
def test_forged_unsigned_tokens_rejected(token: Any) -> None:
    dispatcher = _make_dispatcher(pro=True)
    _assert_deception(_check(dispatcher, canary_token=token))


def test_signed_expired_or_unaudited_tokens_rejected() -> None:
    dispatcher = _make_dispatcher(pro=True)
    expired = generate_signed_canary(raw_token="CANARY_EXPIRED_2024")
    unaudited = generate_signed_canary(raw_token="CANARY_UNAUDITED_PARTIAL_9999")
    _assert_deception(_check(dispatcher, canary_token=expired))
    _assert_deception(_check(dispatcher, canary_token=unaudited))


def test_session_bound_signature() -> None:
    dispatcher = _make_dispatcher(pro=True)
    token = generate_signed_canary(session_id="sess-abc")
    _assert_confirmed(
        _check(dispatcher, canary_token=token, session_id="sess-abc"),
        signature_verified=True,
    )
    _assert_deception(_check(dispatcher, canary_token=token, session_id="sess-xyz"))
    _assert_deception(_check(dispatcher, canary_token=token))


def test_explicit_secret_key_override() -> None:
    token = generate_signed_canary(secret_key=b"explicit-key-a")
    assert verify_canary_signature(token, secret_key=b"explicit-key-a")[0] is True
    assert verify_canary_signature(token, secret_key=b"explicit-key-b")[0] is False


def test_env_secret_key_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VERITY_ORACLE_SECRET_KEY", "env-key-a")
    token = generate_signed_canary()
    assert verify_canary_signature(token)[0] is True

    monkeypatch.setenv("VERITY_ORACLE_SECRET_KEY", "env-key-b")
    assert verify_canary_signature(token)[0] is False

    assert verify_canary_signature(token, secret_key=b"env-key-a")[0] is True


@pytest.mark.parametrize(
    "token",
    [
        "CANARY_ABC.SIG_123",
        "CANARY_ABC.SIG_" + "A" * 16,
        "CANARY_ABC.SIG_" + "g" * 16,
        "CANARY_ABC.SIG_",
        ".SIG_" + "0" * 16,
        "NO_DELIMITER_CANARY",
    ],
)
def test_malformed_signatures_rejected(token: str) -> None:
    dispatcher = _make_dispatcher(pro=True)
    _assert_deception(_check(dispatcher, canary_token=token))


def test_backward_compatible_manifest_canary() -> None:
    dispatcher = _make_dispatcher(pro=False)
    dispatcher.set_canary_manifest({"acme": "CANARY_ACME_MANIFEST_001"})

    _assert_confirmed(
        _check(dispatcher, canary_token="CANARY_ACME_MANIFEST_001"),
        signature_verified=False,
    )
    _assert_deception(
        _check(
            dispatcher,
            canary_token="CANARY_ACME_MANIFEST_001",
            require_signature=True,
        )
    )


def test_backward_compatible_audited_deception_canary() -> None:
    dispatcher = _make_dispatcher(pro=True)

    _assert_confirmed(
        _check(
            dispatcher,
            canary_token="CANARY_VERIFY_DECEPTION_001",
            audit_event_id="evt-42",
        ),
        signature_verified=False,
    )
    _assert_deception(
        _check(
            dispatcher,
            canary_token="CANARY_VERIFY_DECEPTION_001",
            audit_event_id="evt-42",
            require_signature=True,
        )
    )
    _assert_deception(_check(dispatcher, canary_token="CANARY_VERIFY_DECEPTION_001"))


def test_pro_feature_gate_without_pro_or_manifest() -> None:
    dispatcher = _make_dispatcher(pro=False)
    res = _check(dispatcher, canary_token=generate_signed_canary())
    assert res["ok"] is False
    assert res["error"] == "PRO_FEATURE_REQUIRED"


def test_empty_manifest_values_never_match() -> None:
    dispatcher = _make_dispatcher(pro=False)
    dispatcher.set_canary_manifest({"acme": ""})
    _assert_deception(_check(dispatcher, canary_token="CANARY_UNRELATED_999"))


def test_empty_raw_token_generates_verifiable_canary() -> None:
    token = generate_signed_canary("")
    raw_token, signature = token.rsplit(".SIG_", 1)
    assert raw_token.startswith("CANARY_")
    assert len(signature) == 16
    assert verify_canary_signature(token) == (True, raw_token)
