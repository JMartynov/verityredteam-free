"""Database oracle MCP tool handlers."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import uuid
from typing import Any

from verity.mcp_server.protocols import (
    BasicResponseOracle,
    pro_feature_required_response,
)

logger = logging.getLogger("verity.mcp_server.tools")

__all__ = [
    "DatabaseOracleHandlerMixin",
    "generate_signed_canary",
    "verify_canary_signature",
]

DEFAULT_ORACLE_SECRET_KEY = b"verity-oracle-hmac-default-key"


def _get_oracle_secret_key(secret_key: bytes | str | None = None) -> bytes:
    """Resolve the HMAC secret key: explicit > env var > built-in default."""
    if secret_key is not None:
        return secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
    env_key = os.environ.get("VERITY_ORACLE_SECRET_KEY", "")
    if env_key:
        return env_key.encode("utf-8")
    return DEFAULT_ORACLE_SECRET_KEY


def _compute_canary_signature(raw_token: str, secret_key: bytes, session_id: str | None) -> str:
    """Compute the truncated HMAC-SHA256 signature for a canary payload."""
    payload = f"{raw_token}:{session_id}" if session_id is not None else raw_token
    digest = hmac.new(secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:16]


def generate_signed_canary(
    raw_token: str | None = None,
    *,
    secret_key: bytes | str | None = None,
    session_id: str | None = None,
) -> str:
    """Build a canary token carrying a truncated HMAC-SHA256 signature."""
    if not raw_token:
        raw_token = f"CANARY_{uuid.uuid4().hex[:12].upper()}"
    signature = _compute_canary_signature(
        raw_token,
        _get_oracle_secret_key(secret_key),
        session_id,
    )
    return f"{raw_token}.SIG_{signature}"


def verify_canary_signature(
    canary_token: str,
    *,
    secret_key: bytes | str | None = None,
    session_id: str | None = None,
) -> tuple[bool, str]:
    """Verify a signed canary token, returning ``(is_valid, raw_token)``."""
    if not isinstance(canary_token, str):
        return False, ""
    if ".SIG_" not in canary_token:
        return False, canary_token
    raw_token, signature = canary_token.rsplit(".SIG_", 1)
    if not raw_token:
        return False, raw_token
    if len(signature) != 16 or any(c not in "0123456789abcdef" for c in signature):
        return False, raw_token
    expected = _compute_canary_signature(
        raw_token,
        _get_oracle_secret_key(secret_key),
        session_id,
    )
    return hmac.compare_digest(expected, signature), raw_token


class DatabaseOracleHandlerMixin:
    """Handlers for verity_database_oracle."""

    def _execute_database_oracle(self, args: dict[str, Any]) -> dict[str, Any]:
        action = args.get("action", "")
        options = args.get("options") or {}

        if action == "generate_attack_proposal":
            pkg = options.get("package_name") or options.get("target_server_id", "mongo-basic")
            cond_id = options.get("condition_id")
            plan_provider = getattr(self, "_plan_provider", None)
            if plan_provider is None:
                return pro_feature_required_response(
                    action,
                    "Attack proposal generation requires the verity-pro plugin.",
                )
            plan = plan_provider(pkg)
            matching_proposal = next(
                (p for p in plan if not cond_id or p.condition_id == cond_id), None
            )
            if matching_proposal:
                return {
                    "ok": True,
                    "action": action,
                    "condition_id": matching_proposal.condition_id,
                    "rationale": matching_proposal.rationale,
                    "proposed_calls": [
                        {
                            "tool_name": c.tool_name,
                            "arguments": c.arguments,
                            "hypothesis": c.hypothesis,
                        }
                        for c in matching_proposal.proposed_calls
                    ],
                }
            # Fallback to bridge
            bridge_res = self._audit_and_generate_exploit_plan(options)
            bridge_res["action"] = action
            return bridge_res

        if action == "verify_tool_response":
            cond_id = options.get("condition_id", "GENERIC_001")
            tool_resp = options.get("tool_response", {})
            mcp_args = options.get("mcp_arguments", {})
            profile = options.get("profile", "vulnerable")
            res = self.oracle.verify_condition(
                condition_id=cond_id,
                tool_response=tool_resp,
                mcp_arguments=mcp_args,
                profile=profile,
            )
            return {
                "ok": True,
                "action": action,
                "condition_id": res.condition_id,
                "status": res.status.value if hasattr(res.status, "value") else str(res.status),
                "details": res.details,
                "evidence": res.evidence,
                "observed_in_database": res.observed_in_database,
            }

        if action == "check_canary_proof":
            canary = options.get("canary_token", "")
            audit_id = options.get("audit_event_id", "")
            session_id = options.get("session_id")
            require_signature = bool(options.get("require_signature", False))
            manifest = getattr(self, "_canary_manifest", None)
            if manifest is None and not getattr(self, "_remediation_pro_enabled", False):
                return pro_feature_required_response(
                    action,
                    "Canary proof verification requires the verity-pro plugin.",
                )
            if manifest is None:
                manifest = {}

            def _deception_response(tool_action: str, reason: str) -> dict[str, Any]:
                return {
                    "ok": True,
                    "action": tool_action,
                    "status": "NOT_CONFIRMED",
                    "verdict": "VERIFIER_DECEPTION_DETECTED",
                    "error_code": "VERIFIER_DECEPTION_DETECTED",
                    "deception_detected": True,
                    "signature_verified": False,
                    "corroborated": False,
                    "details": f"VERIFIER_DECEPTION_DETECTED: {reason}",
                }

            if not canary or not isinstance(canary, str):
                return _deception_response(action, "missing or non-string canary token")

            signature_verified = False
            is_valid_canary = False

            if ".SIG_" in canary:
                is_signed_valid, raw_token = verify_canary_signature(
                    canary,
                    session_id=session_id,
                )
                if not is_signed_valid:
                    return _deception_response(action, "invalid canary signature")
                if raw_token.startswith("CANARY_EXPIRED") or raw_token.startswith(
                    "CANARY_UNAUDITED"
                ):
                    return _deception_response(action, "expired or unaudited signed canary")
                signature_verified = True
                is_valid_canary = True
            else:
                if require_signature:
                    return _deception_response(action, "unsigned canary rejected: signature required")
                is_customer_canary = any(
                    isinstance(c_val, str) and c_val and c_val in canary
                    for c_val in manifest.values()
                )
                is_audited_deception = bool(audit_id) and canary.startswith(
                    "CANARY_VERIFY_DECEPTION_"
                )
                if not (is_customer_canary or is_audited_deception):
                    return _deception_response(
                        action,
                        "unsigned canary not corroborated by manifest or audit trail",
                    )
                is_valid_canary = True

            mock_resp = {
                "ok": True,
                "canary_token": canary,
                "audit_event_id": audit_id,
                "verification_corroborated": is_valid_canary,
            }
            res = self.oracle.verify_condition(
                condition_id="VERIFY-CANARY-PROOF-001",
                tool_response=mock_resp,
                mcp_arguments={},
                profile="vulnerable",
            )
            status_val = res.status.value if hasattr(res.status, "value") else str(res.status)
            is_confirmed = status_val in ("CONFIRMED", "VERIFIED")
            return {
                "ok": True,
                "action": action,
                "status": status_val,
                "corroborated": bool(mock_resp["verification_corroborated"] and is_confirmed),
                "signature_verified": signature_verified,
                "deception_detected": False,
                "details": res.details,
            }

        if action == "verify_physical_database":
            if isinstance(self.oracle, BasicResponseOracle):
                return pro_feature_required_response(
                    action,
                    "Physical database verification requires the verity-pro plugin.",
                )
            engine = options.get("engine", "postgres")
            query = options.get("query") or options.get("sql_query") or options.get("filter") or ""
            expected_tenant = options.get("session_tenant") or options.get("expected_tenant")
            res = self.oracle.execute_physical_verification(
                engine=engine,
                query=query,
                expected_tenant=expected_tenant,
            )
            res["action"] = action
            return res

        return {
            "ok": False,
            "error": f"Unsupported action '{action}' for verity_database_oracle",
        }

    # =========================================================================
    # Unified Tool 4: verity_remediation_ops
    # =========================================================================
