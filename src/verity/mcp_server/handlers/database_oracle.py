"""Database oracle MCP tool handlers."""

from __future__ import annotations

import logging
from typing import Any

from verity.mcp_server.protocols import (
    BasicResponseOracle,
    pro_feature_required_response,
)

logger = logging.getLogger("verity.mcp_server.tools")


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
            manifest = getattr(self, "_canary_manifest", None)
            if manifest is None and not getattr(self, "_remediation_pro_enabled", False):
                return pro_feature_required_response(
                    action,
                    "Canary proof verification requires the verity-pro plugin.",
                )
            if manifest is None:
                manifest = {}

            is_customer_canary = any(
                isinstance(canary, str) and (c_val in canary or canary == c_val)
                for c_val in manifest.values()
            )
            is_valid_canary = bool(
                canary
                and isinstance(canary, str)
                and (
                    is_customer_canary
                    or (audit_id and canary.startswith("CANARY_VERIFY_DECEPTION_"))
                    or (
                        canary.startswith("CANARY_")
                        and not canary.startswith("CANARY_EXPIRED")
                        and not canary.startswith("CANARY_UNAUDITED")
                    )
                    or canary.startswith("AWS_CANARY_")
                    or canary.startswith("flag{")
                )
            )

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
            is_confirmed = (
                res.status.value == "CONFIRMED"
                if hasattr(res.status, "value")
                else str(res.status) == "CONFIRMED"
            )
            return {
                "ok": True,
                "action": action,
                "status": res.status.value if hasattr(res.status, "value") else str(res.status),
                "corroborated": bool(mock_resp["verification_corroborated"] and is_confirmed),
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
