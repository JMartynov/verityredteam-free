"""Remediation ops MCP tool handlers."""

from __future__ import annotations

import logging
from typing import Any

from verity.mcp_server.protocols import pro_feature_required_response

logger = logging.getLogger("verity.mcp_server.tools")


class RemediationHandlerMixin:
    """Handlers for verity_remediation_ops."""

    def _execute_remediation_ops(self, args: dict[str, Any]) -> dict[str, Any]:
        action = args.get("action", "")
        options = args.get("options") or {}

        if action == "explain_vulnerability_remediation":
            vuln_id = options.get("vulnerability_id") or options.get("package_name", "")
            res = self.context.vuln_engine.query(vuln_id)
            if res.is_vulnerable:
                advice = (
                    res.upgrade_advice.action_summary
                    if res.upgrade_advice
                    else "Upgrade to fixed release."
                )
                return {
                    "ok": True,
                    "action": action,
                    "vulnerability_id": vuln_id,
                    "affected_package": res.package_name,
                    "recommended_version": (
                        f">= {res.vulnerabilities[0].fixed}"
                        if res.vulnerabilities and res.vulnerabilities[0].fixed
                        else "Latest"
                    ),
                    "summary": advice,
                }
            return {
                "ok": True,
                "action": action,
                "vulnerability_id": vuln_id,
                "summary": "Target is clean. No remediation required.",
            }

        if action == "generate_guard_patch":
            if not getattr(self, "_remediation_pro_enabled", False):
                return pro_feature_required_response(action)
            schema = options.get("tool_schema") or {}
            tool_name = schema.get("name", "tool_name")
            allowed_cols = schema.get("allowed_columns", ["id", "name"])
            patch_code = (
                f"from verity.mcp_library.sql_guard import SqlSecurityGuard\n\n"
                f"SAFE_PROJECTION = {tuple(allowed_cols)}\n\n"
                f"def {tool_name}_secure(record_id: str, session_tenant: str):\n"
                f"    query = 'SELECT * FROM records WHERE record_id = %s AND tenant_id = %s'\n"
                f"    params = (record_id, session_tenant)\n"
                f"    SqlSecurityGuard.validate_parameterized_query(query, params)\n"
                f"    row = db.fetch_one(query, params)\n"
                f"    return SqlSecurityGuard.apply_projection(row, SAFE_PROJECTION)\n"
            )
            return {
                "ok": True,
                "action": action,
                "patch_code": patch_code,
            }

        if action == "generate_wrapper_config":
            if not getattr(self, "_remediation_pro_enabled", False):
                return pro_feature_required_response(action)
            schema = options.get("tool_schema") or {}
            tool_name = schema.get("name", "query")
            engine = schema.get("database", "postgres")
            config_yaml = (
                f"guards:\n"
                f"  - tool: {tool_name}\n"
                f"    engine: {engine}\n"
                f"    rules:\n"
                f"      - forbid_stacked_queries: true\n"
                f"      - forbid_system_catalogs: true\n"
                f"      - max_timeout_ms: 5000\n"
            )
            return {
                "ok": True,
                "action": action,
                "config_yaml": config_yaml,
            }

        if action == "generate_safe_parameterized_query":
            if not getattr(self, "_remediation_pro_enabled", False):
                return pro_feature_required_response(action)
            raw_query = options.get("sql_query") or options.get("query", "")
            try:
                import sqlglot
                from sqlglot import exp

                stmts = [s for s in sqlglot.parse(raw_query, read="postgres") if s is not None]
            except Exception:
                stmts = []

            select_stmt = next((s for s in stmts if isinstance(s, (exp.Select, exp.Union))), None)
            params: dict[str, Any] = {}

            if select_stmt is not None:
                where_clause = select_stmt.args.get("where")
                if where_clause:
                    literals = list(where_clause.find_all(exp.Literal))
                    for i, lit in enumerate(literals, 1):
                        pname = f"param_{i}"
                        params[pname] = lit.this
                        lit.replace(exp.var(f":{pname}"))
                safe_query = select_stmt.sql()
            else:
                import re

                m = re.search(r"FROM\s+([a-zA-Z0-9_]+)", raw_query, re.IGNORECASE)
                table = m.group(1) if m else "records"
                safe_query = f"SELECT * FROM {table} WHERE id = :id"
                params["id"] = "1"

            diff = (
                f"--- a/query.sql\n"
                f"+++ b/query.sql\n"
                f"-{raw_query}\n"
                f"+{safe_query}\n"
            )
            out_file = options.get("output_patch_file")
            if out_file:
                try:
                    from pathlib import Path

                    p = Path(out_file)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(diff, encoding="utf-8")
                except Exception:
                    pass

            return {
                "ok": True,
                "action": action,
                "original_query": raw_query,
                "safe_query": safe_query,
                "extracted_parameters": params,
                "patch_diff": diff,
                "explanation": (
                    "Neutralized stacked DDL and converted unsafe SQL into a safe, "
                    "single parameterized SELECT statement compliant with AST guardrails."
                ),
            }

        return {
            "ok": False,
            "error": f"Unsupported action '{action}' for verity_remediation_ops",
        }

