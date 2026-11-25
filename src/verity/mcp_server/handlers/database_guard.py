"""Database guard MCP tool handlers."""

from __future__ import annotations

import logging
from typing import Any

from verity.mcp_library.sql_guard import SqlSecurityError, SqlSecurityGuard
from verity.mcp_server.protocols import pro_feature_required_response

logger = logging.getLogger("verity.mcp_server.tools")


class DatabaseGuardHandlerMixin:
    """Handlers for verity_database_guard."""

    def _execute_database_guard(self, args: dict[str, Any]) -> dict[str, Any]:
        action = args.get("action", "")
        options = args.get("options")
        if not isinstance(options, dict):
            options = {}

        if action in ("validate_sql_query", "validate_query"):
            sql_query = options.get("sql_query", "")
            dialect = options.get("dialect") or "postgres"
            if isinstance(dialect, str):
                dialect = dialect.strip().lower()
            timeout_ms = options.get("timeout_ms")
            try:
                SqlSecurityGuard.validate_single_select_statement(
                    sql_query, dialect=dialect
                )
                SqlSecurityGuard.validate_parameterized_query(sql_query)
                clamped_timeout = SqlSecurityGuard.validate_statement_timeout(timeout_ms)
                return {
                    "ok": True,
                    "action": action,
                    "verdict": "ALLOWED",
                    "dialect": dialect,
                    "details": (
                        "SQL query satisfies parameterization, single-statement, "
                        "and catalog isolation rules."
                    ),
                    "clamped_timeout_ms": clamped_timeout,
                }
            except SqlSecurityError as e:
                return {
                    "ok": False,
                    "action": action,
                    "verdict": "BLOCKED",
                    "dialect": dialect,
                    "violations": [str(e)],
                    "remediation": (
                        "Ensure query is a single SELECT/WITH statement without "
                        "semicolons or catalog access."
                    ),
                }

        if action == "validate_nosql_filter":
            filter_guard = getattr(self, "_guards", {}).get("nosql_filter")
            if filter_guard is None:
                return pro_feature_required_response(
                    "validate_nosql_filter",
                    "NoSQL filter validation requires the verity-pro plugin.",
                )
            if "filter_obj" in options:
                filter_obj = options["filter_obj"]
            elif "filter_obj" in args:
                filter_obj = args["filter_obj"]
            elif "filter" in options:
                filter_obj = options["filter"]
            else:
                filter_obj = args.get("filter")
            session_tenant = (
                options.get("session_tenant")
                or args.get("session_tenant")
                or "default"
            )
            allowed_fields = (
                options["allowed_fields"]
                if "allowed_fields" in options
                else args.get("allowed_fields")
            )
            if allowed_fields is not None and isinstance(
                allowed_fields, list | tuple | set
            ):
                allowed_fields = frozenset(allowed_fields)
            max_depth = options.get("max_depth", args.get("max_depth", 3))
            try:
                sanitized = filter_guard.validate_and_sanitize(
                    filter_obj=filter_obj,
                    session_tenant=session_tenant,
                    allowed_fields=allowed_fields,
                    max_depth=max_depth,
                )
            except Exception as exc:
                code = getattr(exc, "code", None)
                if code is None:
                    message = str(exc)
                    if "Forbidden NoSQL query operator" in message:
                        code = "NOSQL_OPERATOR_BLOCKED"
                    elif "maximum depth" in message:
                        code = "FILTER_DEPTH_EXCEEDED"
                    elif "not in allowed search fields" in message:
                        code = "FIELD_NOT_ALLOWED"
                    else:
                        code = "INVALID_FILTER"
                return {
                    "ok": False,
                    "action": action,
                    "verdict": "BLOCKED",
                    "error": "FILTER_VALIDATION_FAILED",
                    "code": code,
                    "message": str(exc),
                }
            return {
                "ok": True,
                "action": action,
                "verdict": "ALLOWED",
                "sanitized_filter": sanitized,
                "mode": "schema_less" if allowed_fields is None else "allowlist",
            }

        if action == "enforce_volume_policy":
            volume_guard = getattr(self, "_guards", {}).get("volume_policy")
            if volume_guard is None:
                return pro_feature_required_response(
                    "enforce_volume_policy",
                    "Volume policy enforcement requires the verity-pro plugin.",
                )
            records = (
                options["records"] if "records" in options else args.get("records", [])
            )
            if records is None:
                records = []
            records = list(records)
            requested_limit = (
                options["requested_limit"]
                if "requested_limit" in options
                else args.get("requested_limit")
            )
            clamped_limit = volume_guard.clamp_limit(requested_limit)
            bounded = records[:clamped_limit]
            truncated_records, byte_truncated = volume_guard.truncate_payload(bounded)
            truncated = byte_truncated or (len(records) > len(truncated_records))
            payload_sha256 = volume_guard.compute_evidence_hash(truncated_records)
            return {
                "ok": True,
                "action": action,
                "verdict": "ALLOWED",
                "records": truncated_records,
                "record_count": len(truncated_records),
                "clamped_limit": clamped_limit,
                "truncated": truncated,
                "payload_sha256": payload_sha256,
            }

        if action == "validate_snowflake_policy":
            snowflake_guard = getattr(self, "_guards", {}).get("snowflake")
            if snowflake_guard is None:
                return pro_feature_required_response(
                    action,
                    "Snowflake policy validation requires the verity-pro plugin.",
                )
            role = options.get("requested_role", "ANALYST_READ_ROLE")
            persona = options.get("persona") or options.get("target_persona", "data_analyst")
            allowed_role = options.get("allowed_role", "ANALYST_READ_ROLE")
            sql_query = options.get("sql_query")
            stage_path = options.get("stage_path")
            tag_override = options.get("tag_override")
            query_tag = options.get("query_tag")

            violations: list[str] = []
            try:
                snowflake_guard.validate_session_role(
                    role, allowed_role=allowed_role, persona=persona
                )
            except Exception as e:
                violations.append(str(e))

            if sql_query:
                try:
                    snowflake_guard.validate_query(sql_query)
                except Exception as e:
                    violations.append(str(e))
                try:
                    snowflake_guard.validate_time_travel(sql_query)
                except Exception as e:
                    violations.append(str(e))

            if stage_path:
                try:
                    snowflake_guard.validate_stage_path(stage_path)
                except Exception as e:
                    violations.append(str(e))

            if tag_override:
                try:
                    snowflake_guard.validate_tag_masking(tag_override)
                except Exception as e:
                    violations.append(str(e))

            if query_tag:
                try:
                    snowflake_guard.validate_query_tag(query_tag)
                except Exception as e:
                    violations.append(str(e))

            if violations:
                return {
                    "ok": False,
                    "action": action,
                    "verdict": "BLOCKED",
                    "violations": violations,
                }
            return {
                "ok": True,
                "action": action,
                "verdict": "ALLOWED",
                "details": "Warehouse policy compliance verified.",
            }

        if action == "apply_projection_mask":
            row_data = options.get("row_data") or {}
            allowed = options.get("allowed_columns") or []
            masked = SqlSecurityGuard.apply_projection(row_data, allowed) or {}
            pruned = [k for k in row_data if k not in set(allowed)]
            return {
                "ok": True,
                "action": action,
                "pruned_fields": pruned,
                "masked_row": masked,
            }

        if action == "sanitize_inputs":
            pattern = options.get("search_pattern")
            sanitized = SqlSecurityGuard.sanitize_like_pattern(pattern) if pattern else ""
            return {
                "ok": True,
                "action": action,
                "sanitized_pattern": sanitized,
            }

        return {
            "ok": False,
            "error": f"Unsupported action '{action}' for verity_database_guard",
        }

    # =========================================================================
    # Unified Tool 3: verity_database_oracle
    # =========================================================================
