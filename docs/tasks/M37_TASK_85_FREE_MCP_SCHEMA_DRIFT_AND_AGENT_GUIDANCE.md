---
task_id: M37
alias: TASK-85-FREE
title: "Free MCP Schema-Handler Drift & Structured Agent Guidance"
status: Not Done
priority: High (P0)
size: S
estimate_days: 2
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhLJPuo
target_repos: [verityredteam-free]
---

# M37 (`TASK-85-FREE`): Free MCP Schema-Handler Drift & Structured Agent Guidance

## Purpose & Architectural Decisions
- **Eliminate Schema-vs-Handler Drift (`85.1`)**: Expose `verify_physical_database` in `verity_database_oracle.inputSchema` and `generate_safe_parameterized_query` in `verity_remediation_ops.inputSchema` inside `UNIFIED_TOOL_DEFINITIONS` (`schemas.py`), and honor `options["dialect"]` (default `"postgres"`) in `remediation.py`. When `verity-pro` is absent, both Pro actions still return `PRO_FEATURE_REQUIRED`.
- **Dual-Path & Agent Guidance (`85.2`)**: Invoke `DualPathRouter.classify_server(...)` once per audit in `_full_audit_pipeline` (`security_scan.py`), build `UnknownCapabilityProfiler` plans whenever `audit_mode == "UNKNOWN_CAPABILITY_PROFILING"` and `tools` is non-empty, and emit read-only-safe `next_recommended_actions`.
- **Unified-Only Server Mode (`85.3`)**: Add `--unified-only` to `verity serve` (`cli.py` and `VerityDiscoveryMcpServer` in `server.py`) so `tools/list` returns only the 4 `UNIFIED_TOOL_DEFINITIONS`. *(Companion `SKILL.md` Mode A/Mode B split lives in `verityredteam` and is excluded from Free.)*

## Target Files
| File | Change |
| :--- | :--- |
| `src/verity/mcp_server/schemas.py` | Expose `verify_physical_database` and `generate_safe_parameterized_query` in `UNIFIED_TOOL_DEFINITIONS` |
| `src/verity/mcp_server/handlers/remediation.py` | Pass `read=options.get("dialect", "postgres")` to `sqlglot.parse` |
| `src/verity/mcp_server/handlers/security_scan.py` | Wire `DualPathRouter.classify_server`, UCP plans, and `next_recommended_actions` |
| `src/verity/mcp_server/server.py` | Add `unified_only: bool = False` option filtering `tools/list` and `/health` count |
| `src/verity/cli.py` | Add `--unified-only` flag to `verity serve` |
| `tests/unit/mcp_server/test_schema_drift_and_guidance.py` | Schema-vs-handler parity, `next_recommended_actions`, and `--unified-only` tests |

## ATDD Traceability Matrix
| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-37.1` | `UNIFIED_TOOL_DEFINITIONS` exposes all actions supported by `DatabaseOracleHandlerMixin` and `RemediationHandlerMixin`. | Without `verity-pro`, Pro actions return `PRO_FEATURE_REQUIRED`; free actions still work. | `unit` | `tests/unit/mcp_server/test_schema_drift_and_guidance.py::test_schema_matches_handlers` |
| `AC-37.2` | `generate_safe_parameterized_query` honors `options["dialect"]` (default `"postgres"`). | Omitted `dialect` defaults cleanly to `"postgres"`. | `unit` | `tests/unit/mcp_server/test_schema_drift_and_guidance.py::test_remediation_dialect_honored` |
| `AC-37.3` | `_full_audit_pipeline` invokes `DualPathRouter.classify_server` once and emits `ReadOnlySafetyGuard`-safe `next_recommended_actions`. | Known passport server routes to Path A (`KNOWN`). | `unit` | `tests/unit/mcp_server/test_schema_drift_and_guidance.py::test_dual_path_and_guidance` |
| `AC-37.4` | `verity serve --unified-only` exposes exactly the 4 unified tools on `tools/list` and `/health`. | Default `verity serve` preserves legacy tools alongside unified tools. | `unit` | `tests/unit/mcp_server/test_schema_drift_and_guidance.py::test_serve_unified_only` |
| `AC-37.5` | Ruff linter and unit test suite pass with zero violations. | Clean code conforms to ruff rules. | `ruff` | `uv run ruff check src tests` |
