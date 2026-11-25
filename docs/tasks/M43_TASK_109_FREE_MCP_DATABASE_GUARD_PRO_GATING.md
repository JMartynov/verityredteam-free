---
task_id: M43
alias: TASK-109-FREE
title: "Free MCP Database Guard Pro Gating"
status: Ready
priority: P0
size: XS
estimate_days: 1
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhLvm_M
target_repos: [verityredteam-free]
---


## Context & Objectives

The Free `verity_database_guard` tool serves SQL validation. Two of its actions belong
to Verity Pro: NoSQL filter validation and response-volume enforcement. On a Free
installation those actions must fail closed with a structured `PRO_FEATURE_REQUIRED`
error rather than importing Pro modules or approximating the check.

This task implements only the Free gating behaviour.

## Scope

| File | Change |
| --- | --- |
| `src/verity/mcp_server/handlers/database.py` | Edition gate for the two Pro-only actions |
| `tests/unit/mcp_server/test_database_guard_pro_gating.py` | Gate and benign Free-action tests |

Out of scope: the Pro guard implementations themselves and any other MCP tool.

## Contract

When the `verity-pro` plugin is absent:

- `verity_database_guard(action="validate_nosql_filter", ...)` returns
  `{"error": "PRO_FEATURE_REQUIRED", "feature": "validate_nosql_filter"}`.
- `verity_database_guard(action="enforce_volume_policy", ...)` returns
  `{"error": "PRO_FEATURE_REQUIRED", "feature": "enforce_volume_policy"}`.
- Neither path performs guard logic, and neither imports a Pro-only filter or volume
  guard module. The gate is evaluated before any import of optional dependencies.
- The response is a normal tool result; the MCP server keeps serving later requests.

The Free `validate_query` action continues to work exactly as before, including on the
same server instance that just returned a `PRO_FEATURE_REQUIRED` result.

## ATDD Traceability Matrix

| Acceptance Criterion | Test Level | Target File / Function | Description | Status |
| --- | --- | --- | --- | --- |
| AC-43.1 | unit | `tests/unit/mcp_server/test_database_guard_pro_gating.py::test_pro_feature_required_and_free_action_benign` | Pro-only action returns `PRO_FEATURE_REQUIRED`; `validate_query` still succeeds on the same instance. | Pending |
| AC-43.2 | unit | `tests/unit/mcp_server/test_database_guard_pro_gating.py::test_enforce_volume_policy_gated` | Volume enforcement is gated with the structured error and performs no guard logic. | Pending |
| AC-43.3 | static | `uv run ruff check src tests` | Zero lint findings. | Pending |

## Validation Commands

~~~bash
uv run pytest tests/unit/mcp_server/test_database_guard_pro_gating.py -q
uv run ruff check src tests
~~~

## Delivery Checklist

- [ ] `validate_nosql_filter` gated when the plugin is absent.
- [ ] `enforce_volume_policy` gated when the plugin is absent.
- [ ] Gate runs before any Pro-module import.
- [ ] `validate_query` remains functional on the same server instance.
- [ ] Structured error shape matches the documented contract.
- [ ] `uv run ruff check src tests` clean.
