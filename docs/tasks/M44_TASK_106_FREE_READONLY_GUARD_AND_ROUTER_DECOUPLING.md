---
task_id: M44
alias: TASK-106-FREE
title: "Free Read-Only Guard & Router Decoupling"
status: Done
priority: P1
size: S
estimate_days: 1
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhLvmgk
target_repos: [verityredteam-free]
---


## Context & Objectives

Two Free components carry fixture-coupled behaviour:

1. The read-only guard misses several destructive verbs that real MCP servers expose
   (`run_sql`, `execute_sql`, `upsert`, `post_`, `put_`, `patch_`, `chmod`, `kill`).
2. The dual-path router injects a hardcoded `"formula": "1 + 1"` argument for unknown
   tools, which fabricates caller intent instead of reflecting the target schema.

This task hardens the guard and removes the hardcoded payload from the router while
preserving known-tool arguments verbatim.

## Scope

| File | Change |
| --- | --- |
| `src/verity/scanner/readonly_guard.py` | Extended forbidden-verb coverage |
| `src/verity/scanner/dual_path_router.py` | Remove hardcoded formula; schema-driven skeleton |
| `tests/unit/test_readonly_guard.py` | Destructive-verb block and read-only allow tests |
| `tests/unit/test_dual_path_router.py` | No-hardcoded-formula and known-args-preserved tests |

Out of scope: transport probing and any Phase 2 mutation logic.

## Contract

### Read-only guard

- The forbidden-tool-keyword set blocks `run_sql`, `execute_sql`, `upsert`, `post_`,
  `put_`, `patch_`, `chmod`, and `kill` in addition to the existing destructive verbs.
- Read-only tools such as `list_customers` remain permitted.
- Argument scanning behaviour is unchanged: destructive SQL and shell payloads are
  still blocked recursively, and `phase != PHASE_1` still bypasses the guard.

### Dual-path router

- For unknown tools, the router must not inject the hardcoded `"formula": "1 + 1"`.
- Instead it emits the schema's required-argument skeleton with neutral type-correct
  values, or an explicit `NEEDS_ARGS` marker when a required argument cannot be
  synthesised safely.
- Known-tool arguments are preserved verbatim; no synthesised value overwrites a
  caller-supplied argument.

## ATDD Traceability Matrix

| Acceptance Criterion | Test Level | Target File / Function | Description | Status |
| --- | --- | --- | --- | --- |
| AC-44.1 | unit | `tests/unit/test_readonly_guard.py::test_destructive_verbs_blocked`, `::test_readonly_tool_allowed` | New destructive verbs are blocked; read-only tools stay permitted. | Verified (Green) |
| AC-44.2 | unit | `tests/unit/test_dual_path_router.py::test_no_hardcoded_formula_for_unknown_tool`, `::test_known_tool_args_preserved` | No hardcoded formula for unknown tools; known arguments preserved verbatim. | Verified (Green) |
| AC-44.3 | static | `uv run ruff check src tests` | Zero lint findings. | Verified (Green) |

## Validation Commands

~~~bash
uv run pytest tests/unit/test_readonly_guard.py tests/unit/test_dual_path_router.py -q
uv run ruff check src tests
~~~

## Delivery Checklist

- [x] `run_sql`, `execute_sql`, `upsert`, `post_`, `put_`, `patch_`, `chmod`, and `kill` blocked.
- [x] `list_customers` and equivalent read-only tools permitted.
- [x] Hardcoded `"formula": "1 + 1"` removed from the router.
- [x] Unknown-tool skeleton uses neutral values or `NEEDS_ARGS`.
- [x] Known-tool arguments preserved verbatim.
- [x] `uv run ruff check src tests` clean.
