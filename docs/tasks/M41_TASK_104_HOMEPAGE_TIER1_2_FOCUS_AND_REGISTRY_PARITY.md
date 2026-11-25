---
task_id: M41
alias: TASK-104
title: "Homepage Tier 1/2 Focus & Registry Parity"
status: Done
priority: P0
size: S
estimate_days: 2
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhLvmDo
target_repos: [verityredteam-free]
---


## Context & Objectives

The documentation homepage must tell one honest story: the twelve Tier 1 and thirteen
Tier 2 capabilities a customer actually installs Verity for. Everything else lives in a
separate appendix. At the same time, every rule ID, demo slug, and MCP tool name on the
homepage must resolve against a runtime constant, so documentation cannot drift from the
engine.

This task delivered both properties and is complete.

## Scope

| File | Change |
| --- | --- |
| `docs/index.md` | Tier 1 (12) and Tier 2 (13) tables, single auxiliary link, `[Pro]` SARIF badge |
| `docs/reference/auxiliary_and_benchmarks.md` | Tier 3/4 catalogue outside the primary story |
| `mkdocs.yml` | `Reference:` nav entry for the appendix |
| `src/verity/scanner/static_rules.py` | `STATIC_RULE_IDS` runtime registry (13 rules) |
| `src/verity/scanner/python_ast.py` | `AST_RULE_IDS` runtime registry (9 rules) |
| `src/verity/targets/__init__.py` | `TARGET_SLUGS` runtime registry |
| `src/verity/mcp_server/server.py` | `MCP_TOOL_NAMES` runtime registry (4 tools) |
| `tests/unit/test_docs_homepage_parity.py` | Parity and paired benign-control tests |

## Contract

- The homepage showcases only Tier 1 (12 rows) and Tier 2 (13 rows); no `## Tier 3` or
  `## Tier 4` heading exists.
- Exactly one auxiliary link is present, labelled
  `Auxiliary & Benchmark Appendix (Tier 3/4)`, and it appears after the Tier 2 section.
- Every `VERITY-STATIC-*` and `VERITY-AST-*` token on the homepage resolves in the
  live registries, and the rule catalog equals the union of both registries.
- Every demo slug on the homepage resolves in `TARGET_SLUGS`; `postgres-basic` is
  present and `postgres-multitenant` is absent.
- The Agent-Native MCP Server section lists exactly the four `MCP_TOOL_NAMES`; legacy
  `mcp_*` tool names are purged.
- `--format sarif` is badged `[Pro]` and carries the
  `PRO_FEATURE_REQUIRED` (exit code 2) note; `terminal`, `json`, `markdown`, and `html`
  carry no `[Pro]` badge.

## ATDD Traceability Matrix

| Acceptance Criterion | Test Level | Target File / Function | Description | Status |
| --- | --- | --- | --- | --- |
| AC-41.1 | unit | `tests/unit/test_docs_homepage_parity.py::test_homepage_focuses_tier1_tier2` | 12 Tier 1 rows, 13 Tier 2 rows, no Tier 3/4 heading, one auxiliary link. | Done |
| AC-41.2 | unit | `tests/unit/test_docs_homepage_parity.py::test_rule_ids_resolve_in_live_code` | Homepage rule IDs resolve in the live registries; catalog equals the union. | Done |
| AC-41.3 | unit | `tests/unit/test_docs_homepage_parity.py::test_target_slug_parity` | Demo slugs resolve in `TARGET_SLUGS`; `postgres-multitenant` absent. | Done |
| AC-41.4 | unit | `tests/unit/test_docs_homepage_parity.py::test_mcp_tool_names_parity` | Section lists exactly the four live MCP tool names; legacy names purged. | Done |
| AC-41.5 | unit | `tests/unit/test_docs_homepage_parity.py::test_sarif_pro_badge` | SARIF carries `[Pro]` plus `PRO_FEATURE_REQUIRED`/exit code 2; Free formats unbadged. | Done |
| AC-41.6 | unit | `tests/unit/test_docs_homepage_parity.py::test_auxiliary_page_nav` | Appendix exists with Tier 3/4 content and is registered in `mkdocs.yml`. | Done |
| AC-41.7 | static | `uv run ruff check src tests` | Zero lint findings. | Done |

## Verification Evidence

~~~bash
uv run pytest tests/unit/test_docs_homepage_parity.py -q
uv run ruff check src tests
~~~

Both commands passed on the delivered branch.

## Delivery Checklist

- [x] Tier 1 table has exactly 12 rows.
- [x] Tier 2 table has exactly 13 rows.
- [x] No Tier 3 or Tier 4 heading on the homepage.
- [x] Single auxiliary link placed after the Tier 2 section.
- [x] Rule IDs, demo slugs, and MCP tool names match runtime registries.
- [x] `--format sarif` badged `[Pro]` with `PRO_FEATURE_REQUIRED` (exit code 2).
- [x] Appendix page registered under `Reference:` in `mkdocs.yml`.
- [x] Paired benign controls committed; lint clean.
