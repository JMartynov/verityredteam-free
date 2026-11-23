---
task_id: "TASK-94"
title: "Web Documentation Portal & Automated Task-to-Docs Pipeline"
status: "Done"
priority: "P1"
phase: "Documentation & Portal"
target_repos: ["verityredteam-free"]
github_project_id: "PVT_kwHOD-xmQM4Br351"
github_item_id: "PVTI_lAHOD-xmQM4Br351zhLOM2U"
verification_levels: ["unit", "static", "cli-smoke"]
doc_targets: [
  "docs/index.md",
  "docs/getting-started/installation.md",
  "docs/getting-started/quickstart.md",
  "docs/cli/reference.md",
  "docs/rules/catalog.md",
  "docs/guards/sql-security-guard.md",
  "docs/mcp/server-and-ides.md",
  "docs/extensibility.md",
  "docs/roadmap/index.md",
  "docs/changelog/tasks.md"
]
acceptance_criteria: [
  "AC-38.1",
  "AC-38.2",
  "AC-38.3",
  "AC-38.4",
  "AC-38.5"
]
---

# Milestone M38: Web Documentation Portal & Automated Task-to-Docs Pipeline (`TASK-94`)

## Context & Objectives
Deliver a comprehensive, customer-centric Web Documentation Portal using **MkDocs Material** (100% Python toolchain via `uv`) hosted on GitHub Pages (`https://jmartynov.github.io/verityredteam-free/`), featuring instant rule search, beautiful dark/light themes, and an automated task-to-docs publisher integrated directly into `test_documentation_parity.py`.

## Detailed Customer-Centric Guide Pages
1. **`docs/index.md`**: Glassmorphic hero landing page, 1-click installation (`uvx verity-redteam-core scan`), live rules & advisories statistics, and ecosystem navigation tabs.
2. **`docs/getting-started/installation.md`**: Step-by-step installation guides across `pip`, `uvx`, Homebrew, and Docker containers with secret isolation warnings.
3. **`docs/getting-started/quickstart.md`**: 60-second single-player security scan (`verity scan`), zero-Docker vulnerability harness (`verity test --demo`), and terminal output walkthroughs.
4. **`docs/cli/reference.md`**: Comprehensive reference for `verity scan`, `verity test`, and `verity serve` flags (`--config-file`, `--format`, `--offline`, `--json`).
5. **`docs/rules/catalog.md`**: Complete catalog of 13 Static Rules (`VERITY-STATIC-*`) and 9 AST Rules (`VERITY-AST-*`) with CWE mappings and remediation code diffs.
6. **`docs/guards/sql-security-guard.md`**: Dialect-aware SQL injection protection across 7 SQL dialects (`postgres`, `mysql`, `sqlite`, `snowflake`, `bigquery`, `tsql`, `oracle`).
7. **`docs/mcp/server-and-ides.md`**: Pure-stdlib MCP server setup (`verity serve`) for AI coding agents (Antigravity, Claude Code, Cursor, Windsurf).
8. **`docs/extensibility.md`**: Custom Python checks, YAML static rules, and plugin extension architecture.

## 1-to-1 ATDD Traceability Matrix

| Acceptance Criterion | Test Level | Target File / Function | Description | Status |
| :--- | :--- | :--- | :--- | :--- |
| **`AC-38.1`** | `unit` | `tests/unit/test_documentation_parity.py::test_web_documentation_portal_structure` | Verifies MkDocs configuration `mkdocs.yml` and all 10 Markdown portal pages exist with >= 180 lines. | **Done** |
| **`AC-38.2`** | `static` | `.github/workflows/pages.yml` | GitHub Actions workflow successfully builds MkDocs site using `uv` and publishes to GitHub Pages. | **Done** |
| **`AC-38.3`** | `cli-smoke` | `tests/unit/test_documentation_parity.py::test_task_spec_and_board_parity` | Verifies M38 task spec file `docs/tasks/M38_web_documentation_portal_and_task_publisher.md` maps correctly to Project Board #5 item `PVTI_lAHOD-xmQM4Br351zhLOM2U` in `TASK_BOARD.md`. | **Done** |
| **`AC-38.4`** | `unit` | `tests/unit/test_documentation_parity.py::test_rule_catalog_parity` | Verifies all static and AST rule IDs documented in `docs/rules/catalog.md` match engine implementation constants 1-to-1. | **Done** |
| **`AC-38.5`** | `unit` | `tests/unit/test_documentation_parity.py::test_benign_control_docs` | Paired Benign Control: Verifies clean customer guides have zero stale `verity-core` references and benign placeholder configs scan with zero false positives. | **Done** |

<!-- synced-from: verityredteam-free/docs/tasks/M38_web_documentation_portal_and_task_publisher.md -->
