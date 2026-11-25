---
task_id: M45
alias: TASK-110-FREE
title: "Free README Tier 1/2 Focus, Pro Showcase & Parity"
status: Done
priority: P0
size: S
estimate_days: 1
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhLvnMQ
target_repos: [verityredteam-free]
---


## Context & Objectives

The README is the first page a customer reads. It must present the twelve Tier 1 and
thirteen Tier 2 capabilities a Free customer installs, summarise the Pro edition without
misrepresenting it, and keep every rule ID, demo slug, and MCP tool name honest against
the runtime registries.

This task delivered that README and is complete.

## Scope

| File | Change |
| --- | --- |
| `README.md` | Tier 1/2 focus, Pro showcase, parity-clean identifiers |
| `tests/unit/test_readme_parity.py` | Parity, Pro showcase, and paired benign-control tests |

Out of scope: documentation portal pages and any runtime code change.

## Contract

### Tier focus

- `## Tier 1 — Must-Have Product Core` contains exactly 12 data rows.
- `## Tier 2 — High Customer Need` contains exactly 13 data rows.
- No `## Tier 3` or `## Tier 4` heading exists in the README.
- Exactly one auxiliary link is present, labelled
  `Auxiliary & Benchmark Appendix (Tier 3/4)`, pointing at the appendix and placed after
  the Tier 2 section.

### Pro showcase

- `## Verity Pro Enterprise Features` contains the four-domain matrix with the header
  `| Capability Domain | Verity RedTeam Free (Apache-2.0) | Verity RedTeam Pro (Commercial) |`.
- Each Pro cell carries `[Pro]`.
- Six feature subsections exist (`SnowflakeSecurityGuard`, `FilterSecurityGuard`,
  `VolumePolicyGuard`, `OASIS SARIF v2.1.0 & Compliance Bundles`,
  `Pro verity_remediation_ops`, `Multi-Turn Socratic Red-Teaming`), each with a Python
  usage-only snippet, a bash or JSON snippet, and a Mermaid diagram, and no Pro class
  definition.
- A link to `docs/pro/enterprise_features.md` is present in the Pro section, which sits
  after Tier 2 and before the appendix link.

### Edition and parity guarantees

- `--format sarif` carries a `[Pro]` badge and the section states
  `PRO_FEATURE_REQUIRED` and exit code `2`.
- `terminal`, `json`, `markdown`, and `html` carry no `[Pro]` badge.
- Every README `VERITY-STATIC-*` and `VERITY-AST-*` token resolves in the live
  registries.
- Every fenced demo slug resolves in `TARGET_SLUGS`; `postgres-basic` present,
  `postgres-multitenant` absent.
- Only the four canonical MCP tool names appear as `verity_*` tokens.

## ATDD Traceability Matrix

| Acceptance Criterion | Test Level | Target File / Function | Description | Status |
| --- | --- | --- | --- | --- |
| AC-45.1 | unit | `tests/unit/test_readme_parity.py::test_readme_tier1_tier2_focus` | 12 Tier 1 rows, 13 Tier 2 rows, no Tier 3/4 heading, one auxiliary link. | Done |
| AC-45.2 | unit | `tests/unit/test_readme_parity.py::test_readme_rule_id_parity` | README rule IDs resolve in the live registries. | Done |
| AC-45.3 | unit | `tests/unit/test_readme_parity.py::test_readme_target_slug_parity` | Demo slugs resolve in `TARGET_SLUGS`; `postgres-multitenant` absent. | Done |
| AC-45.4 | unit | `tests/unit/test_readme_parity.py::test_readme_mcp_tool_names_parity` | Only the four canonical `verity_*` tool names appear. | Done |
| AC-45.5 | unit | `tests/unit/test_readme_parity.py::test_readme_sarif_pro_badge` | `[Pro]` badge plus `PRO_FEATURE_REQUIRED` / exit code `2`; Free formats unbadged. | Done |
| AC-45.6 | unit | `tests/unit/test_readme_parity.py::test_readme_pro_section_matrix_and_link` | Four-domain matrix with `[Pro]` cells and the Pro docs link, correctly positioned. | Done |
| AC-45.7 | unit | `tests/unit/test_readme_parity.py::test_readme_pro_feature_subsections` | Six H3 subsections each have Python, bash/JSON, and Mermaid blocks with no Pro class defs. | Done |
| AC-45.8 | static | `uv run ruff check src tests` | Zero lint findings. | Done |

## Verification Evidence

~~~bash
uv run pytest tests/unit/test_readme_parity.py -q
uv run ruff check src tests
~~~

Both commands passed on the delivered branch.

## Delivery Checklist

- [x] Tier 1 table has exactly 12 rows.
- [x] Tier 2 table has exactly 13 rows.
- [x] No Tier 3 or Tier 4 heading.
- [x] Single auxiliary link after Tier 2.
- [x] Rule IDs, demo slugs, and MCP tool names match runtime registries.
- [x] `[Pro]` SARIF badge with `PRO_FEATURE_REQUIRED` (exit code 2).
- [x] Pro section renders the four-domain matrix and links the Pro guide.
- [x] Six Pro feature subsections with Python, bash/JSON, and Mermaid blocks.
- [x] Paired controls committed; lint clean.
