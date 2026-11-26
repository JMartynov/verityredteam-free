# Feature Realism & Product Alignment — Action Plan (M39–M45)

- **Repository scope:** `verityredteam-free` only.
- **Board:** [GitHub Project #5](https://github.com/users/JMartynov/projects/5) (`PVT_kwHOD-xmQM4Br351`).
- **Pro counterpart:** `verityredteam/docs/reports/FEATURE_REALISM_ACTION_PLAN_AND_TASKS.md`, tracked on GitHub Project Board #2 (`PVT_kwHOD-xmQM4BfzE2`).
- **Goal:** make the Free product read truthfully — real AST rules at dispatch time, honest Pro gating for SARIF and guard families, and documentation that leads with the customer core (Tier 1 / Tier 2) plus a single auxiliary pointer.

## Locked Free / Pro Boundary Decisions

1. **OASIS SARIF v2.1.0 stays a Pro capability.** `--format sarif` and the `export_sarif` action return `PRO_FEATURE_REQUIRED` with exit code `2` in Free whenever the `verity-pro` plugin is absent. They are `[Pro]`-badged in both the Free README and the Free docs; JSON, Markdown, and Table output remain fully Free and unbadged.
2. **NoSQL and volume guards are Pro-only.** `FilterSecurityGuard` (`validate_nosql_filter`) and `VolumePolicyGuard` (`enforce_volume_policy`) ship exclusively through the `verity-pro` plugin and return `PRO_FEATURE_REQUIRED` in Free, alongside `SnowflakeSecurityGuard`.
3. **Tier 1 / Tier 2 focus with one auxiliary pointer.** Both entrypoints surface only the 12 Tier 1 and 13 Tier 2 customer-facing capabilities, a single `Auxiliary & Benchmark Appendix (Tier 3/4)` pointer to `docs/reference/auxiliary_and_benchmarks.md`, and the dedicated `Verity Pro Enterprise Features` showcase (`docs/pro/enterprise_features.md` plus the README section).

## Task Matrix

| Key | Alias | Status | Priority | Size | Board Item | Task Spec | Free Deliverable |
| --- | --- | --- | --- | --- | --- | --- | --- |
| M39 | `TASK-102` | `Done` | P0 | S | `PVTI_lAHOD-xmQM4Br351zhLvl0M` | [M39 spec](../tasks/M39_TASK_102_PYTHON_AST_REAL_WORLD_RULES_AND_IMPORT_ALIASES.md) | Alias-aware `visit_Call` dispatch with real def-use CWE-22 / CWE-89 / CWE-862 rules in `src/verity/scanner/python_ast.py` (`4e6399a`, `650df12`). |
| M40 | `TASK-103-FREE` | `Done` | P0 | XS | `PVTI_lAHOD-xmQM4Br351zhLvmAQ` | [M40 spec](../tasks/M40_TASK_103_FREE_CLI_SARIF_PRO_GATE_AND_LINE_PRECISION.md) | `_pro_plugin_available()` gate for `--format sarif` and true `line_number` / `uri` propagation in `src/verity/cli.py`. |
| M41 | `TASK-104` | `Done` | P0 | S | `PVTI_lAHOD-xmQM4Br351zhLvmDo` | [M41 spec](../tasks/M41_TASK_104_HOMEPAGE_TIER1_2_FOCUS_AND_REGISTRY_PARITY.md) | Tier 1 / Tier 2 homepage with auxiliary appendix and runtime-registry parity checks. |
| M42 | `TASK-107` | `Done` | P0 | S | `PVTI_lAHOD-xmQM4Br351zhLvmsE` | [M42 spec](../tasks/M42_TASK_107_PRO_FEATURES_SHOWCASE_AND_COMPARISON_DOCS_IN_FREE.md) | `docs/pro/enterprise_features.md`, Free vs Pro matrix, and documented `PRO_FEATURE_REQUIRED` contract. |
| M43 | `TASK-109-FREE` | `Done` | P0 | XS | `PVTI_lAHOD-xmQM4Br351zhLvm_M` | [M43 spec](../tasks/M43_TASK_109_FREE_MCP_DATABASE_GUARD_PRO_GATING.md) | `PRO_FEATURE_REQUIRED` gate for `validate_nosql_filter` and `enforce_volume_policy` in the MCP database handler. |
| M44 | `TASK-106-FREE` | `Done` | P1 | S | `PVTI_lAHOD-xmQM4Br351zhLvmgk` | [M44 spec](../tasks/M44_TASK_106_FREE_READONLY_GUARD_AND_ROUTER_DECOUPLING.md) | Destructive-verb blocking in `readonly_guard.py` and formula de-hardcoding in `dual_path_router.py` (`bc8dbcb` / `99e3e70`). |
| M45 | `TASK-110-FREE` | `Done` | P0 | S | `PVTI_lAHOD-xmQM4Br351zhLvnMQ` | [M45 spec](../tasks/M45_TASK_110_FREE_README_TIER1_2_FOCUS_PRO_SHOWCASE_AND_PARITY.md) | README Tier 1 / Tier 2 focus, Pro showcase, and `[Pro]` badge parity checks. |

## Summary Status

- **Free Feature Realism (`M39`–`M45`, Board `#5`):** **7 / 7 (`100%`) `Implemented` / `Done`** (`M39`, `M40`, `M41`, `M42`, `M43`, `M44`, `M45`).

## Free-Only Execution Graph

~~~mermaid
flowchart TD
  classDef done fill:#e6f4ea,stroke:#1e8e3e,color:#137333

  subgraph Completed["Completed (7 / 7 — 100% Done)"]
    M39["M39 - TASK-102 - Python AST real-world rules [Done]"]:::done
    M40["M40 - TASK-103-FREE - CLI SARIF Pro gate [Done]"]:::done
    M41["M41 - TASK-104 - Homepage Tier 1/2 focus [Done]"]:::done
    M42["M42 - TASK-107 - Pro showcase and comparison [Done]"]:::done
    M43["M43 - TASK-109-FREE - MCP DB guard gating [Done]"]:::done
    M44["M44 - TASK-106-FREE - Read-only guard decoupling [Done]"]:::done
    M45["M45 - TASK-110-FREE - README Tier 1/2 focus [Done]"]:::done
  end

  M41 --> M42
  M42 --> M45
  M41 --> M45

  M39 --> M43
  M40 --> M43
  M43 --> M44
~~~

## Execution Notes

- **Wave 1 (Done):** M39 (`TASK-102`, commits `4e6399a` / `650df12`) and M40 (`TASK-103-FREE`) are both `Done` (**7 / 7 (`100%`)** Free tasks `Implemented` / `Done`).
- **Wave 2 (Done):** M43 consumes the `PRO_FEATURE_REQUIRED` pattern established by M40.
- **Wave 3 (Done):** M44 (`bc8dbcb` / `99e3e70`) hardens `ReadOnlySafetyGuard` and decouples `DualPathRouter` from hardcoded demo payloads.
- **Completed track:** M41 (homepage parity) → M42 (Pro showcase) → M45 (README parity), with M41 → M45 as the direct fallback link.
