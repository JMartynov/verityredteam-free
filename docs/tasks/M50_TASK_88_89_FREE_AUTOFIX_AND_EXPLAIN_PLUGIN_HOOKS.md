---
task_id: M50
alias: TASK-88-89-FREE
title: "Free PRO_FEATURE_REQUIRED Plugin Hooks for --autofix and --explain"
status: Not Done
priority: Medium (P1)
size: S
estimate_days: 2
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhMEjTI
target_repos: [verityredteam-free]
---

# M50 (`TASK-88-89-FREE`): Free `PRO_FEATURE_REQUIRED` Plugin Hooks for `--autofix` and `--explain`

## Purpose & Architectural Decisions
- **Autofix Plugin Hook (`TASK-88` Free Side)**: Add `set_autofix_provider(provider)` on `VerityToolDispatcher`, expose `"synthesize_verified_patch"` in `verity_remediation_ops.inputSchema.properties.action.enum`, and wire `--autofix` CLI option handling so Free installations fail closed with `PRO_FEATURE_REQUIRED` (exit `2`) when `verity-pro` is absent, and delegate cleanly when registered.
- **Explain Plugin Hook (`TASK-89` Free Side)**: Expose `"explain_finding_context"` in `verity_remediation_ops.inputSchema.properties.action.enum` plus optional `--explain` CLI hook, failing closed with `PRO_FEATURE_REQUIRED` when `verity-pro` is absent and delegating when registered.
- **Strict Open-Core Isolation**: Zero `verity_lite` or `verity_pro` imports or LLM dependencies exist in `verityredteam-free`.

## Target Files
| File | Change |
| :--- | :--- |
| `src/verity/mcp_server/protocols.py` | Define `AutofixProviderProtocol` / `ExplainProviderProtocol` hooks |
| `src/verity/mcp_server/tools.py` | Add `set_autofix_provider(provider)` / `set_explain_provider(provider)` on `VerityToolDispatcher` |
| `src/verity/mcp_server/schemas.py` | Expose `synthesize_verified_patch` and `explain_finding_context` in `verity_remediation_ops` |
| `src/verity/mcp_server/handlers/remediation.py` | Fail closed with `PRO_FEATURE_REQUIRED` when Pro providers are unset; delegate when set |
| `src/verity/cli.py` | Gate `--autofix` / `--explain` with `PRO_FEATURE_REQUIRED` (exit `2`) when `verity-pro` is absent |
| `tests/unit/mcp_server/test_autofix_and_explain_hooks.py` | Paired Pro-absent `PRO_FEATURE_REQUIRED` and mock-provider delegation tests |

## ATDD Traceability Matrix
| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-50.1` | `VerityToolDispatcher.set_autofix_provider` and `synthesize_verified_patch` schema/gate return `PRO_FEATURE_REQUIRED` without `verity-pro`. | Registered mock provider delegates cleanly; free remediation actions remain unaffected. | `unit` | `tests/unit/mcp_server/test_autofix_and_explain_hooks.py::test_autofix_hook_and_gate` |
| `AC-50.2` | `explain_finding_context` returns `PRO_FEATURE_REQUIRED` without `verity-pro` and delegates when provider is registered. | Free `verity_remediation_ops` actions stay operational on the same instance. | `unit` | `tests/unit/mcp_server/test_autofix_and_explain_hooks.py::test_explain_hook_and_gate` |
| `AC-50.3` | CLI `--autofix` / `--explain` return `PRO_FEATURE_REQUIRED` (exit `2`) without `verity-pro`; zero Pro imports; ruff clean. | Standard `verity scan` without `--autofix`/`--explain` exits normally. | `ruff` | `uv run ruff check src tests` |
