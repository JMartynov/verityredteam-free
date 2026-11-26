---
task_id: M49
alias: TASK-87-FREE
title: "Opt-In --llm-assist Semantic Alignment Analyzer on UCP Path B"
status: Partially Done
priority: Medium (P1)
size: M
estimate_days: 3
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhMEjOY
target_repos: [verityredteam-free]
---

# M49 (`TASK-87-FREE`): Opt-In `--llm-assist` Semantic Alignment Analyzer on UCP Path B

## Status Note (`Partially Done`)
- **Already Done (in `M39` / `TASK-102`)**: `src/verity/scanner/python_ast.py` already implements `visit_AsyncFunctionDef` (`@mcp.tool` async handlers) and real `CWE-22` / `CWE-89` / `CWE-862` AST def-use heuristics.
- **Remaining in M49**: Wire `DualPathRouter.route_server(...)` into `ConsolidatedSecurityAuditor.audit_server(..., live_probe=True)`, fix `TEMPLATE_INDICATORS` in `src/verity/scanner/static_rules.py`, add pure-stdlib `src/verity/scanner/semantic_assist.py`, and expose `--llm-assist` CLI flags.

## Purpose & Architectural Decisions
- **100% Deterministic Default**: Without `--llm-assist`, `verity scan` performs zero HTTP/LLM calls and keeps 100% deterministic offline output and exit codes.
- **Anti-Hallucination & Prompt Hygiene**: When `--llm-assist` is explicitly passed, `SemanticAssistClient` pre-sanitizes all `ToolSemanticCheckInput` fields via `MetadataNormalizer.sanitize_text` and enforces exact substring verification on `SemanticFindingDraft.evidence_span` (discarding fabricated findings).
- **Zero Extra AI SDK Dependencies**: Support `ollama`, `deepseek`, `openai`, `anthropic`, and `gemini` via pure Python stdlib (`urllib.request`) emitting `VERITY-SEMANTIC-ASSIST-ADVISORY`.

## Target Files
| File | Change |
| :--- | :--- |
| `src/verity/discovery/auditor.py` | Wire `DualPathRouter.route_server(...)` when `live_cap.tools` is non-empty |
| `src/verity/scanner/static_rules.py` | Fix `TEMPLATE_INDICATORS` pattern accuracy |
| `src/verity/scanner/semantic_assist.py` | New pure-stdlib `SemanticAssistClient` with exact `evidence_span` verification |
| `src/verity/cli.py` | Expose `--llm-assist` (and provider/model options) on `verity scan` |
| `tests/unit/scanner/test_semantic_assist.py` | Zero-network default, sanitization, substring verification & provider tests |

## ATDD Traceability Matrix
| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-49.1` | `ConsolidatedSecurityAuditor.audit_server(..., live_probe=True)` routes non-empty `live_cap.tools` through `DualPathRouter`. | Empty tool list skips UCP plan generation cleanly. | `unit` | `tests/unit/test_auditor_dual_path.py` |
| `AC-49.2` | Without `--llm-assist`, `verity scan` executes zero HTTP/LLM requests. | Monkeypatched `urllib.request.urlopen` is never called. | `unit` | `tests/unit/scanner/test_semantic_assist.py::test_zero_network_by_default` |
| `AC-49.3` | `SemanticAssistClient` sanitizes inputs and discards drafts whose `evidence_span` is not an exact substring. | Valid evidence span emits `VERITY-SEMANTIC-ASSIST-ADVISORY`. | `unit` | `tests/unit/scanner/test_semantic_assist.py::test_evidence_span_guard` |
| `AC-49.4` | Mocked `ollama`/`deepseek`/`openai`/`anthropic`/`gemini` responses parse cleanly with 0 new dependencies in `pyproject.toml`; ruff clean. | Malformed LLM payload degrades safely without crash. | `ruff` | `uv run ruff check src tests` |
