---
task_id: M33
alias: TASK-90
title: "TypeScript / JavaScript MCP SAST Scanner"
status: Not Done
priority: High (P0)
size: M
estimate_days: 4
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhLJPfA
target_repos: [verityredteam-free]
---

# M33 (`TASK-90`): TypeScript / JavaScript MCP SAST Scanner

## Purpose & Architectural Decisions
- **Polyglot MCP Coverage**: Extend `McpAstScannerEngine.scan_path()` to discover `.ts`, `.tsx`, `.js`, and `.mjs` files (skipping `node_modules`, `dist`, `build`, `.git`) and reuse `mcp_fingerprints.ast_parser` (`parse_typescript_mcp_ast`) for tool schema extraction into `StaticRuleEvaluator` and `UnknownCapabilityProfiler`.
- **Deterministic TS/JS Sink Rules**: Add `src/verity/scanner/typescript_ast.py` with 5 deterministic `VERITY-AST-TS-*` rules (`VERITY-AST-TS-CWE-94-EVAL`, `VERITY-AST-TS-CWE-94-VM`, `VERITY-AST-TS-CWE-78-EXEC`, `VERITY-AST-TS-CWE-22-FS`, `VERITY-AST-TS-CWE-89-SQLI`) with exact line numbers and paired hardened controls.
- **Zero New Dependencies**: Build on existing `mcp-fingerprints` tree-sitter/AST support with 0% LLM involvement.

## Target Files
| File | Change |
| :--- | :--- |
| `src/verity/scanner/engine.py` | Multi-language file discovery (`.py`, `.ts`, `.tsx`, `.js`, `.mjs`) and TS/JS dispatch |
| `src/verity/scanner/typescript_ast.py` | New TS/JS MCP schema extractor & 5 `VERITY-AST-TS-*` sink rules |
| `src/verity/scanner/rules.py` | Register 5 `VERITY-AST-TS-*` rule metadata entries |
| `src/verity/scanner/models.py` | Support TS/JS findings cleanly across report formats |
| `src/verity/cli.py` | Surface TS/JS schema & sink findings in `verity scan --path` |
| `tests/unit/scanner/test_typescript_ast.py` | Paired vulnerable/hardened controls for all 5 TS/JS sink rules |

## ATDD Traceability Matrix
| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-33.1` | `McpAstScannerEngine.scan_path()` discovers `.ts`/`.tsx`/`.js`/`.mjs` while skipping `node_modules`/`dist`/`build`. | Non-code assets and ignored build dirs are skipped. | `unit` | `tests/unit/scanner/test_typescript_ast.py::test_ts_js_file_discovery` |
| `AC-33.2` | TS/JS MCP tool schemas feed `StaticRuleEvaluator` and UCP profiling. | Clean TS/JS MCP server yields 0 static poisoning findings. | `unit` | `tests/unit/scanner/test_typescript_ast.py::test_ts_schema_extraction` |
| `AC-33.3` | `VERITY-AST-TS-CWE-94-EVAL` and `VERITY-AST-TS-CWE-94-VM` detect `eval`/`new Function` and `vm.runInNewContext`. | `JSON.parse` / safe math expression produces 0 findings. | `unit` | `tests/unit/scanner/test_typescript_ast.py::test_ts_eval_and_vm_sinks` |
| `AC-33.4` | `VERITY-AST-TS-CWE-78-EXEC`, `CWE-22-FS`, `CWE-89-SQLI` detect `exec`, uncontained `fs.*`, and SQL template interpolation. | Hardened `execFile`, `path.resolve` containment, and parameterized SQL yield 0 findings. | `unit` | `tests/unit/scanner/test_typescript_ast.py::test_ts_exec_fs_sqli_sinks` |
| `AC-33.5` | `verity scan --path <ts_repo> --fail-on-findings` exits `1` on vulnerable TS repo and `0` on clean repo; ruff clean. | Clean TS repo exits `0`. | `ruff` | `uv run ruff check src tests` |
