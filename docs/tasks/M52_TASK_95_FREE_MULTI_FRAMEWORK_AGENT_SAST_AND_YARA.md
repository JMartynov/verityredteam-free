---
task_id: M52
alias: TASK-95-FREE
title: "Multi-Framework Agent SAST (LangChain/CrewAI/AutoGen) & Optional YARA Engine"
status: Not Done
priority: Medium (P1)
size: L
estimate_days: 5
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhMEjcE
target_repos: [verityredteam-free]
---

# M52 (`TASK-95-FREE`): Multi-Framework Agent SAST (LangChain/CrewAI/AutoGen) & Optional YARA Engine

## Purpose & Architectural Decisions
- **Multi-Framework Agent AST Visitors**: Add deterministic Python AST visitors for LangChain (`langchain_ast.py`), CrewAI (`crewai_ast.py`), and AutoGen (`autogen_ast.py`) extracting agent/tool declarations and detecting unsafe shell/eval/deserialization sinks, wired into `McpAstScannerEngine`.
- **Optional YARA Signature Engine**: Add `src/verity/scanner/yara_engine.py` supporting custom YARA rule packs when `yara-python` is installed and degrading gracefully (no-op with explicit status) when `yara-python` is absent — keeping `pyproject.toml` core dependencies zero-bloat.

## Target Files
| File | Change |
| :--- | :--- |
| `src/verity/scanner/langchain_ast.py` | LangChain `@tool` / `Tool` / `StructuredTool` AST visitor & sink checks |
| `src/verity/scanner/crewai_ast.py` | CrewAI `Agent` / `@tool` AST visitor & sink checks |
| `src/verity/scanner/autogen_ast.py` | AutoGen `register_for_execution` / `ConversableAgent` AST visitor & sink checks |
| `src/verity/scanner/yara_engine.py` | Optional `yara-python` signature scanner with graceful absence fallback |
| `src/verity/scanner/engine.py` | Dispatch multi-framework AST visitors and optional YARA rules |
| `tests/unit/scanner/test_multi_framework_and_yara.py` | Paired vulnerable/clean controls for LangChain, CrewAI, AutoGen & YARA |

## ATDD Traceability Matrix
| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-52.1` | LangChain AST visitor extracts tools and flags dangerous sinks. | Clean LangChain tool with validated args produces 0 findings. | `unit` | `tests/unit/scanner/test_multi_framework_and_yara.py::test_langchain_ast` |
| `AC-52.2` | CrewAI and AutoGen AST visitors extract agent tools and flag dangerous sinks. | Clean agent definitions without shell/eval yield 0 findings. | `unit` | `tests/unit/scanner/test_multi_framework_and_yara.py::test_crewai_and_autogen_ast` |
| `AC-52.3` | Optional YARA engine matches signatures when `yara-python` is present and degrades gracefully when absent. | Benign files matching no YARA rules yield 0 findings. | `unit` | `tests/unit/scanner/test_multi_framework_and_yara.py::test_yara_engine_and_fallback` |
| `AC-52.4` | Ruff linter and unit test suite pass with zero violations. | Clean code conforms to ruff rules. | `ruff` | `uv run ruff check src tests` |
