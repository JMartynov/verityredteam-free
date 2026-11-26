---
task_id: M32
alias: TASK-81
title: "Official GitHub Action (verity-scan-action@v1) & Pre-Commit Hooks"
status: Not Done
priority: High (P0)
size: M
estimate_days: 3
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhLJPcI
target_repos: [verityredteam-free]
---

# M32 (`TASK-81`): Official GitHub Action (`verity-scan-action@v1`) & Pre-Commit Hooks

## Purpose & Architectural Decisions
- **Zero-Friction Pre-Commit Hooks**: Ship `.pre-commit-hooks.yaml` at repo root exposing `verity-scan`, `verity-scan-configs`, and `verity-scan-uvx` (all defaulting to `--offline` with `pass_filenames: true` multi-file routing).
- **CI Composite Action Alignment**: Ensure `README.md` documents `.pre-commit-config.yaml` and `JMartynov/verity-scan-action@v1` using pinned actions (`actions/checkout@v5`, `astral-sh/setup-uv@v6`, `actions/cache@v4`, `github/codeql-action/upload-sarif@v3`) with all CLI commands validated by `test_documentation_parity.py`.
- **Open-Core Isolation**: Private `verity-pro` capabilities are never bundled into pre-commit or Action defaults.

## Target Files
| File | Change |
| :--- | :--- |
| `.pre-commit-hooks.yaml` | Define `verity-scan`, `verity-scan-configs`, and `verity-scan-uvx` hooks |
| `README.md` | Document pre-commit and GitHub Action CI usage snippets |
| `tests/unit/test_precommit_hooks.py` | Validate hook schema, `--offline` defaults, and `build_parser()` flag compatibility |
| `tests/unit/test_documentation_parity.py` | Validate README YAML pre-commit & Action CLI snippets |

## ATDD Traceability Matrix
| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-32.1` | `.pre-commit-hooks.yaml` defines `verity-scan`, `verity-scan-configs`, `verity-scan-uvx` with `--offline`. | Missing required hook keys or invalid flags fail validation. | `unit` | `tests/unit/test_precommit_hooks.py::test_hooks_schema_and_flags` |
| `AC-32.2` | Multi-file staged runs (`pass_filenames: true` with `.py` + `.json`/`.yaml`) parse cleanly. | Invalid CLI flags exit non-zero. | `unit` | `tests/unit/test_precommit_hooks.py::test_staged_multi_file_invocation` |
| `AC-32.3` | README pre-commit and Action YAML snippets pass `build_parser()` and relative-link parity. | Invalid YAML `verity` command is rejected. | `unit` | `tests/unit/test_documentation_parity.py` |
| `AC-32.4` | Ruff linter and unit test suite pass with zero violations. | Clean code conforms to ruff rules. | `ruff` | `uv run ruff check src tests` |
