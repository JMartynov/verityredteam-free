---
task_id: M30
alias: TASK-79
title: "uvx Single-Token Execution & Homebrew Distribution"
status: Done
priority: High (P0)
size: S
estimate_days: 2
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhLJPUU
target_repos: [verityredteam-free]
---

# M30 (`TASK-79`): `uvx` Single-Token Execution & Homebrew Distribution

## Purpose & Architectural Decisions
- **Sub-10s Time-to-First-Value**: Register both `verity` and `verity-redteam-core` under `[project.scripts]` in `pyproject.toml` so `uvx verity-redteam-core scan` works as a single-token invocation without `--from`.
- **CLI Version & Metadata**: Expose `-V` / `--version` on the root parser (`verity <__version__>`, exit `0`) and populate `[project.urls]` (`Homepage`, `Repository`, `Documentation`, `Issues`).
- **Deterministic Homebrew Tap**: Generate `Formula/verity.rb` (`Language::Python::Virtualenv`, `depends_on "libyaml"`, `depends_on "python@3.13"`) via a pure deterministic script and automate publishing to `JMartynov/homebrew-tap` on PyPI release.
- **Zero-LLM Boundary**: Packaging, version reporting, formula generation, and tap publishing are 100% deterministic.

## Target Files
| File | Change |
| :--- | :--- |
| `pyproject.toml` | Dual `[project.scripts]` (`verity`, `verity-redteam-core`) and `[project.urls]` |
| `src/verity/cli.py` | Root `-V` / `--version` flag outputting `verity <__version__>` |
| `README.md` | Document `uvx verity-redteam-core scan` and `brew install JMartynov/tap/verity` |
| `scripts/generate_homebrew_formula.py` | Deterministic PyPI sdist + SHA-256 Homebrew formula renderer |
| `.github/workflows/homebrew-tap.yml` | Release workflow updating `JMartynov/homebrew-tap` |
| `tests/unit/test_cli_version_and_packaging.py` | Packaging, entrypoint, and `-V`/`--version` parity tests |

## ATDD Traceability Matrix
| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-30.1` | `pyproject.toml` declares `verity` and `verity-redteam-core` scripts plus `[project.urls]`. | Unknown script alias is absent. | `unit` | `tests/unit/test_cli_version_and_packaging.py::test_pyproject_entrypoints_and_urls` |
| `AC-30.2` | `verity --version` and `verity -V` print `verity <__version__>` and exit `0`. | Unknown `--invalid-version-flag` exits `2`. | `unit` | `tests/unit/test_cli_version_and_packaging.py::test_cli_version_flags` |
| `AC-30.3` | `scripts/generate_homebrew_formula.py` renders deterministic `Formula/verity.rb`. | Invalid/missing version or SHA fails cleanly. | `unit` | `tests/unit/test_homebrew_formula_generator.py` |
| `AC-30.4` | `.github/workflows/homebrew-tap.yml` uses `actions/checkout@v5` and `astral-sh/setup-uv@v6`. | Floating `@main` refs fail hygiene check. | `unit` | `tests/unit/test_workflow_hygiene.py` |
| `AC-30.5` | Ruff linter and unit test suite pass with zero violations. | Clean code conforms to ruff rules. | `ruff` | `uv run ruff check src tests` |
