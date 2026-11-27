---
task_id: M55
alias: TASK-112-FREE
title: "CI Workflow Hygiene, Dynamic E2E Container Version Parity & Static Security Gates"
status: Not Done
priority: High (P0)
size: S
estimate_days: 2
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhMX-Wo
target_repos: [verityredteam-free]
source_research:
  - docs/reports/GITHUB_PIPELINES_AND_TEST_SUITE_AUDIT.md
---

# M55 (`TASK-112-FREE`): CI Workflow Hygiene, Dynamic E2E Container Version Parity & Static Security Gates

## 1. Purpose & Architectural Decisions
- **Dynamic Workflow Hygiene Discovery**: `tests/unit/test_workflow_hygiene.py` currently hardcodes 5 workflows in `ALL_WORKFLOW_PATHS`, omitting `.github/workflows/pages.yml` and any newly added workflows (such as `upstream-sync.yml`). Discover all `.yml`/`.yaml` files under `.github/workflows/` dynamically so action pins (`actions/checkout@v5`, `astral-sh/setup-uv@v6`), `permissions`, and duplicate-upload guards cover 100% of repo workflows.
- **Eliminate Hardcoded `"0.2.2"` Version Strings**: Replace hardcoded `"0.2.2"` in `tests/e2e_containers/Dockerfile.customer-pip`, `Dockerfile.customer-uvx`, `Dockerfile.customer-workstation`, `tests/e2e_containers/verify_all_scenarios.sh`, and `tests/unit/test_cli_auditor_parity.py` with dynamic resolution from `pyproject.toml` / `verity.__version__` and `--build-arg VERITY_VERSION=...` in `tests/e2e_containers/run_e2e.sh`.
- **Tighten PR CI & Lint Gates**: Expand `ruff check src tests` to `ruff check src tests scripts` in `ci.yml` and `full-tests.yml`, and run `uv run python scripts/build_docs_portal.py --check` in `ci.yml` on PRs so documentation portal drift is caught before merging to `main`.

## 2. Target Files
| File | Change |
| :--- | :--- |
| `tests/unit/test_workflow_hygiene.py` | Dynamically populate `ALL_WORKFLOW_PATHS` from `.github/workflows/*.{yml,yaml}` and enforce pin, permission, and duplicate-upload invariants |
| `tests/e2e_containers/run_e2e.sh` | Read `VERITY_VERSION` from `pyproject.toml` and pass `--build-arg VERITY_VERSION="$VERITY_VERSION"` + `-e VERITY_VERSION="$VERITY_VERSION"` to Compose |
| `tests/e2e_containers/docker-compose.verify.yml` | Forward `VERITY_VERSION` build arg and environment variable to customer containers |
| `tests/e2e_containers/Dockerfile.customer-pip` | Replace hardcoded `0.2.2` with `ARG VERITY_VERSION` |
| `tests/e2e_containers/Dockerfile.customer-uvx` | Replace hardcoded `0.2.2` with `ARG VERITY_VERSION` / `ENV VERITY_VERSION` |
| `tests/e2e_containers/Dockerfile.customer-workstation` | Replace hardcoded `0.2.2` with `ARG VERITY_VERSION` |
| `tests/e2e_containers/verify_all_scenarios.sh` | Compare `pip show verity-redteam-core` against dynamic `$VERITY_VERSION` (defaulting from `verity.__version__`) |
| `tests/unit/test_cli_auditor_parity.py` | Replace `assert verity.__version__ == "0.2.2"` with dynamic comparison against `pyproject.toml`'s `[project].version` |
| `.github/workflows/ci.yml` | Run `ruff check src tests scripts` and `uv run python scripts/build_docs_portal.py --check` |
| `.github/workflows/full-tests.yml` | Run `ruff check src tests scripts` |

## 3. ATDD Traceability Matrix

| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-55.1` | `tests/unit/test_workflow_hygiene.py` dynamically discovers all `.github/workflows/*.{yml,yaml}` files (including `pages.yml` and `upstream-sync.yml`) and validates action pins (`checkout@v5`, `setup-uv@v6`), permissions, and duplicate-upload guards. | Adding an unpinned `checkout@v4` workflow fixture fails validation; valid repo workflows pass. | `unit` | `tests/unit/test_workflow_hygiene.py::test_all_workflows_dynamically_discovered_and_pinned` |
| `AC-55.2` | Zero hardcoded package version literals remain in `tests/e2e_containers/` or `tests/unit/test_cli_auditor_parity.py`; `verity.__version__` matches `pyproject.toml` and `run_e2e.sh` passes `VERITY_VERSION`. | Simulated version bump in a temporary `pyproject.toml` / env var propagates cleanly without hardcode failures. | `unit` | `tests/unit/test_cli_auditor_parity.py::test_package_version_matches_pyproject` |
| `AC-55.3` | `ci.yml` and `full-tests.yml` lint `src tests scripts` and `ci.yml` executes `scripts/build_docs_portal.py --check` on PRs. | Clean `src`, `tests`, `scripts`, and generated portal docs exit `0`. | `unit` | `tests/unit/test_workflow_hygiene.py::test_ci_lints_scripts_and_checks_portal` |
| `AC-55.4` | Ruff linter (`src tests scripts`), documentation parity, and full unit test suite pass cleanly. | — | `ruff` | `uv run ruff check src tests scripts && uv run pytest tests/` |

## 4. Verification Commands
```bash
uv run pytest tests/unit/test_workflow_hygiene.py tests/unit/test_cli_auditor_parity.py tests/unit/test_documentation_parity.py
uv run pytest tests/
uv run ruff check src tests scripts
```

## 5. Execution Checklist
- [ ] `AC-55.1` verified green (test locked during Pass 1)
- [ ] `AC-55.2` verified green
- [ ] `AC-55.3` verified green
- [ ] `AC-55.4` verified green
- [ ] Board #5 item `PVTI_lAHOD-xmQM4Br351zhMX-Wo` synced & status updated
