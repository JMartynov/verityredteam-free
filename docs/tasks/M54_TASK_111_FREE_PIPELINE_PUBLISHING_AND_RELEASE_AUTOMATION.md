---
task_id: M54
alias: TASK-111-FREE
title: "GitHub Pipeline Publishing, Homebrew Tap, GitHub Releases & Upstream Sync Automation"
status: Not Done
priority: High (P0)
size: M
estimate_days: 3
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhMX-Sc
target_repos: [verityredteam-free]
source_research:
  - docs/reports/GITHUB_PIPELINES_AND_TEST_SUITE_AUDIT.md
---

# M54 (`TASK-111-FREE`): GitHub Pipeline Publishing, Homebrew Tap, GitHub Releases & Upstream Sync Automation

## 1. Purpose & Architectural Decisions
- **Reliable End-to-End Release Publishing**: Fix `.github/workflows/homebrew-tap.yml` failures observed in run `45914244097` (missing `HOMEBREW_TAP_TOKEN` secret preflight, `"main"` branch version fallback when `Publish to PyPI` runs via `workflow_dispatch`, missing `--from-lock`, and missing `ruby -c` syntax validation).
- **Complete GitHub Release Artifacts & Post-Publish PyPI E2E**: Expand `.github/workflows/workflow.yaml` on `v*` tag pushes to create/update a GitHub Release attaching the built wheel, sdist, and `SHA256SUMS.txt`, and trigger `e2e-containers.yml` with `INSTALL_SOURCE=pypi` after PyPI upload succeeds.
- **Automated Upstream Catalog Synchronization**: Add `.github/workflows/upstream-sync.yml` (`repository_dispatch` types `[upstream_fingerprints_updated, upstream_vulnerabilities_updated]` + weekly cron + `workflow_dispatch`) to upgrade `mcp-fingerprints` and `mcp-vulnerabilities` in `uv.lock`, refresh packaged offline snapshots in `src/verity/data/`, run full verification gates, and open/update an automated PR.
- **Free/Open-Core Boundary**: All deliverables are pure Open-Core CI/CD automation in `verityredteam-free` with zero Pro dependencies.

## 2. Target Files
| File | Change |
| :--- | :--- |
| `.github/workflows/homebrew-tap.yml` | Fallback version resolution (`head_branch == "main"` -> `pyproject.toml` / latest `v*` tag), pass `--from-lock`, run `ruby -c` + optional formula check, add explicit `HOMEBREW_TAP_TOKEN` preflight check |
| `.github/workflows/workflow.yaml` | Create/update GitHub Release on `v*` tags with `.whl`, `.tar.gz`, and `SHA256SUMS.txt`; trigger `e2e-containers.yml` post-publish verification |
| `.github/workflows/e2e-containers.yml` | Accept `workflow_dispatch` input `install_source` (`wheel` \| `pypi`) / `workflow_call` for post-publish `INSTALL_SOURCE=pypi` verification |
| `.github/workflows/upstream-sync.yml` | New workflow (`repository_dispatch`, weekly cron, `workflow_dispatch`) to bump upstream deps in `uv.lock`, refresh `src/verity/data/*.json.gz`, run gates, and open/update PR |
| `tests/unit/test_workflow_hygiene.py` | Unit tests verifying `homebrew-tap.yml` fallback/preflight, `workflow.yaml` release artifact & `permissions`, and `upstream-sync.yml` action pins & triggers |

## 3. ATDD Traceability Matrix

| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-54.1` | `homebrew-tap.yml` resolves version from `pyproject.toml` / latest `v*` tag when `workflow_run.head_branch == "main"`, passes `--from-lock`, validates `ruby -c`, and fails fast with a clear diagnostic message if `HOMEBREW_TAP_TOKEN` is unset. | Missing `HOMEBREW_TAP_TOKEN` emits an explicit remediation error instead of failing opaque `actions/checkout` token input; valid tag `v0.2.2` resolves `0.2.2`. | `unit` | `tests/unit/test_workflow_hygiene.py::test_homebrew_tap_fallback_and_preflight_contract` |
| `AC-54.2` | `workflow.yaml` creates/updates a GitHub Release on `v*` tag pushes with wheel, sdist, and `SHA256SUMS.txt`, preserving `skip-existing` duplicate-upload protections and triggering post-publish `INSTALL_SOURCE=pypi` verification. | `workflow_dispatch` without a `v*` tag does not attempt to publish a tag release or duplicate PyPI upload. | `unit` | `tests/unit/test_workflow_hygiene.py::test_workflow_release_artifacts_and_pypi_e2e` |
| `AC-54.3` | `.github/workflows/upstream-sync.yml` declares `repository_dispatch` (`upstream_fingerprints_updated`, `upstream_vulnerabilities_updated`), weekly `schedule`, and `workflow_dispatch`, uses `actions/checkout@v5` + `astral-sh/setup-uv@v6`, runs `ruff` + `pytest` gates, and opens/updates a PR. | No floating `@main`/`@master` action refs and `permissions` scoped cleanly (`contents: write`, `pull-requests: write`). | `unit` | `tests/unit/test_workflow_hygiene.py::test_upstream_sync_workflow_contract` |
| `AC-54.4` | Ruff linter, documentation parity, and full unit test suite pass cleanly. | Clean workspace yields zero lint or parity errors. | `ruff` | `uv run ruff check src tests scripts && uv run pytest tests/` |

## 4. Verification Commands
```bash
uv run pytest tests/unit/test_workflow_hygiene.py tests/unit/test_homebrew_formula_generator.py
uv run pytest tests/
uv run ruff check src tests scripts
```

## 5. Execution Checklist
- [ ] `AC-54.1` verified green (test locked during Pass 1)
- [ ] `AC-54.2` verified green
- [ ] `AC-54.3` verified green
- [ ] `AC-54.4` verified green
- [ ] Board #5 item `PVTI_lAHOD-xmQM4Br351zhMX-Sc` synced & status updated
