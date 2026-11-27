# GitHub Pipelines & Test Suite Ecosystem Audit

> **Scope**: Canonical audit of GitHub Actions workflows, publishing destinations, test suites, execution timings, local-vs-CI gaps, and live run diagnostics for Open-Core `verityredteam-free`, `JMartynov/homebrew-tap`, and upstream public catalog dependencies (`mcp-fingerprints`, `mcp-vulnerabilities`), plus high-level downstream ecosystem integration (audited 2026-11-27).

---

## 1. Executive Summary & Live Health Matrix

| Repository | Workflows | Live CI Status (2026-11-27) | Publishing Destinations | Primary Gaps / Failures |
| :--- | :---: | :--- | :--- | :--- |
| **`verityredteam-free`** | 6 | 5 passing (`CI`, `Deploy Documentation Portal`, `e2e-containers`, `Full Test Suite`, `Publish to PyPI` on `v0.2.2`); **1 failing** (`Update Homebrew Tap` run `45914244097`) | PyPI (`verity-redteam-core`), GitHub Pages (`mike`), `JMartynov/homebrew-tap` (`Formula/verity.rb`), GitHub Releases (`v0.2.2`) | `HOMEBREW_TAP_TOKEN` unset; `workflow_dispatch` version fallback bug in `homebrew-tap.yml`; `workflow.yaml` creates no GitHub Release assets; hardcoded `0.2.2` in E2E Dockerfiles & parity test; missing `upstream-sync.yml`; `pages.yml` omitted from `test_workflow_hygiene.py`. Tracked in `M54`, `M55`. |
| **`homebrew-tap`** | 0 | N/A (`Formula/verity.rb`, 5,814 B) | Homebrew (`brew install JMartynov/tap/verity`) | Automated formula updates blocked by missing `HOMEBREW_TAP_TOKEN` in `verityredteam-free`. Tracked in `M54`. |
| **`mcp-fingerprints`** | 5 | `e2e.yml`, `deploy_pages.yml`, `release.yml` passing; **`Daily MCP Fingerprint & Passport Sync` failing since Nov 24** (run `45983774823`) | PyPI (`mcp-fingerprints`), GitHub Pages, GitHub Releases (`passports.json.gz`), TestPyPI | `web/catalog.json` reached `101.30 MB` (>100 MB GitHub push limit), halting daily passport commits, releases & downstream dispatch; `REPO_DISPATCH_PAT` unset + mismatched payload keys; no `ruff check` gate in `e2e.yml`. |
| **`mcp-vulnerabilities`** | 11 | All 11 workflows green on 2026-11-27 (`CI` `45982907610`, `Cross-Repo Synchronization` `45983001123`) | PyPI (`mcp-vulnerabilities`), GHCR, GitHub Pages, GitHub Releases (`v*` + `snapshot-*`), Sigstore | `v*` GitHub Releases (`v1.7.44`) attach zero assets (`assets: []`); `sign_release.yml` dispatch omits `--ref`; `cross_repo_sync.yml` cron (`0 4 * * *`) collides with `mcp-fingerprints`; no downstream dispatch to `verityredteam-free`. |
| **Downstream Pro Plugin Ecosystem** | 2 | Integration regression observed | Private plugin CI layered on `verity-redteam-core` | Downstream CI uses `pip` instead of `uv` workspace resolution, pulling stale PyPI wheels instead of latest `verity-redteam-core` symbols. Tracked in downstream project board. |

---

## 2. Workflow, Artifact, Trigger & Secret Inventory

### 2.1 `JMartynov/verityredteam-free`

| Workflow File | Name | Triggers | Permissions & Secrets | Published Artifacts / Destinations |
| :--- | :--- | :--- | :--- | :--- |
| `.github/workflows/ci.yml` | `CI` | `push` (`main`), `pull_request` (`main`) | Default (`GITHUB_TOKEN`); LLM keys blanked (`""`) | None (PR/push validation gate) |
| `.github/workflows/full-tests.yml` | `Full Test Suite` | `workflow_call`, `workflow_dispatch`, `schedule` (`0 3 * * *`) | Default; LLM keys blanked | Builds wheel & sdist locally in job (not uploaded) |
| `.github/workflows/workflow.yaml` | `Publish to PyPI` | `push.tags: ["v*"]`, `workflow_dispatch` | `id-token: write`, `contents: read`; `environment: pypi` | PyPI package `verity-redteam-core` via OIDC Trusted Publishing (`pypa/gh-action-pypi-publish@release/v1`) |
| `.github/workflows/homebrew-tap.yml` | `Update Homebrew Tap` | `workflow_run` (`Publish to PyPI` completed), `workflow_dispatch` (`version`) | `contents: read`; requires **`secrets.HOMEBREW_TAP_TOKEN`** (unset) | Commits `Formula/verity.rb` to `JMartynov/homebrew-tap` |
| `.github/workflows/e2e-containers.yml` | `e2e-containers` | `workflow_dispatch`, `schedule` (`0 4 * * *`), `push.tags: ["v*"]`, `pull_request` (`src/**`, `README.md`, `tests/e2e_containers/**`) | Default | Ephemeral clean-room Docker verification (`INSTALL_SOURCE=wheel`) |
| `.github/workflows/pages.yml` | `Deploy Documentation Portal` | `push` (`main`), `workflow_dispatch` | `contents: write`; `GITHUB_TOKEN` (`lychee-action`) | Versioned MkDocs Material site via `mike deploy` to `gh-pages` |

### 2.2 Upstream Public Catalog Dependencies (`mcp-fingerprints` & `mcp-vulnerabilities`)

| Repository | Key Workflows | Triggers | Publishing Destinations |
| :--- | :--- | :--- | :--- |
| **`mcp-fingerprints`** | `daily_sync.yml`, `deploy_pages.yml`, `e2e.yml`, `release.yml`, `test_release.yml` | `0 4 * * *` cron, `push` (`main`), `pull_request`, `release` (`published`), `workflow_dispatch` | PyPI (`mcp-fingerprints`), GitHub Releases (`passports.json.gz`), GitHub Pages (`web/`), `repository_dispatch` -> `mcp-vulnerabilities` |
| **`mcp-vulnerabilities`** | `ci.yml`, `daily_sync.yml`, `cross_repo_sync.yml`, `snapshot_release.yml`, `release.yaml`, `sign_release.yml`, `docker.yml`, `pages.yml`, `daily_web_audit.yml`, `remediate_action.yml`, `test_action.yml` | `0 3 * * *` / `0 4 * * *` / `0 5 * * *` / `0 2 1,15 * *` crons, `repository_dispatch`, `push` (`main`, `v*.*.*`), `pull_request`, `release` (`published`) | PyPI (`mcp-vulnerabilities`), GHCR, GitHub Pages, `snapshot-*` & `v*` GitHub Releases, Sigstore bundles |

---

## 3. Test Suite Coverage, Stage Ordering & Measured Timings

| Repository | Pipeline / Gate | Stage Order & Executed Checks | Observed Timing |
| :--- | :--- | :--- | :--- |
| **`verityredteam-free`** | `ci.yml` (`test-and-build`) | `ruff check src tests` -> `pytest tests/ -q` (`895 passed, 1 skipped` locally) -> `verity test --demo` | CI: **1m41s** (`3.13`), **2m09s** (`3.12`) (run `45968582488`); Local pytest: **63.91s** |
| **`verityredteam-free`** | `full-tests.yml` | `ruff` -> `pytest tests/ -v` -> `--demo` -> `--sql` -> `server --help` -> `uv build` | CI: **1m53s** (`3.12`), **2m11s** (`3.13`) (run `45913812639`) |
| **`verityredteam-free`** | `workflow.yaml` (`pypi-publish`) | Re-runs `ruff` + `pytest tests/ -q` -> `uv build` -> PyPI OIDC publish | CI: **2m21s** (run `45913812639`) |
| **`verityredteam-free`** | `e2e-containers.yml` | `run_e2e.sh` (`customer-pip`, `customer-uvx`, `customer-full-workstation`, `--network none` airgap) | CI: **5m00s** (run `45913812518`) |
| **`verityredteam-free`** | `pages.yml` | `build_docs_portal.py --check` -> `mkdocs build --strict` -> `lychee` -> `mike deploy` | CI: **15s** (run `45968582442`) |
| **`mcp-fingerprints`** | `e2e.yml` | `pytest -v -m "not integration"` -> Playwright `test_web_pwa_e2e.py` | CI: **3m00s** (run `45987237832`) |
| **`mcp-vulnerabilities`** | `ci.yml` | `ruff check src/` -> dataset `validate` -> `pytest -v tests/` (`3.12`, `3.14`) | CI: **3m24s** (`3.12`), **2m42s** (`3.14`) (run `45982907610`) |

### Local-vs-CI Gaps in `verityredteam-free`

1. **`scripts/` Not Linted in CI**: `ci.yml` and `full-tests.yml` run `ruff check src tests` rather than `ruff check src tests scripts` (unlike the local developer baseline).
2. **Portal Drift Caught Post-Merge**: `scripts/build_docs_portal.py --check` runs only in `pages.yml` on `main` push, not in `ci.yml` on pull requests.
3. **Partial Workflow Hygiene Coverage**: `tests/unit/test_workflow_hygiene.py` hardcodes 5 files in `ALL_WORKFLOW_PATHS`, omitting `pages.yml` (and any future `upstream-sync.yml`).
4. **Hardcoded `"0.2.2"` in Container E2E & Parity Tests**: `tests/e2e_containers/Dockerfile.customer-pip:13`, `Dockerfile.customer-uvx:9`, `Dockerfile.customer-workstation:22`, `verify_all_scenarios.sh:171`, and `tests/unit/test_cli_auditor_parity.py:530` hardcode `"0.2.2"`, creating manual release drift.
5. **No Automated Upstream Sync**: `verityredteam-free` has no `.github/workflows/upstream-sync.yml` to refresh `uv.lock` and `src/verity/data/*.json.gz` when upstream `mcp-fingerprints` / `mcp-vulnerabilities` release.

---

## 4. Root-Cause Diagnosis of Failing & Incomplete Flows

1. **`Update Homebrew Tap` Failure (`45914244097`)**:
   - `secrets.HOMEBREW_TAP_TOKEN` is unset in `JMartynov/verityredteam-free`, so `actions/checkout@v5` fails with `Input required and not supplied: token`.
   - When `Publish to PyPI` runs via `workflow_dispatch` on `main`, `github.event.workflow_run.head_branch` evaluates to `"main"`, causing PyPI lookup of `verity-redteam-core/main/json` to fail.
   - `homebrew-tap.yml` does not pass `--from-lock` to `scripts/generate_homebrew_formula.py` and does not validate `Formula/verity.rb` with `ruby -c`.
2. **Empty `v0.2.2` GitHub Release & Manual PyPI E2E**:
   - `workflow.yaml` publishes to PyPI only, leaving GitHub Release `v0.2.2` with `assets: []` and requiring manual runs for `INSTALL_SOURCE=pypi` container verification.
3. **Upstream `mcp-fingerprints` Daily Sync Rejection (`45983774823`)**:
   - `web/catalog.json` exceeded GitHub's `100.00 MB` file limit (`101.30 MB`), rejecting `git push` since Nov 24 and preventing downstream `repository_dispatch` (which also lacks `REPO_DISPATCH_PAT` and sends mismatched `fingerprints_version` instead of `upstream_version`).
4. **Upstream `mcp-vulnerabilities` Asset & Scheduling Gaps**:
   - `v*` GitHub Releases (`v1.7.44`) omit `vulnerabilities.json.gz`, `sign_release.yml` dispatch omits `--ref "v${NEW_VERSION}"`, and `cross_repo_sync.yml` runs at `0 4 * * *` simultaneously with `mcp-fingerprints`.

---

## 5. Remediation Plan (`verityredteam-free` Tasks)

| Milestone / Task | Priority | Status | Summary |
| :--- | :---: | :---: | :--- |
| **`M54` (`TASK-111-FREE`)** | `P0` (`High`) | `Done` | Fix `homebrew-tap.yml` fallback + `--from-lock` + `ruby -c` + secret preflight; publish GitHub Release artifacts + trigger `INSTALL_SOURCE=pypi` verification in `workflow.yaml`; add `.github/workflows/upstream-sync.yml`. |
| **`M55` (`TASK-112-FREE`)** | `P0` (`High`) | `Done` | Dynamically validate all `.github/workflows/*.{yml,yaml}` in `test_workflow_hygiene.py`; eliminate hardcoded `"0.2.2"` across E2E Dockerfiles, `verify_all_scenarios.sh`, `run_e2e.sh`, and `test_cli_auditor_parity.py`; add `scripts` to `ruff` and `build_docs_portal.py --check` to `ci.yml`. |
