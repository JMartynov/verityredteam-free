# M25: Add Nightly `schedule` Trigger (`cron: '0 4 * * *'`) to `e2e-containers.yml`

- **Task ID**: `M25`
- **Priority**: `P2` (Master Rank `#14`, Track B — Simple Fixes, Docs & CI Hygiene)
- **Status**: `Todo`
- **Dependencies**: `M8`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

`.github/workflows/e2e-containers.yml` currently runs only on `workflow_dispatch`, version tag pushes (`v*`), and pull requests touching `src/**`, `README.md`, or `tests/e2e_containers/**`. It has no scheduled execution.

The container E2E suite installs upstream artifacts at runtime:
- PyPI packages resolved by `uv sync --extra dev` / wheel installation.
- `mcp-remote@0.1.15` via `npx`.
- DVMCP.
- Docker base images.

Without a nightly run, upstream drift or yanked package versions can break the ground-zero install path between releases. `.github/workflows/full-tests.yml` already has a nightly `schedule` at `cron: '0 3 * * *'`; `e2e-containers.yml` should run at `cron: '0 4 * * *'` so the heavier container suite executes after the full test suite and still every night.

---

## 2. Requirements & Target Files

1. **Workflow Trigger**: Add to `.github/workflows/e2e-containers.yml`:
   ```yaml
   schedule:
     - cron: '0 4 * * *'
   ```
2. **Preserve Existing Triggers**: Keep `workflow_dispatch`, `push: tags: - "v*"`, and the existing `pull_request` path filters unchanged.
3. **Offset From Full Tests**: Use `0 4 * * *` (one hour after `full-tests.yml` at `0 3 * * *`) to avoid runner contention and catch daily upstream drift in PyPI packages, `mcp-remote@0.1.15`, DVMCP, and Docker base images.
4. **Workflow Hygiene Test**: Add `tests/unit/test_workflow_hygiene.py` coverage that loads `.github/workflows/e2e-containers.yml` with `yaml.safe_load` and asserts the `0 4 * * *` schedule exists alongside `workflow_dispatch`, tag pushes, and `pull_request`.
5. **Container E2E Acceptance Run**: The scheduled job must continue to run `bash ./tests/e2e_containers/run_e2e.sh` with `INSTALL_SOURCE=wheel`.

---

## 3. Automated Tests to Verify (`tests/unit/test_workflow_hygiene.py`)

1. `test_e2e_containers_has_nightly_schedule`: `yaml.safe_load()` the workflow and assert `on.schedule` contains `{"cron": "0 4 * * *"}`.
2. `test_e2e_containers_preserves_existing_triggers`: assert `workflow_dispatch`, `push.tags == ["v*"]`, and `pull_request.paths` are present.
3. `test_schedule_offset_differs_from_full_tests`: parse both workflows and assert `e2e-containers.yml` uses `0 4 * * *` while `full-tests.yml` uses `0 3 * * *`.
4. `test_e2e_containers_runs_container_suite`: assert the workflow still invokes `bash ./tests/e2e_containers/run_e2e.sh` with `INSTALL_SOURCE: wheel`.

---

## 4. Acceptance Scenario: Nightly Container E2E Verification

1. Open a pull request containing the workflow change and confirm `e2e-containers` still runs through its existing `pull_request` trigger.
2. Use `workflow_dispatch` to confirm manual execution remains available.
3. Confirm GitHub Actions registers the workflow with a nightly `schedule` entry at `0 4 * * *`.
4. Wait for or simulate the scheduled run and confirm `INSTALL_SOURCE=wheel bash ./tests/e2e_containers/run_e2e.sh` completes successfully.
5. **Assertions**: the YAML parse test passes; `workflow_dispatch`, tag `v*`, and `pull_request` triggers remain intact; the scheduled container verification runs nightly and fails loudly on upstream drift.

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run pytest tests/unit/test_workflow_hygiene.py -v
uv run ruff check src tests
INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] `.github/workflows/e2e-containers.yml` includes `schedule: - cron: '0 4 * * *'`.
- [ ] Existing `workflow_dispatch`, tag `v*`, and `pull_request` triggers are preserved.
- [ ] `tests/unit/test_workflow_hygiene.py` parses the workflow with `yaml.safe_load` and verifies the cron plus existing triggers.
- [ ] Scheduled runs execute the container E2E suite with `INSTALL_SOURCE=wheel` and pass.
- [ ] `uv run pytest tests/unit/test_workflow_hygiene.py -v`, `uv run ruff check src tests`, and `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh` pass cleanly.
