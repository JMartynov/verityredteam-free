# M26: Upgrade `actions/checkout` and `astral-sh/setup-uv` Pins Across All GitHub Actions Workflows

- **Task ID**: `M26`
- **Priority**: `P3` (Master Rank `#15`, Track B — Simple Fixes, Docs & CI Hygiene)
- **Status**: `Todo`
- **Dependencies**: `M6`, `M8`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

All four GitHub Actions workflows pin third-party actions to versions that still run on the **Node 20** runtime, which GitHub has deprecated and now annotates on every run:

- `.github/workflows/ci.yml` — `actions/checkout@v4`, `astral-sh/setup-uv@v4`
- `.github/workflows/full-tests.yml` — `actions/checkout@v4`, `astral-sh/setup-uv@v4`
- `.github/workflows/workflow.yaml` — `actions/checkout@v4`, `astral-sh/setup-uv@v4`
- `.github/workflows/e2e-containers.yml` — `actions/checkout@v4`, `astral-sh/setup-uv@v5`

Result: every CI run emits `Node.js 20 actions are deprecated` warnings, the setup-uv pin is **inconsistent** across workflows (`v4` vs `v5`), and `workflow.yaml` gates the PyPI publish so its warnings pollute release runs. A hard runtime cut-over to Node 24 will break the `v4` pins outright.

---

## 2. Requirements & Target Files

1. **actions/checkout**: bump `v4` → `v5` (Node 24 runtime) in **all four** workflows.
2. **astral-sh/setup-uv**: bump to `v6` (Node 24 runtime) in **all four** workflows — including `.github/workflows/e2e-containers.yml`, which is currently `v5` — so a single pin is used everywhere.
3. **No legacy pins**: zero occurrences of `actions/checkout@v4` and zero occurrences of `astral-sh/setup-uv@v4` / `astral-sh/setup-uv@v5` in `.github/workflows/**`.
4. **No floating refs**: no `@main` / `@master` action references introduced by the migration.
5. **No behavioural change**: job names, triggers, matrices, env blocks, permissions, and step ordering stay identical; only `uses:` version tags change.

Target files:
- `.github/workflows/ci.yml`
- `.github/workflows/full-tests.yml`
- `.github/workflows/workflow.yaml`
- `.github/workflows/e2e-containers.yml`
- `tests/unit/test_workflow_hygiene.py` (new)

---

## 3. Automated Tests to Verify (`tests/unit/test_workflow_hygiene.py`)

1. Parametrized over all four workflow files: every `uses: actions/checkout@…` equals `actions/checkout@v5`.
2. Parametrized over all four workflow files: every `uses: astral-sh/setup-uv@…` equals `astral-sh/setup-uv@v6`.
3. `setup-uv@v4` and `checkout@v4` appear **zero** times across `.github/workflows/**` (directory-wide grep-style scan).
4. No action reference uses a floating `@main` / `@master` branch.
5. Pin parity: the set of `actions/checkout@…` tags across the four workflows has size `1`, and likewise for `astral-sh/setup-uv@…` (prevents future drift).
6. Workflow YAML still parses and every expected job name (`test-and-build`, `full-tests`, `pypi-publish`, `e2e-containers`) is present.

---

## 4. Acceptance Scenario in Live CI & Clean Container

1. Push the change to a branch / open a PR that touches `.github/workflows/**`.
2. **CI job assertions**: the `CI` workflow completes green on Python `3.12` and `3.13` with **zero** `Node.js 20 actions are deprecated` annotations on the run summary.
3. **Full suite assertions**: `Full Test Suite` runs green on `3.12` / `3.13`; `Verify Zero-Docker Demo Targets CLI`, `Verify SQL AST Guard CLI` and `Verify MCP Server CLI` steps still pass unchanged.
4. **Release path**: `Publish to PyPI` workflow reaches the `full-tests` job and builds `uv build` artefacts without deprecation warnings.
5. **Container E2E**: `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh` passes (`e2e-containers.yml` bumped to the same pins).
6. Confirm no remaining `@v4` action pins in the workflow directory after the change.

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/unit/test_workflow_hygiene.py -v
uv run pytest tests/
rg -n "uses: (actions/checkout|astral-sh/setup-uv)@" .github/workflows
INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] `actions/checkout@v5` and `astral-sh/setup-uv@v6` are used in **all four** workflows (`ci.yml`, `full-tests.yml`, `workflow.yaml`, `e2e-containers.yml`).
- [ ] Zero `actions/checkout@v4`, zero `astral-sh/setup-uv@v4` and zero `astral-sh/setup-uv@v5` references remain under `.github/workflows/`.
- [ ] `tests/unit/test_workflow_hygiene.py` asserts pin consistency and absence of legacy pins, and passes.
- [ ] Live CI run shows no `Node.js 20` deprecation annotations for either action.
- [ ] `ruff check src tests`, full `pytest tests/`, and `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh` pass cleanly.
