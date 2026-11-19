# M22: Publish GitHub Release for `v0.2.0` & Guard Duplicate PyPI Workflow Trigger

- **Task ID**: `M22`
- **Priority**: `P1` (Master Rank `#11`, Track B — Simple Fixes, Docs & CI Hygiene)
- **Status**: `Todo`
- **Dependencies**: `M6`, `M11`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

Tag `v0.2.0` was published to PyPI, but the repository `JMartynov/verityredteam-free` has **zero GitHub Releases** — there is no structured, human-readable changelog entry for `v0.2.0`, no release assets, and no link from the GitHub UI to the shipped distribution.

Blocking issue: `.github/workflows/workflow.yaml` (lines 3–9) triggers the publish pipeline on **both** `push: tags: ["v*"]` **and** `release: types: [published]`:

```yaml
on:
  push:
    tags:
      - "v*"
  release:
    types: [published]
  workflow_dispatch:
```

Creating a GitHub Release for `v0.2.0` therefore re-runs `pypi-publish` after the tag push already uploaded the artifacts, and `pypa/gh-action-pypi-publish` fails with `400 File already exists` (duplicate filename for the same version). Without a guard, this task's core deliverable (the GitHub Release) is impossible to complete on a green CI run.

---

## 2. Requirements & Target Files

1. **Guard `.github/workflows/workflow.yaml`** against duplicate PyPI upload, using exactly one of:
   - remove the `release: types: [published]` trigger so only tag pushes publish, **or**
   - keep both triggers and add `skip-existing: true` to the `pypa/gh-action-pypi-publish@release/v1` step.
   The chosen guard must be explicit and verifiable by parsing the YAML (no comments-only guard).
2. **Add `tests/unit/test_workflow_hygiene.py`** that loads `.github/workflows/workflow.yaml` with `yaml.safe_load` and asserts:
   - the effective trigger set is a subset of `{push, release, workflow_dispatch}`, and `push.tags` (if present) covers `v*`;
   - a duplicate-upload guard exists: either `release` absent from `on`, or the publish step carries `with.skip-existing: true`;
   - `pypi-publish` declares `needs: full-tests`, `environment.name == pypi`, and `permissions.id-token: write`.
3. **Publish the `v0.2.0` GitHub Release** with structured notes covering the `M7`–`M11` deliverables, verified against the actual repository state, including an `INSTALL_SOURCE=pypi` container E2E confirmation.
4. **No regression** to the existing release flow: a `push` of a new tag must still build, lint, test, and publish exactly once.

---

## 3. Automated Tests to Verify (`tests/unit/test_workflow_hygiene.py`)

1. `workflow.yaml` parses cleanly with `yaml.safe_load` and exposes an `on` mapping (or list) with only known trigger keys.
2. `push.tags` (when `push` is present) contains a pattern matching `v*` (e.g. `"v*"`).
3. Duplicate-upload guard assertion:
   - `release` **not** in triggers → pass, **or**
   - `release` in triggers **and** the `pypa/gh-action-pypi-publish` step has `with: {skip-existing: true}` → pass.
   - any other combination → fail with an explicit message naming both remedies.
4. `pypi-publish` job contract: `needs == "full-tests"`, `environment.name == "pypi"`, `permissions["id-token"] == "write"`.
5. Parametrized negative test: a mutated in-memory copy with `release` present and no `skip-existing` is rejected by the guard helper (pure-function check, no file writes).
6. `gh release view v0.2.0 --json tagName,body` output contains the `M7`–`M11` sections, the PyPI URL for `verity-redteam-core==0.2.0`, and the `INSTALL_SOURCE=pypi` E2E line (asserted via recorded fixture captured after publishing, not live network).

---

## 4. Acceptance Scenario in Clean Container with `INSTALL_SOURCE=pypi`

1. Apply the workflow guard, then run `uv run pytest tests/unit/test_workflow_hygiene.py -v` locally — green.
2. Push the guard commit and create the release:
   ```bash
   gh release create v0.2.0 --title "v0.2.0" --notes-file docs/releases/v0.2.0.md
   ```
   (or `--notes "…"` with the same content) with sections for `M7`, `M8`, `M9`, `M10`, `M11`.
3. Confirm the release exists and the notes are intact:
   ```bash
   gh release view v0.2.0
   ```
4. Confirm the test matrix stays green: the `release` event run of `workflow.yaml` must reach `pypi-publish` and either skip the already-present files (`skip-existing`) or not run at all because the `release` trigger was removed — **no `400 File already exists` failure**.
5. Container E2E against the PyPI artifact:
   ```bash
   INSTALL_SOURCE=pypi ./tests/e2e_containers/run_e2e.sh
   ```
6. **Assertions**: `gh release view v0.2.0` exits `0` and shows tag `v0.2.0`; the release-triggered run does not fail on duplicate upload; `INSTALL_SOURCE=pypi ./tests/e2e_containers/run_e2e.sh` passes and installs `verity-redteam-core==0.2.0` from PyPI.

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/unit/test_workflow_hygiene.py -v
uv run pytest tests/
gh release view v0.2.0
INSTALL_SOURCE=pypi ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] `.github/workflows/workflow.yaml` has an explicit duplicate-upload guard (either the `release: types: [published]` trigger is removed, or `pypa/gh-action-pypi-publish` sets `skip-existing: true`).
- [ ] `tests/unit/test_workflow_hygiene.py` validates the workflow triggers and guard, including the parametrized negative case, and passes.
- [ ] GitHub Release `v0.2.0` is published on `JMartynov/verityredteam-free` with structured notes covering `M7`–`M11` and a PyPI install link, verified by `gh release view v0.2.0`.
- [ ] Re-triggering `pypi-publish` for an existing `v0.2.0` no longer fails with a duplicate-filename error.
- [ ] `uv run pytest tests/`, `uv run ruff check src tests`, and `INSTALL_SOURCE=pypi ./tests/e2e_containers/run_e2e.sh` pass cleanly.
