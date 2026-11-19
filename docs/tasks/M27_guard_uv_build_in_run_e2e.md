# M27: Guard `uv build` & Local Wheel Staging in `run_e2e.sh` When `INSTALL_SOURCE=pypi`

- **Task ID**: `M27`
- **Priority**: `P3` (Master Rank `#16`, Track B — Simple Fixes, Docs & CI Hygiene)
- **Status**: `Todo`
- **Dependencies**: `M8`, `M11`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

`tests/e2e_containers/run_e2e.sh` (lines 21–36) unconditionally runs `uv build` and stages the freshly built wheel into the local staging directory (`.wheel_stage/`) before invoking Docker Compose, regardless of `INSTALL_SOURCE`.

When `INSTALL_SOURCE=pypi`:
- The wheel build is never consumed by any customer container (they install from PyPI), so build time is wasted on every run.
- Staging still copies a wheel, and stale `*.whl` files left in `dist/` can be selected and staged — or picked up later when the same checkout is rerun in wheel mode — leading to tests exercising an outdated artifact.

The build and staging steps must be guarded behind `if [ "$INSTALL_SOURCE" = "wheel" ]; then … fi`, while still ensuring the staging directory exists so the Docker build context never fails.

---

## 2. Requirements & Target Files

1. **Guard build + staging** in `tests/e2e_containers/run_e2e.sh` (lines 21–36):
   ```bash
   if [ "$INSTALL_SOURCE" = "wheel" ]; then
     …
   fi
   ```
   `uv build`, wheel discovery, and wheel copy into `.wheel_stage/` must run only in `wheel` mode.
2. **Directory invariant**: `.wheel_stage/` (or the configured staging dir) must always exist (`mkdir -p`) regardless of `INSTALL_SOURCE`, so the Docker build context and Dockerfile `COPY` never fail in `pypi` mode.
3. **Stale artifact hygiene**: before building, remove previous wheel(s) from both `dist/` and the staging directory (e.g. `rm -f dist/verity_redteam_core-*.whl` and clearing staged wheels) to guarantee a fresh artifact is used.
4. **Fail-fast preserved**: in `wheel` mode, if `uv build` produces no `verity_redteam_core-*.whl`, exit non-zero with a clear message. In `pypi` mode, no wheel check is performed and the run proceeds.
5. **Compose wiring unchanged**: `docker compose build --build-arg INSTALL_SOURCE="$INSTALL_SOURCE"` continues to receive the selected mode in both branches.
6. **Testability**: build/staging logic must be observable from a shell/unit test in `tests/unit/test_e2e_runner_hygiene.py` (e.g. static assertions on the script plus an executable harness that stubs `uv` and `docker compose`).

---

## 3. Automated Tests to Verify (`tests/unit/test_e2e_runner_hygiene.py`)

1. `INSTALL_SOURCE=pypi`: `uv build` is **not** invoked, no wheel is copied into `.wheel_stage/`, and `docker compose build` still receives `INSTALL_SOURCE=pypi` (parametrized with default/unset value resolving to `wheel` or documented default).
2. `INSTALL_SOURCE=wheel`: stale `dist/verity_redteam_core-*.whl` and staged wheels are removed before `uv build`; fresh wheel is discovered and copied into `.wheel_stage/`.
3. Staging directory (`.wheel_stage/`) exists after the script's setup phase in **both** modes.
4. `INSTALL_SOURCE=wheel` with a stubbed `uv build` producing no wheel → script exits non-zero with the expected message; `INSTALL_SOURCE=pypi` under the same stub → script does not fail on missing wheel.
5. Script hygiene: `bash -n tests/e2e_containers/run_e2e.sh` and (if available) `shellcheck` pass.

---

## 4. Acceptance Scenario in Clean Container with Real MCP Server Config

Run the container E2E suite in both install modes from a clean checkout:

1. **Wheel mode**
   ```bash
   INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
   ```
   - `uv build` runs, stale wheels are cleared first, `.wheel_stage/` contains exactly the freshly built `verity_redteam_core-*.whl`.
   - All customer containers (`customer-pip`, `customer-uvx`, `customer-full-workstation`) pass.

2. **PyPI mode**
   ```bash
   INSTALL_SOURCE=pypi ./tests/e2e_containers/run_e2e.sh
   ```
   - `uv build` is **not** invoked and no local wheel is staged; `.wheel_stage/` still exists so the Docker build context is valid.
   - All customer containers install from PyPI and pass.

3. **Stale-wheel regression**
   - Seed `dist/` with an older `verity_redteam_core-0.0.0-*.whl`, then run `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh`.
   - **Assertions**: the stale artifact is removed before build, no log/line references the seeded stale version, and the run passes using only the newly built wheel.

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/unit/test_e2e_runner_hygiene.py -v
uv run pytest tests/
INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
INSTALL_SOURCE=pypi ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] `uv build` and wheel staging in `tests/e2e_containers/run_e2e.sh` run only when `INSTALL_SOURCE=wheel`.
- [ ] `.wheel_stage/` always exists before `docker compose build`, regardless of `INSTALL_SOURCE`.
- [ ] Stale wheels in `dist/` and the staging directory are removed before building; a seeded stale wheel is never used.
- [ ] Missing wheel in `wheel` mode fails fast; `pypi` mode proceeds without any build or wheel check.
- [ ] `tests/unit/test_e2e_runner_hygiene.py`, full `pytest tests/`, `ruff check src tests`, and container E2E runs for both `INSTALL_SOURCE=wheel` and `INSTALL_SOURCE=pypi` pass cleanly.
