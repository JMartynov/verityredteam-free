# M23: Remove Stale "If the package is not yet on PyPI…" Caveat from `README.md`

- **Task ID**: `M23`
- **Priority**: `P1` (Master Rank `#12`, Track B — Simple Fixes, Docs & CI Hygiene)
- **Status**: `Done`
- **Dependencies**: `M10`, `M11`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

`README.md` still contains a stale caveat above the quickstart:

```
If the package is not yet on PyPI, install from source or from a built wheel:
```

`verity-redteam-core==0.2.0` is live on PyPI and installable via `pip install verity-redteam-core` and `uvx --from verity-redteam-core`. The caveat (a) contradicts the immediately preceding block that already shows the PyPI install, (b) undermines trust that the published package is authoritative, and (c) pushes contributor source-build steps onto end-user onboarding. `tests/unit/test_documentation_parity.py` has no guard against this regression.

---

## 2. Requirements & Target Files

1. **Rewrite quickstart (`README.md`, lines 17-24)**: delete the "If the package is not yet on PyPI…" sentence and the top-level `git clone` / `uv build` / `pip install dist/*.whl` block. Keep the direct PyPI install block as the only primary path.
2. **Move source build into a collapsible section**: wrap the source-build steps in `<details><summary>Install from source (contributors)</summary>` with a short intro line so end users see only PyPI.
3. **Parity guard (`tests/unit/test_documentation_parity.py`)**: add a test asserting the literal substring `not yet on PyPI` is absent from `README.md`, and that `pip install verity-redteam-core` plus `uvx --from verity-redteam-core` remain documented.
4. **Container E2E (`tests/e2e_containers/run_e2e.sh`)**: verify the `INSTALL_SOURCE=pypi` mode that cold-installs `verity-redteam-core==0.2.0` from public PyPI into a fresh container.

---

## 3. Automated Tests to Verify (`tests/unit/test_documentation_parity.py`)

1. `test_readme_has_no_stale_pypi_caveat`: `README_PATH.read_text(encoding="utf-8")` must not contain `not yet on PyPI` (case-insensitive).
2. `test_readme_documents_pypi_quickstart`: README must contain `pip install verity-redteam-core` and `uvx --from verity-redteam-core`.
3. Existing `test_readme_cli_commands_are_valid`, `test_relative_links_and_media_resolve`, and `test_readme_documents_free_capabilities` continue to pass unchanged.
4. Container E2E assertion (see §4) verifies the cold PyPI install produces a working `verity` entrypoint.

---

## 4. Acceptance Scenario in Clean Container with Cold PyPI Install

Verify `tests/e2e_containers/run_e2e.sh` with `INSTALL_SOURCE=pypi`:
1. Spawn a fresh container with no local wheel and no `--find-links` overrides.
2. Cold install from public PyPI only: `pip install "verity-redteam-core==0.2.0"`.
3. Assert `pip show verity-redteam-core` reports `Version: 0.2.0`.
4. Run `verity scan` and `verity test --demo`; assert both exit successfully and combined output contains no `not yet on PyPI` text.
5. `INSTALL_SOURCE=pypi ./tests/e2e_containers/run_e2e.sh` passes; the existing `INSTALL_SOURCE=wheel` scenario remains green.

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/unit/test_documentation_parity.py -v
uv run pytest tests/
INSTALL_SOURCE=pypi ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] `README.md` no longer contains the "If the package is not yet on PyPI…" caveat; PyPI install is the only top-level quickstart.
- [ ] Source build instructions remain available inside a `<details>` "Install from source (contributors)" block.
- [ ] `tests/unit/test_documentation_parity.py` fails if `not yet on PyPI` reappears in `README.md`.
- [ ] `INSTALL_SOURCE=pypi` container scenario cold-installs `verity-redteam-core==0.2.0` from PyPI and passes `verity scan` / `verity test --demo`.
- [ ] `ruff check src tests`, full `pytest tests/`, and the pypi E2E scenario pass cleanly.
