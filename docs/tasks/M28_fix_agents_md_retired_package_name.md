# M28: Fix Retired `verity-core` Package Name in `AGENTS.md` & Extend Documentation Parity Guard

- **Task ID**: `M28`
- **Priority**: `P3` (Master Rank `#17`, Track B — Simple Fixes, Docs & CI Hygiene)
- **Status**: `Done`
- **Dependencies**: `M10`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

`AGENTS.md` still identifies the repository by its retired distribution name `verity-core`
on line 5 (project identity block) and again in the plugin/MCP section, even though the
package now ships as `verity-redteam-core`. The same block also hardcodes the stale task
range "Tasks M1–M6", which no longer reflects the live board.

`tests/unit/test_documentation_parity.py::test_no_stale_package_references` guards against
this drift, but its `_STALE_PACKAGE_RE` scan iterates only over `README.md` and
`docs/extensibility.md`. `AGENTS.md` is never validated, so the retired name survives every
CI run.

Result: agent-facing documentation contradicts `pyproject.toml` and the README, and the
parity guard does not cover the one file agents read first.

---

## 2. Requirements & Target Files

1. **Rename in `AGENTS.md`**: replace every `verity-core` occurrence with
   `verity-redteam-core` in the Project Identity header (line 5) and the open-core plugin
   boundary section (line 12), keeping the parenthetical repo path unchanged.
2. **Task board reference**: replace the hardcoded "Tasks M1–M6" range with a
   non-stale pointer to `TASK_BOARD.md` / GitHub Project #5.
3. **Extend the parity guard**: in `tests/unit/test_documentation_parity.py`, extend
   `test_no_stale_package_references` to include `REPO_ROOT / "AGENTS.md"`, and introduce
   an `AGENTS_PATH` constant alongside `README_PATH` and `EXTENSIBILITY_PATH` so future
   docs are added in one place.
4. **Optional hardening**: teach `_extract_verity_commands()` to also parse YAML
   (``yaml``) fenced blocks in `README.md`, validating the `verity scan`/`verity test`
   command lines inside the GitHub Actions CI snippet, not only shell fences.
5. **Zero behavioural change**: no `src/` edits; documentation and test guard only.

---

## 3. Automated Tests to Verify (`tests/unit/test_documentation_parity.py`)

1. `test_no_stale_package_references` parametrized over `[README_PATH, EXTENSIBILITY_PATH,
   AGENTS_PATH]` → asserts `_STALE_PACKAGE_RE` does not match any of the three files.
2. `test_agents_md_documents_current_package_name` → `AGENTS.md` contains
   `verity-redteam-core` at least once and contains no `verity-core` token.
3. `test_agents_md_has_no_stale_task_range` → asserts the literal `Tasks M1–M6` sentinel is
   absent and `TASK_BOARD.md` is referenced instead.
4. `test_readme_yaml_snippet_commands_are_valid` (optional) → extracts commands from the
   ``yaml`` CI fence and feeds each through `build_parser().parse_args()`.
5. Regression parity: `_extract_verity_commands()` still returns the same command count for
   existing shell fences (no drops from the YAML addition).

---

## 4. Acceptance Scenario in Clean Container with Real Documentation Checkout

Extend `tests/e2e_containers/verify_all_scenarios.sh` with a documentation-parity scenario:

1. Inside the built wheel container, copy the repository `README.md`, `docs/extensibility.md`,
   and `AGENTS.md` into `/tmp/docslab/`.
2. Run:
   ```bash
   python -c "import re,sys,pathlib;r=re.compile(r'\bverity-core\b');bad=[p for p in sys.argv[1:] if r.search(pathlib.Path(p).read_text())];sys.exit(1 if bad else 0)" \
     /tmp/docslab/README.md /tmp/docslab/docs/extensibility.md /tmp/docslab/AGENTS.md
   ```
3. **Assertions**: exit `0`; grep for `verity-redteam-core` in the AGENTS.md copy returns at
   least one hit and grep for `verity-core` returns zero hits; the relative-link check finds
   `TASK_BOARD.md` resolvable; full `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh`
   passes.

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/unit/test_documentation_parity.py -v
uv run pytest tests/
INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] `AGENTS.md` no longer contains the retired `verity-core` token in any section; identity
      and plugin-boundary text use `verity-redteam-core`.
- [ ] The stale "Tasks M1–M6" range is replaced by a live task-board pointer.
- [ ] `test_no_stale_package_references` covers `README.md`, `docs/extensibility.md`, and
      `AGENTS.md`, and fails if `verity-core` reappears in any of them.
- [ ] Optional YAML-fence CLI validation (if implemented) rejects invalid documented commands.
- [ ] `tests/unit/test_documentation_parity.py`, full `pytest tests/`, `ruff check src tests`,
      and the container E2E scenario pass cleanly.
