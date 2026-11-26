# M29: Populate Exact GitHub Project #5 Item IDs & Links Across `TASK_BOARD.md` (`M1`–`M29`)

- **Task ID**: `M29`
- **Priority**: `P3` (Master Rank `#18`, Track B — Simple Fixes, Docs & CI Hygiene)
- **Status**: `Done`
- **Dependencies**: `M10`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

The Task Matrix in `TASK_BOARD.md` links rows `M1`–`M11` only to the generic Project #5 root URL
(`https://github.com/users/JMartynov/projects/5`), while rows `M12`–`M29` carry the exact item id
(`[View Item #M12](https://github.com/users/JMartynov/projects/5) (\`PVTI_…\`)`). The same gap exists
in the detailed `### M<n>:` sections: their `#### Task Spec` blocks for `M1`–`M10` omit the
`GitHub Project #5 Item: \`PVTI_…\`` identifier that `M11`–`M29` use.

Consequences:

- A reader cannot navigate from a board row to the concrete project item; the link always lands on
  Project #5 view 1.
- Nothing prevents the same drift when new rows are added, because no test asserts the
  matrix/detailed-section/id relationship.
- Manual reconciliation (search by title in the GitHub UI) is required after every board edit.

---

## 2. Requirements & Target Files

1. **Harvest canonical item ids (execution time, never guessed).** Run
   `gh project item-list 5 --owner JMartynov --format json --limit 100` and persist the payload
   (e.g. `/tmp/project5_items.json`), then map each task row `M<n>` to its item by matching the
   task key/title prefix (e.g. `M11:`) in the item content title. Record the item `id` field
   verbatim (shape `PVTI_…`). **Do not invent, reorder or truncate ids.** If an existing row has no
   matching item, stop and report it instead of writing a placeholder.
2. **Matrix normalization** in `TASK_BOARD.md` for `M1`–`M11` and for any other matrix row missing
   an id: follow the exact convention already used by `M12`–`M29` —
   `[View Item #M<n>](https://github.com/users/JMartynov/projects/5) (\`PVTI_…\`)` — keeping the
   root URL and appending the id in backticks. Do not alter other columns, ordering or wording.
3. **Detailed-section normalization**: for every `### M<n>:` heading whose `#### Task Spec` / reference block
   lacks it, add `GitHub Project #5 Item: \`PVTI_…\``.
   Preserve all existing spec text; the id must equal the matrix id for the same row.
4. **Scope guard.** All added validation must **discover rows dynamically** from
   `TASK_BOARD.md` (regex such as `^\| \*\*M(\d+)\*\* \|` and `^### M(\d+):`) so the guarantees
   hold automatically across all rows `M1`–`M29`.
5. **Parity test** in `tests/unit/test_documentation_parity.py` (new or extended, no new
   dependencies) covering every discovered row:
   - matrix row contains an id matching `PVTI_[A-Za-z0-9_-]{10,}`;
   - matrix row links to `https://github.com/users/JMartynov/projects/5`;
   - the spec link resolves to an existing `docs/tasks/*.md` file, or is the documented
     `Inline below` marker with a matching `### M<n>:` heading in the same file;
   - the detailed section for that row exists and contains the same id;
   - ids are unique across rows; the matrix row set equals the detailed heading set.
6. No runtime/source changes, no new dependencies, no report-format changes.

---

## 3. Automated Tests to Verify (`tests/unit/test_documentation_parity.py`)

1. `test_task_matrix_rows_carry_project_item_ids` — parametrized over rows discovered in the Task
   Matrix; each row's `PVTI_…` id matches `PVTI_[A-Za-z0-9_-]{10,}`.
2. `test_task_matrix_rows_link_to_project_5` — each row links to
   `https://github.com/users/JMartynov/projects/5` and is not a bare root link without an id.
3. `test_task_matrix_spec_links_resolve` — `docs/tasks/…md` targets exist on disk; `Inline below`
   is accepted only when the matching `### M<n>:` heading exists.
4. `test_detailed_sections_carry_project_item_ids` — every `### M<n>:` section includes its `PVTI_…` item id.
5. `test_matrix_and_detailed_sections_are_in_sync` — matrix row ids equal detailed-section ids
   per `M<n>`; matrix row set equals detailed heading set.
6. `test_project_item_ids_are_unique` — no id repeated across rows or sections.

---

## 4. Acceptance Scenario with Live GitHub Project #5 and Container Regression Check

1. Run the harvest command, persist `/tmp/project5_items.json`, and confirm the mapping report lists
   one item id per board row that exists.
2. Confirm `TASK_BOARD.md` rows `M1`–`M29` all render as
   `[View Item #M<n>](https://github.com/users/JMartynov/projects/5) (\`PVTI_…\`)` and their
   detailed sections list the same ids.
3. Verify the ids against Project #5 via `gh project item-list 5 --owner JMartynov --format json`
   (id present, title contains the matching `M<n>` key) — no id may be absent from the project.
4. **Assertions**: `tests/unit/test_documentation_parity.py` passes; the full `pytest tests/` suite
   stays green; no file under `src/` changes (`git diff --stat src/` is empty).
5. **Container regression check**: since this is a docs/test-only change, run
   `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh` once and confirm it remains green
   (proves the packaging/manifests are unaffected).

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
gh project item-list 5 --owner JMartynov --format json --limit 100 > /tmp/project5_items.json
uv run pytest tests/unit/test_documentation_parity.py -v
uv run ruff check src tests && uv run pytest tests/ && INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] Every row present in the `TASK_BOARD.md` Task Matrix carries an exact, project-verified
      `PVTI_…` item id and links to Project #5; rows `M1`–`M11` are backfilled.
- [ ] Every matching `### M<n>:` detailed section states the same `PVTI_…` id.
- [ ] No placeholder, guessed or duplicated ids; ids are sourced verbatim from
      `gh project item-list 5 --owner JMartynov --format json`.
- [ ] `tests/unit/test_documentation_parity.py` enforces row/id/spec-link consistency over
      dynamically discovered rows and passes alongside `ruff check src tests`, full `pytest tests/`, and the container E2E run.
