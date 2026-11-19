# M21: Sync `README.md` Verbatim Tables, `demo.tape` Scene 4 & `demo.gif` to `v0.2.0` Un-Ellipsized Output

- **Task ID**: `M21`
- **Priority**: `P1` (Master Rank `#10`, Track B — Simple Fixes, Docs & CI Hygiene)
- **Status**: `Todo`
- **Dependencies**: `M9`, `M10`, `M11`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

`README.md` documents two "verified" terminal tables that were captured before `M11` disabled
Rich column wrapping (`no_wrap=True`) on the findings table. They still contain ellipsized rule
IDs that the CLI no longer emits:

- Workstation audit table (`README.md` lines 76–104): `SEC-STATIC-SECRET-IN-CONF…`,
  `SEC-STATIC-UNSAFE-SHELL-W…`.
- Schema screen table (`README.md` lines 206–218): `VERITY-STATIC-INJECTION-O…`,
  `VERITY-STATIC-TOOL-POISON…`, `VERITY-STATIC-EXFIL-WEBHO…`, `VERITY-STATIC-METADATA-SS…`.

The authoritative, un-ellipsized captures already exist in
`tests/e2e_containers/snapshots/01_workstation_scan.txt` and
`tests/e2e_containers/snapshots/02_schema_scan.txt`. The README blocks drifted from them.

Additionally, `docs/assets/demo.tape` Scene 4 (line 68) still runs
`verity test --demo --target sqlite-basic`, which produces a single-target result table that no
longer matches the README's four-target demo proof (`sqlite-basic`, `postgres-basic`,
`mongo-basic`, `code-exec-basic`). The rendered `docs/assets/demo.gif` is stale as a result.

---

## 2. Requirements & Target Files

1. **README Table Sync**: Replace the two ellipsized terminal blocks in `README.md`
   (lines 76–104 and 206–218) with the verbatim contents of
   `tests/e2e_containers/snapshots/01_workstation_scan.txt` and
   `tests/e2e_containers/snapshots/02_schema_scan.txt` respectively — full rule IDs, no `…`.
2. **Demo Tape Fidelity**: Update `docs/assets/demo.tape` Scene 4 (line 68) to
   `Type "verity test --demo"` (drop `--target sqlite-basic`), matching the four-target
   demo table documented in the README.
3. **GIF Re-Record**: Regenerate `docs/assets/demo.gif` via
   `scripts/record_demo_gif.sh` (vhs + gifsicle), preserving the documented invariants:
   animated, `<= 900x480`, `>= 100` frames, `< 2.5MB`.
4. **Docs Parity Guard**: Extend `tests/unit/test_documentation_parity.py` with tests that
   assert zero ellipsized rule IDs in `README.md` and that the `demo.tape` Scene 4 command is
   exactly `verity test --demo`.

---

## 3. Automated Tests to Verify (`tests/unit/test_documentation_parity.py`)

1. `test_readme_workstation_table_matches_snapshot` — the fenced `text` block following the
   "Verified Result" for scenario 1 equals
   `tests/e2e_containers/snapshots/01_workstation_scan.txt` (byte-for-byte).
2. `test_readme_schema_table_matches_snapshot` — the `<details>` schema screen block equals
   `tests/e2e_containers/snapshots/02_schema_scan.txt`.
3. `test_readme_has_no_ellipsized_rule_ids` — assert the `…` ellipsis character never appears
   inside any `VERITY-*` or `SEC-*` rule ID fragment in `README.md`, and that every
   `STATIC_RULE_IDS` value appears verbatim.
4. `test_demo_tape_scene4_uses_full_demo` — parse `docs/assets/demo.tape`, assert Scene 4
   contains `verity test --demo` and does **not** contain `--target`.
5. `test_demo_gif_present_and_not_stale` — assert `docs/assets/demo.gif` exists and is
   referenced by `README.md`.

---

## 4. Acceptance Scenario in Clean Container with Real CLI Output

Inside the existing empty-container suite (`tests/e2e_containers/verify_all_scenarios.sh`):
1. Run `verity scan --config-file "$HOME/.cursor/mcp.json"` and
   `verity scan --schema-file vendor_tools.json`; capture output.
2. Assert the rendered rule IDs match `01_workstation_scan.txt` /
   `02_schema_scan.txt` exactly (no truncation, no `…`).
3. Run `./scripts/record_demo_gif.sh` inside a Docker-enabled CI runner (the script itself
   builds the recorder image and runs `vhs`/`gifsicle`).
4. **Assertions**: exit `0`; produced `docs/assets/demo.gif` is animated, `<= 900x480`,
   `>= 100` frames, `< 2.5MB`; `scan_for_leaks` finds no raw secrets in any output; full
   `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh` passes.

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/unit/test_documentation_parity.py -v
uv run pytest tests/
./scripts/record_demo_gif.sh
INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] Both README terminal tables are byte-for-byte identical to snapshots `01` and `02`, with
      zero ellipsized rule IDs.
- [ ] `docs/assets/demo.tape` Scene 4 runs `verity test --demo` (no `--target`).
- [ ] `docs/assets/demo.gif` re-recorded and validated (animated, `<= 900x480`, `>= 100` frames,
      `< 2.5MB`).
- [ ] New parity tests in `tests/unit/test_documentation_parity.py` pass, along with full
      `pytest tests/`, `ruff check src tests`, and container E2E.
