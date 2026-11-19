# M18: Sync SARIF Exporter Driver Version with `verity.__version__`

- **Task ID**: `M18`
- **Priority**: `P1` (Master Rank `#7`, Track B — Simple Fixes, Docs & CI Hygiene)
- **Status**: `Todo`
- **Dependencies**: `M7`, `M11`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

`_stdlib_sarif_exporter()` (`src/verity/cli.py`, ~line 106) hardcodes the SARIF tool driver version:

```python
"driver": {
    "name": "Verity MCP Security Scanner",
    "version": "0.1.0",
    ...
}
```

`src/verity/__init__.py` declares `__version__ = "0.2.0"`, and `pyproject.toml` declares `version = "0.2.0"`. Result: SARIF output reports `0.1.0`, diverging from the rest of the package. This breaks downstream SARIF consumers (GitHub Code Scanning, IDE integrations) that correlate tool version with baseline state — version desync can suppress or duplicate alerts.

---

## 2. Requirements & Target Files

1. **Single Source of Truth**: Replace the hardcoded `"0.1.0"` in `_stdlib_sarif_exporter()` with `verity.__version__` (imported from the package root) so the SARIF driver version always tracks the package.
2. **No Regressions**: Preserve the existing SARIF v2.1.0 structure (`$schema`, `version`, `runs[].tool.driver`, `rules`, `results`); only the driver version string changes.
3. **Plugin Path Parity**: The `verity-pro` plugin exporter path (`_load_sarif_exporter()`) is unchanged; the stdlib fallback (`_stdlib_sarif_exporter()`) is the only edited code path.
4. **Forward Safety**: Any future version bump in `pyproject.toml` / `verity.__version__` must propagate automatically — no second hardcoded version constant anywhere in `src/`.

---

## 3. Automated Tests to Verify (`tests/unit/test_cli_auditor_parity.py`)

1. `test_sarif_driver_version_matches_package()`: invoke `cli.main(["scan", "--format", "sarif"])` with the stdlib fallback (monkeypatched `_iter_plugin_entry_points` returning a stub entry point), parse the JSON output, and assert:
   - `data["runs"][0]["tool"]["driver"]["version"] == verity.__version__`
2. `test_sarif_driver_version_matches_pyproject()`: read `pyproject.toml` (`tomllib` on Python 3.12+), assert `pyproject["project"]["version"] == verity.__version__` — guarantees the three sources (`pyproject.toml`, `verity.__version__`, SARIF driver) stay in lockstep.
3. Extend the existing `test_scan_sarif_stdlib_fallback` with an assertion that `data["runs"][0]["tool"]["driver"]["version"] == verity.__version__`.

---

## 4. Acceptance Scenario in Clean Container with Real MCP Server Config

Extend `tests/e2e_containers/verify_all_scenarios.sh` with a new step (inside Scenario 1, or a dedicated Scenario 7):

1. Generate a real MCP server config (e.g. `@modelcontextprotocol/server-fetch` via `npx -y …`) at `~/.cursor/mcp.json` — reuse the existing fixture.
2. Export SARIF using the stdlib fallback path (`verity-pro` not installed in the container):
   ```bash
   verity scan --config-file "$HOME/.cursor/mcp.json" --format sarif \
     --output "$OUT_DIR/sarif.json"
   ```
3. **Assertions** (Python one-liner in the script):
   - `json.loads(open("$OUT_DIR/sarif.json"))["runs"][0]["tool"]["driver"]["version"]`
     equals the installed package version reported by `python -c "import verity; print(verity.__version__)"`.
   - Exit `0` (findings present, no `--fail-on-findings`); SARIF parses as valid JSON; `version` field is `2.1.0`.
4. `scan_for_leaks "$OUT_DIR"` remains clean (no secrets in SARIF output).

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/unit/test_cli_auditor_parity.py -v -k sarif
uv run pytest tests/
INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] `_stdlib_sarif_exporter()` uses `verity.__version__`; no hardcoded version string remains in `src/verity/cli.py`.
- [ ] Unit tests assert SARIF `runs[0].tool.driver.version == verity.__version__` and that `pyproject.toml` version matches, preventing future drift.
- [ ] Container E2E scenario runs `verity scan --format sarif` against a real MCP config and confirms the driver version matches the installed package version.
- [ ] `uv run pytest tests/`, `uv run ruff check src tests`, and `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh` all pass cleanly.
