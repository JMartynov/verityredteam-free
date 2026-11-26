# M24: Extend Container E2E (`verify_all_scenarios.sh`) for DSN Credentials, `CUSTOM_FIELD=sk-…` & Live DVMCP `stdio` Probing

- **Task ID**: `M24`
- **Priority**: `P2` (Master Rank `#13`, Track B — Simple Fixes, Docs & CI Hygiene)
- **Status**: `Done`
- **Dependencies**: `M8`, `M11`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

`MultiClientConfigScanner` (`src/verity/discovery/config_scanner.py`) separates key-name matching (`SECRET_KEY_PATTERNS`) from value-shape matching (`SECRET_VALUE_PATTERNS`). M11 added DSN credential detection (`DATABASE_URL` / `postgres://user:pass@host/db`-style values) and M7/M11 extended value-shape coverage, but the container E2E suite never exercises either behaviour:

- Scenario 1 configs contain only `sk-`, `ghp_` and placeholder env values; no DSN with an embedded password and no secret under an arbitrary (non-secret-looking) key name such as `CUSTOM_FIELD`.
- `SECRETS=( … )` in `tests/e2e_containers/verify_all_scenarios.sh` has no DSN password or arbitrary-key secret, so a redaction regression in `_scrub_secrets()` (`src/verity/cli.py`) could leak raw values into `terminal` / `json` / `markdown` / `html` output undetected.
- DVMCP coverage is static-only: Scenario 4 runs `verity scan --path /opt/dvmcp`. The live probe path (`verity test --command "python3 …"`) is only exercised against the synthetic `vuln_stdio_mcp.py` fixture, so a real DVMCP challenge server is never handshaked against, listed, or probed over `stdio`.

---

## 2. Requirements & Target Files

1. **DSN credential coverage**: extend the generated `~/.cursor/mcp.json` in Scenario 1 with a server whose `env` carries `DATABASE_URL: postgres://analytics:<password>@db.internal:5432/analytics` (embedded password) plus a `CUSTOM_FIELD` holding a `sk-…` literal (arbitrary key name, value-pattern-only detection).
2. **Safe twin**: add a second server using `DATABASE_URL: postgres://analytics:${DB_PASS}@db.internal:5432/analytics`; it must produce **zero** secret findings (no detection, no masking artefacts).
3. **Leak assertions**: append the raw DSN password and the `sk-…` literal to the `SECRETS=( … )` array so both `scan_for_leaks` passes (pre-snapshot and post-snapshot) cover them.
4. **Live DVMCP probing**: in addition to the existing static `verity scan --path /opt/dvmcp`, add a live `stdio` probe `verity test --command "python3 /opt/dvmcp/<challenge_script>.py"` (both terminal and `--format json`), asserting exit `1` and at least one `FAIL` result carrying `VERITY-STATIC-*` rule ids.
5. **Parity**: the same DSN shapes accepted by `MultiClientConfigScanner` must be redacted by `_scrub_secrets()` in all four report formats — no drift between detection and masking.

---

## 3. Automated Tests to Verify (`tests/unit/test_cli_auditor_parity.py`)

1. `DATABASE_URL=postgres://app:SuperSecretDbPassword123@db:5432/app` → flagged `SEC-STATIC-SECRET-IN-CONFIG`; raw password absent from `terminal` / `json` / `markdown` / `html` output (parametrized over the four formats); matched value rendered as `****`.
2. `DATABASE_URL=postgres://app:${DB_PASS}@db:5432/app` and `$DB_PASS`-style references → **not** flagged.
3. `CUSTOM_FIELD=sk-live-…` (non-secret key name) → flagged via value pattern; scrubbed to `****`.
4. `mysql://user:pass@host/db` and `mongodb+srv://user:pass@cluster/db` DSN variants → flagged and scrubbed.
5. Benign values (`DATABASE_URL=postgres://app@db:5432/app`, `REDIS_URL=redis://cache:6379/0`, `DB_POOL_SIZE=10`) → zero findings.
6. Parity test: every DSN shape detected by `MultiClientConfigScanner.is_secret_env_entry()` is redacted to `****` by the CLI scrubber in each report format (no detection/masking drift).

---

## 4. Acceptance Scenario in Clean Container with Real MCP Server Config

Extend `tests/e2e_containers/verify_all_scenarios.sh`:

1. In the generated `~/.cursor/mcp.json`, add:
   - `db-analytics` server (`npx -y @modelcontextprotocol/server-postgres`-style entry) with `DATABASE_URL` carrying a real embedded password and `CUSTOM_FIELD: sk-…`.
   - `db-safe` twin with `DATABASE_URL: postgres://analytics:${DB_PASS}@db.internal:5432/analytics`.
2. Add the raw DSN password and the `sk-…` literal to the `SECRETS=( … )` leak-scan array.
3. Run:
   ```bash
   verity scan --config-file "$HOME/.cursor/mcp.json" --format json --output "$OUT_DIR/dsn_scan.json" --fail-on-findings
   verity scan --format markdown --output "$OUT_DIR/dsn_scan.md"
   verity test --command "python3 /opt/dvmcp/<challenge_script>.py" --format json --output "$OUT_DIR/dvmcp_live.json"
   ```
4. **Assertions**:
   - `verity scan` exits `1`; `SEC-STATIC-SECRET-IN-CONFIG` reported for both `DATABASE_URL` and `CUSTOM_FIELD`, each with `****` evidence.
   - `db-safe` produces zero secret findings.
   - `scan_for_leaks` finds no raw DSN password or `sk-…` value in any output or exported snapshot.
   - The live DVMCP probe exits `1` and yields at least one `FAIL` result with `VERITY-STATIC-*` rule ids, alongside the existing static `--path /opt/dvmcp` findings.
   - Full `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh` passes.

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/unit/test_cli_auditor_parity.py -v
uv run pytest tests/
INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] DSN credentials with embedded passwords are flagged as `SEC-STATIC-SECRET-IN-CONFIG` in MCP config `env` blocks; `${VAR}` / `$VAR` placeholders and password-less DSNs produce zero findings.
- [ ] Secrets under arbitrary key names (`CUSTOM_FIELD`) are detected via value patterns.
- [ ] All matched values (including the DSN password) are redacted to `****` in `terminal`, `json`, `markdown` and `html` reports and in exported snapshots.
- [ ] Container E2E exercises live `verity test --command` probing against a DVMCP challenge server under `/opt/dvmcp`, in addition to static path scanning.
- [ ] `tests/unit/test_cli_auditor_parity.py`, full `pytest tests/`, `ruff check src tests`, and the container E2E scenario pass cleanly.
