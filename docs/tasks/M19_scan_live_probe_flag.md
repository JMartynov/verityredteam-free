# M19: Opt-In `--live-probe` Flag on `verity scan` for Fleet-Wide Live Capability Auditing

- **Task ID**: `M19`
- **Priority**: `P2` (Master Rank `#8`, Track A — Product & Customer Value)
- **Status**: `Done`
- **Dependencies**: `M7`, `M12`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

`ConsolidatedSecurityAuditor.audit_server()` (`src/verity/discovery/auditor.py`) already accepts a `live_probe: bool = False` keyword: when enabled it calls `self.transport.inspect(config)` to fingerprint live capabilities, populates `matched_package` / `matched_version` from live tool signatures, and correlates against the OSV index.

The CLI never enables it. `_collect_config_findings()` (`src/verity/cli.py`, around line 358) hardcodes:

```python
record = auditor.audit_server(config, live_probe=False)
```

and `build_parser()`'s `scan` subparser exposes only `--config-file`, `--schema-file`, `--path`, `--format`, `--output`, `--fail-on-findings`, `--offline`. Consequences:

- `verity scan` over a workstation cannot detect that a configured server is actually a vulnerable package (`VULN-CVE-*`) when the config relies on `command`/`args` that the static matcher cannot pin (e.g. `npx -y <unknown-alias>`), even though `verity test --command` / `verity test --url` do live capability probing.
- Fleet-wide auditing requires running `verity test` once per server, since `scan` has no opt-in live mode.

The gap is only a plumbing + safety concern: expose `--live-probe` (default `False`), thread it into the auditor, and normalize live findings back into the canonical scan-finding schema without crashing on unreachable/disabled servers.

---

## 2. Requirements & Target Files

1. **CLI flag** — `src/verity/cli.py` (`build_parser()`):
   - Add `scan.add_argument("--live-probe", action="store_true", help="Actively probe configured MCP servers to fingerprint live capabilities (opt-in, slower).")`.
   - Default must be `False`; no change to existing invocations and no new behaviour when the flag is omitted.
2. **Threading** — `src/verity/cli.py`:
   - `_cmd_scan()` must pass `live_probe=getattr(args, "live_probe", False)` into `_collect_scan_data()`.
   - `_collect_scan_data()` must forward the flag to `_collect_config_findings(config_file, offline=..., live_probe=...)`.
   - `_collect_config_findings()` must call `auditor.audit_server(config, live_probe=live_probe)` instead of the hardcoded `False`.
3. **Finding normalization** — `src/verity/cli.py`:
   - Live capability findings returned by `ServerAuditRecord.findings` must be normalized through the existing `_normalize_finding()` so they appear in `report["findings"]` with `rule_id`, `severity`, `title`, `message`, `file_path`, `line_number`, `remediation`.
   - Multi-severity ordering must remain stable: `CRITICAL > HIGH > MEDIUM > LOW > INFO`.
   - Results must be scrubbed through `_scrub_secrets()` with the same secret list used for static config findings, so live evidence never leaks plaintext credentials into any report format.
4. **Failure isolation** — `_collect_config_findings()` / `_collect_scan_data()`:
   - A dead, disabled, or timeout-exposed server must not abort the scan. `audit_server()` exceptions must be caught per-server, logged to `stderr` (`print(f"Live probe failed for {config.server_name}: {exc}", file=sys.stderr)`), and the remaining servers must continue to be scanned.
   - `args.live_probe=False` must preserve current behaviour exactly (no transport calls, byte-identical current output).
5. **Output parity** — `--format terminal|json|markdown|html|sarif` must render live findings identically to static findings; `--fail-on-findings` must exit `1` when a live-probe finding is the only finding present.

---

## 3. Automated Tests to Verify (`tests/unit/test_scan_live_probe.py`)

1. **Default off** — parser + handler: `verity scan --config-file ...` (no `--live-probe`) never calls `transport.inspect`; a monkeypatched `StdioDiscoveryTransport.inspect` records zero calls.
2. **Opt-in on** — `verity scan --config-file ... --live-probe --format json` invokes `auditor.audit_server(config, live_probe=True)` once per discovered server; a monkeypatched auditor returning a `SecurityAuditFinding` for a live-exposed tool appears in `report["findings"]` with `rule_id`/`severity`/`remediation` populated.
3. **Dead server resilience** — a monkeypatched `inspect` that raises `TimeoutError` produces exit code `0`, a `stderr` warning mentioning the server name, and still emits findings from other (healthy) configured servers.
4. **Formatting parity** — parametrize `["terminal", "json", "markdown", "html"]` and assert the live `rule_id` appears in every renderer's output and that no live evidence secret (`sk-live-…`) leaks into any format.
5. **`--fail-on-findings`** — with a live-probe-only finding present, exit code is `1`; without `--live-probe`, exit code is `0` for the same config fixture.
6. **`--offline --live-probe`** — combined flags are accepted; `VERITY_OFFLINE=1` remains in effect during the live probe and is restored afterward (no leaked global state).

---

## 4. Acceptance Scenario in Clean Container with Real MCP Server Config

Extend `tests/e2e_containers/verify_all_scenarios.sh` Scenario 2 (live probes):

1. Reuse the existing fixtures `/opt/fixtures/vuln_stdio_mcp.py` and `target-sse-lab:8000/sse` already exercised by `verity test --command` / `verity test --url`.
2. Write a config file `/tmp/out/live_probe_mcp.json` containing:
   - `vuln-stdio`: `{"command": "python3", "args": ["/opt/fixtures/vuln_stdio_mcp.py"]}`
   - `clean-stdio`: `{"command": "python3", "args": ["/opt/fixtures/clean_stdio_mcp.py"]}`
   - `vuln-sse`: `{"type": "sse", "url": "http://target-sse-lab:8000/sse"}`
   - `dead-server`: `{"command": "python3", "args": ["/opt/fixtures/does_not_exist.py"]}`
3. Run:
   ```bash
   verity scan --config-file /tmp/out/live_probe_mcp.json --live-probe --format json \
     --output /tmp/out/live_probe.json --fail-on-findings
   verity scan --config-file /tmp/out/live_probe_mcp.json --live-probe --format terminal \
     --output /tmp/out/live_probe.txt
   verity scan --config-file /tmp/out/live_probe_mcp.json --format json \
     --output /tmp/out/static_only.json
   ```
4. **Assertions**:
   - `--live-probe` run exits `1`; static-only run of the same config exits `0` (no static findings present).
   - `live_probe.json` contains `VERITY-STATIC-INJECTION-OVERRIDE`, `VERITY-STATIC-TOOL-POISONING`, `VERITY-STATIC-EXFIL-WEBHOOK`, `VERITY-STATIC-METADATA-SSRF` from the vulnerable stdio/SSE servers, plus a `VULN-CVE-2025-6514`-style advisory for the pinned vulnerable capability.
   - `clean-stdio` contributes no `VERITY-STATIC-*` findings.
   - `dead-server` produces a `stderr` warning and does **not** cause a non-zero exit by itself.
   - Add any new plaintext values introduced by this fixture to the `SECRETS=( … )` leak array; `scan_for_leaks` must find no raw value in `/tmp/out` or exported snapshots.
   - `./tests/e2e_containers/run_e2e.sh` (with `INSTALL_SOURCE=wheel`) passes end-to-end.

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/unit/test_scan_live_probe.py -v
uv run pytest tests/
INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] `verity scan` accepts `--live-probe` (default `False`); when omitted, behaviour and outputs are unchanged and `transport.inspect` is never called.
- [ ] When set, `live_probe=True` reaches `ConsolidatedSecurityAuditor.audit_server()` via `_cmd_scan` → `_collect_scan_data` → `_collect_config_findings`.
- [ ] Live capability findings appear in every report format (`terminal`, `json`, `markdown`, `html`, `sarif`) with the canonical finding schema, and evidence is scrubbed through `_scrub_secrets()`.
- [ ] Dead/unreachable/disabled servers produce a `stderr` warning and never abort the scan or change the exit code on their own.
- [ ] `--fail-on-findings` exits `1` when the only findings come from live probing.
- [ ] `tests/unit/test_scan_live_probe.py`, full `pytest tests/`, `ruff check src tests`, and the container E2E scenario pass cleanly.
