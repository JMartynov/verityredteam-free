# M13: Expose UCP Rug-Pull Detection (`detect_rug_pull`) in `verity_security_scan` & CLI

- **Task ID**: `M13`
- **Priority**: `P1` (Master Rank `#2`, Track A — Product & Customer Value)
- **Status**: `Todo`
- **Dependencies**: `M8`, `M11` (and pairs cleanly with `M12` for remote streaming MCP servers)
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

Verity already ships a deterministic content-hash rug-pull detection engine — `UnknownCapabilityProfiler.profile_toolset()` and `UnknownCapabilityProfiler.detect_rug_pull()` in `src/verity/ucp/engine.py` — which hashes each tool's canonical name, description, and input schema to detect silent post-approval mutations (added, removed, or tampered tools).

However, today `detect_rug_pull()` is only called internally by `OnboardingController.revalidate_profile()` (`src/verity/onboarding/controller.py`). It is **not** reachable through:
- the IDE MCP server tool `verity_security_scan` (`src/verity/mcp_server/handlers/security_scan.py`),
- the `verity` CLI (`src/verity/cli.py`), or
- the clean-room container E2E suite (`tests/e2e_containers/verify_all_scenarios.sh`).

Meanwhile, `README.md` Scenario 6 (*"In-IDE Self-Auditing & Rug-Pull Detection (`verity serve`)"*) highlights `detect_rug_pull` as a headline trust capability. Exposing it directly closes a high-value customer pain point that lockfiles cannot solve.

---

## 2. Requirements & Target Files

### A. MCP Server Tool Surface (`src/verity/mcp_server/handlers/security_scan.py` & `src/verity/mcp_server/schemas.py`)
1. Add a non-breaking `detect_rug_pull` action to `verity_security_scan` (keeping all existing actions and schemas strictly backward-compatible):
   - Accepts `options` with either:
     - `authorized_hashes: dict[str, str]` + `tools: list[dict]` (or live endpoint `command` / `url` discovered via `_discover_mcp_endpoints`), **or**
     - `baseline_path: str` (JSON file storing `{tool_name: canonical_hash}`) + `save_baseline: bool` to record an initial trusted baseline.
   - Returns structured JSON: `ok`, `action="detect_rug_pull"`, `rug_pull_detected: bool`, `authorized_hashes`, `current_hashes`, and `drift_findings` (tool name, change type: `ADDED` / `REMOVED` / `MUTATED`, details, `is_rug_pull`).
2. Add a companion `snapshot_baseline` (or `save_baseline: true`) path so an IDE agent can pin trusted tool hashes in one call and re-verify on subsequent sessions.

### B. CLI Surface (`src/verity/cli.py`)
1. Extend `verity test` (with `--command` or `--url`) with opt-in baseline flags (default `None`, zero impact on existing invocations):
   - `--save-baseline <path>`: Probes the MCP server's `tools/list`, computes canonical hashes via `UnknownCapabilityProfiler.profile_toolset()`, and writes `<path>` (JSON).
   - `--baseline <path>`: Probes the MCP server's `tools/list`, compares against `<path>` via `UnknownCapabilityProfiler.detect_rug_pull()`, reports `PASS` (exit `0`) when unchanged, or `FAIL` (`RUG_PULL_DETECTED`, exit `1`) when any tool is added, removed, or has its description/schema mutated.

---

## 3. Automated Tests to Verify

### Unit & Integration Tests (`tests/unit/test_rug_pull_exposure.py`)
1. **MCP `verity_security_scan(action="detect_rug_pull")` — Clean Baseline**:
   - Compute `authorized_hashes` via `UnknownCapabilityProfiler.profile_toolset(tools)`.
   - Invoke `verity_security_scan` with unchanged `tools` -> assert `ok is True`, `rug_pull_detected is False`, `drift_findings == []`.
2. **MCP `verity_security_scan(action="detect_rug_pull")` — Description Mutation (Tool Poisoning Rug Pull)**:
   - Mutate a benign tool's `description` to append hidden exfiltration instructions while keeping the tool name and `inputSchema` identical.
   - Assert `rug_pull_detected is True` and `drift_findings` flags the mutated tool with `is_rug_pull is True`.
3. **MCP `verity_security_scan(action="detect_rug_pull")` — Added & Removed Tools**:
   - Add an unexpected shadow tool and remove an authorized tool; assert both drift events are reported accurately.
4. **CLI `--save-baseline` + `--baseline` Workflow**:
   - Run `verity test --command "..." --save-baseline <tmp>/baseline.json` -> assert exit `0` and valid JSON hash map.
   - Re-run `verity test --command "..." --baseline <tmp>/baseline.json` against the same benign server -> assert exit `0` and `PASS`.
   - Mutate the server's exposed `tools/list` and re-run `verity test --command "..." --baseline <tmp>/baseline.json --format json` -> assert exit `1`, `FAIL`, and `RUG_PULL_DETECTED` in output.
5. **Backward Compatibility & Schema Regression**:
   - Assert existing `verity_security_scan` actions (`discover_endpoints`, `scan_client_configs`, `fingerprint_server`, `lookup_vulnerabilities`, `full_audit`, `scan_ast_code`, `call_target_tool`) and `tests/unit/test_documentation_parity.py` remain 100% green.

---

## 4. Acceptance Scenario with a Real MCP Server

Verify rug-pull detection end-to-end against a **real mutable MCP server** inside the clean-room container harness (`tests/e2e_containers/`):

1. **Real Mutable Server Setup (`tests/e2e_containers/`)**:
   - Run a real `FastMCP` (or `stdio` MCP) server whose tool metadata can be switched from **Phase 1 (Benign)** to **Phase 2 (Rug-Pull Mutated)** via an environment variable or state file (e.g., `RUG_PULL_MODE=0` -> benign `query_docs` tool; `RUG_PULL_MODE=1` -> same `query_docs` name/schema, but description silently mutated to exfiltrate `~/.ssh/id_rsa`).
2. **End-to-End Acceptance Commands (in `tests/e2e_containers/verify_all_scenarios.sh` Scenario 6)**:
   ```bash
   # Step 1: Pin trusted baseline against Phase 1 (benign) real server -> exit 0
   RUG_PULL_MODE=0 verity test --command "python3 /opt/fixtures/rug_pull_mcp.py" \
     --save-baseline /tmp/out/trusted_baseline.json

   # Step 2: Re-verify unchanged Phase 1 server -> exit 0 (PASS)
   RUG_PULL_MODE=0 verity test --command "python3 /opt/fixtures/rug_pull_mcp.py" \
     --baseline /tmp/out/trusted_baseline.json

   # Step 3: Server silently mutates tool description (Phase 2 rug pull) -> exit 1 (FAIL: RUG_PULL_DETECTED)
   RUG_PULL_MODE=1 verity test --command "python3 /opt/fixtures/rug_pull_mcp.py" \
     --baseline /tmp/out/trusted_baseline.json --format json

   # Step 4: Verify via `verity serve --transport stdio` JSON-RPC `tools/call` on `verity_security_scan` (`action="detect_rug_pull"`)
   ```
3. **Acceptance Assertions**:
   - Step 1 exits `0` and writes non-empty canonical hash JSON.
   - Step 2 exits `0` (`PASS`).
   - Step 3 exits `1` (`FAIL`) and reports `RUG_PULL_DETECTED` naming `query_docs`.
   - Step 4 JSON-RPC `tools/call` returns `rug_pull_detected: true` cleanly over `verity serve --transport stdio`.
   - Full `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh` passes across all 4 containers.

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/unit/test_rug_pull_exposure.py -v
uv run pytest tests/
INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] `verity_security_scan` exposes `action="detect_rug_pull"` without breaking existing actions or schemas.
- [ ] `verity test` supports `--save-baseline <path>` and `--baseline <path>` returning exit `0` on clean match and exit `1` (`RUG_PULL_DETECTED`) on tool drift.
- [ ] All unit/integration tests in `tests/unit/test_rug_pull_exposure.py`, full `pytest tests/`, and `ruff check src tests` pass cleanly.
- [ ] Real-server rug-pull acceptance scenario (CLI + `verity serve` JSON-RPC) passes inside `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh`.
