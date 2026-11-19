# M15: Flag Unpinned MCP Packages (`UNPINNED-MCP-PACKAGE`) Instead of Guessing Latest Version

- **Task ID**: `M15`
- **Priority**: `P2` (Master Rank `#4`, Track A — Product & Customer Value)
- **Status**: `Todo`
- **Dependencies**: `M7`, `M8`, `M11`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

In `src/verity/discovery/matcher.py`, `HybridDiscoveryMatcher.match_static_config()` currently computes:
```python
matched_v = target_version or (
    matched_spec.versions[-1].version if matched_spec.versions else "1.0.0"
)
```
and returns `confidence_score=0.85`. `ConsolidatedSecurityAuditor.audit_server()` (`src/verity/discovery/auditor.py`) then passes that guessed `matched_ver` into `VulnerabilityLookupEngine.query(identifier=matched_pkg, version=matched_ver)`:
- When a developer configures an unpinned MCP server such as `npx -y mcp-remote` or `npx -y @modelcontextprotocol/server-github` (or `@latest`), Verity silently assumes the newest catalog version (`versions[-1].version` or `"1.0.0"`).
- This creates two problems:
  1. **Supply-chain blind spot:** Floating `npx`/`uvx` executions fetch and run remote code on every client start (typosquatting / package-takeover risk), yet Verity emits no warning.
  2. **Inaccurate OSV attribution:** Querying OSV with a guessed version can either hide CVEs affecting older versions or emit false-positive CVEs for a version the user did not pin.

---

## 2. Requirements & Target Files

1. **Preserve Unpinned State in Matcher (`src/verity/discovery/matcher.py`)**:
   - In `HybridDiscoveryMatcher.match_static_config()`, when `target_version` is `None` (or explicitly `"latest"`), return `matched_version=None` (or `"unpinned"` consistently with `FingerprintMatchResult` typing) and lower `confidence_score` (e.g. `0.65`) instead of substituting `matched_spec.versions[-1].version` / `"1.0.0"`.
   - Keep exact pinned specifiers (`mcp-remote@0.1.15`, `pkg==1.2.3`) returning the exact `target_version` with `confidence_score=0.85`.
2. **Emit `SEC-STATIC-UNPINNED-PACKAGE` / `UNPINNED-MCP-PACKAGE` Advisory (`src/verity/discovery/auditor.py`)**:
   - When a server is launched via a floating package runner (`npx`, `uvx`, `pipx`, `bunx`) without an exact pinned version (or with `@latest`), emit a structured `SecurityAuditFinding`:
     - `issue_id="SEC-STATIC-UNPINNED-PACKAGE"` (severity `MEDIUM`, CWE `CWE-1104` / `CWE-829`),
     - clear remediation instructing the user to pin an exact version (e.g., `mcp-remote@0.1.16` or local audited path).
   - Do **not** query OSV with a fabricated `"1.0.0"` / `versions[-1]` version when unpinned; only run version-specific OSV correlation when a concrete version is pinned or observed via live fingerprint match.
3. **Update Existing Matcher / Auditor Tests (`tests/unit/`)**:
   - Audit existing tests that relied on the old `versions[-1]` fallback and update expectations cleanly so there are zero unintended regressions.

---

## 3. Automated Tests to Verify

### Unit & Integration Tests (`tests/unit/test_unpinned_package_detection.py`)
1. **Unpinned `npx -y mcp-remote` (No `@version`)**:
   - Assert `match_static_config()` returns `matched=True`, `matched_version is None` (not `"1.0.0"` or `versions[-1]`), and `audit_server()` emits `SEC-STATIC-UNPINNED-PACKAGE` (`MEDIUM`) without fabricated version-specific CVE false positives.
2. **Floating `@latest` (`npx -y mcp-remote@latest`)**:
   - Assert `@latest` is treated as unpinned and triggers `SEC-STATIC-UNPINNED-PACKAGE`.
3. **Pinned Vulnerable `npx -y mcp-remote@0.1.15`**:
   - Assert `match_static_config()` returns `matched_version == "0.1.15"`, `audit_server()` does **not** emit `SEC-STATIC-UNPINNED-PACKAGE`, and still emits `VULN-CVE-2025-6514`.
4. **Pinned Python `uvx mcp-server-fetch==1.2.0` vs. Unpinned `uvx mcp-server-fetch`**:
   - Assert pinned passes without unpinned warning, while unpinned triggers `SEC-STATIC-UNPINNED-PACKAGE`.
5. **Local Absolute Binary/Script (`python3 /opt/mcp/server.py`, `node /app/index.js`)**:
   - Assert local pinned paths do **not** trigger `SEC-STATIC-UNPINNED-PACKAGE` (zero false positives).
6. **CLI End-to-End (`verity scan --config-file ... --format json --fail-on-findings`)**:
   - Verify `SEC-STATIC-UNPINNED-PACKAGE` appears cleanly in `terminal`, `json`, `markdown`, and `html` reports with exit code `1`.

---

## 4. Acceptance Scenario with a Real MCP Package in Clean Container

Verify against real npm/Python MCP packages inside `tests/e2e_containers/` (`customer-full-workstation`):

1. **Container Config Setup (`tests/e2e_containers/verify_all_scenarios.sh`)**:
   - Configure three real server entries in `~/.cursor/mcp.json`:
     - `mcp-remote-pinned`: `npx -y mcp-remote@0.1.15 https://remote.example.com/sse` (pinned vulnerable real npm package -> must report `VULN-CVE-2025-6514` and **NOT** `SEC-STATIC-UNPINNED-PACKAGE`).
     - `mcp-remote-unpinned`: `npx -y mcp-remote https://remote.example.com/sse` (unpinned real npm package -> must report `SEC-STATIC-UNPINNED-PACKAGE`).
     - `local-clean-server`: `python3 /opt/fixtures/clean_stdio_mcp.py` (local script -> must report **neither**).
2. **Acceptance Command**:
   ```bash
   verity scan --config-file "$HOME/.cursor/mcp.json" --format json --output /tmp/out/unpinned_check.json --fail-on-findings
   ```
3. **Acceptance Assertions**:
   - Exits `1`.
   - `mcp-remote-pinned` produces `VULN-CVE-2025-6514` (no unpinned warning).
   - `mcp-remote-unpinned` produces `SEC-STATIC-UNPINNED-PACKAGE` with remediation advice.
   - `local-clean-server` produces `0` findings.
   - Full `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh` passes across all 4 containers.

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/unit/test_unpinned_package_detection.py -v
uv run pytest tests/
INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] `HybridDiscoveryMatcher.match_static_config()` no longer fabricates `versions[-1].version` or `"1.0.0"` for unpinned packages.
- [ ] `ConsolidatedSecurityAuditor` emits `SEC-STATIC-UNPINNED-PACKAGE` (`MEDIUM`) for floating `npx`/`uvx`/`@latest` configs and skips guessed-version OSV queries.
- [ ] Pinned packages (`@0.1.15`, `==1.2.0`) and local script paths (`python3 /path/...`) produce zero false positives.
- [ ] `tests/unit/test_unpinned_package_detection.py`, full `pytest tests/`, `ruff check src tests`, and `tests/e2e_containers/run_e2e.sh` all pass cleanly.
