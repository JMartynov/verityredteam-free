# M7: CLI Parity, ConsolidatedSecurityAuditor Wiring & YAML Config Support

- **Task ID**: `M7`
- **Priority**: `P0`
- **Status**: `Todo`
- **Dependencies**: None (`M1`–`M6` completed)
- **Blocks**: `M8`, `M9`, `M10`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Problem Statement & Context

A codebase-vs-documentation audit of `verity-redteam-core` revealed critical parity gaps between what the README/product promises for `verity scan` and what the CLI actually executes today:

1. **`verity scan` bypasses `ConsolidatedSecurityAuditor`**:
   - In `src/verity/cli.py` (`_collect_config_findings`, L155–L191; `_cmd_scan`, L281–L298), `verity scan` (both default 9-client discovery and `--config-file`) only calls `MultiClientConfigScanner` and passes `{"name": config.server_name, **raw}` to `StaticRuleEvaluator.scan_tool()`.
   - Meanwhile, `ConsolidatedSecurityAuditor` (`src/verity/discovery/auditor.py`, L27–L163) already implements:
     - Plaintext secret detection in `config.env` (`SEC-STATIC-SECRET-IN-CONFIG`, `FindingSeverity.HIGH`, redacted evidence `KEY=****`),
     - Unsafe shell execution wrapper detection (`SEC-STATIC-UNSAFE-SHELL-WRAPPER`, `FindingSeverity.MEDIUM` for `sh`/`bash`/`zsh`/`cmd`/`powershell`),
     - Hybrid tri-layer Passport fingerprinting (`HybridDiscoveryMatcher` / `mcp-fingerprints`), and
     - Offline OSV CVE correlation (`VulnerabilityLookupEngine` / `mcp-vulnerabilities`, e.g., catching `mcp-remote@0.1.15` / `CVE-2025-6514` as `VULN-<id>`).
   - Because `cli.py` never invokes `ConsolidatedSecurityAuditor`, running `verity scan` on a workstation config with leaked `env` credentials, raw `bash -c` wrappers, or known-vulnerable pinned npm/PyPI MCP packages reports **0 findings** unless a tool schema itself happens to match a static rule.
2. **YAML IDE configs silently fail**:
   - `MultiClientConfigScanner.get_standard_client_paths()` (`src/verity/discovery/config_scanner.py`, L153, L162–L163) registers `.continue/config.yaml` and `librechat.yaml`, yet `parse_config_file()` (`config_scanner.py`, L199–L204) and `_collect_config_findings()` (`cli.py`, L169–L177) only call `json.loads()`, silently returning `[]` or raising `Invalid JSON` on YAML configs.
3. **Stale CLI template in `ActiveExploitBridge`**:
   - `src/verity/discovery/active_bridge.py` (L44) defines `DEFAULT_CLI_COMMAND_TEMPLATE = "verity test --server '{package}' --vuln '{vuln_id}'"`, referencing `--server` and `--vuln` flags that do not exist in `src/verity/cli.py` (L506–L519).
4. **SARIF plugin entry-point mismatch**:
   - `_load_sarif_exporter()` (`src/verity/cli.py`, L46–L54) looks only for entry points named `"sarif"` or `"sarif_export"` in group `"verity.plugins"`, whereas `../verityredteam/pyproject.toml` registers `"pro"` (`verity_pro.plugin:register_pro_extensions`).

> **Scope Decision (Confirmed):** Fix these CLI parity bugs first (`M7`) before executing ground-zero empty-container verification (`M8`), demo GIF recording (`M9`), and customer README restructuring (`M10`), so every customer claim is 100% real and reproducible.

---

## 2. Requirements & Target Files

### 2.1 Wire `ConsolidatedSecurityAuditor` into `verity scan`
- **Files**: `src/verity/cli.py` (L155–L191, L233–L298, L488–L504), `src/verity/discovery/auditor.py` (L27–L175)
- **Requirements**:
  - Update `_collect_config_findings()` (or add a clean helper called by `_collect_scan_data()`) to run `ConsolidatedSecurityAuditor.audit_server(config, live_probe=...)` on every discovered `DiscoveredServerConfig` in addition to `StaticRuleEvaluator.scan_tool()` schema checks.
  - Ensure `verity scan` continues to run fast (`< 5s`) and **offline-safe by default** (i.e., do not block or crash if network is unavailable or offline caches are empty; gracefully reuse cached/bundled data from `mcp-fingerprints` / `mcp-vulnerabilities` / `data_fetcher.py`). Optionally expose `--live-probe` / `--offline` flags if needed without breaking existing default `verity scan` behavior.
  - **Strict Credential Scrubbing Guarantee**: Plaintext secret values from `config.env` MUST NEVER appear unmasked in `terminal`, `json`, `markdown`, or `html` output — only redacted evidence (`KEY=****`) and rule `SEC-STATIC-SECRET-IN-CONFIG`.
  - Normalize `SecurityAuditFinding` records seamlessly into `_normalize_finding()` so `Summary` severity counts (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), `--fail-on-findings` exit code `1`, `--format {terminal,json,markdown,html}`, and `--output` all work uniformly across config findings, static rule findings, OSV CVE findings, and `--path` AST findings.
  - Ensure `verity scan --config-file <path>` can match `mcp-remote@0.1.15` (and similar versioned npm/PyPI server specs in `command`/`args`) against offline OSV advisories from `mcp-vulnerabilities` / `data_fetcher.py`.

### 2.2 Support YAML Config Parsing for Continue & LibreChat
- **Files**: `src/verity/discovery/config_scanner.py` (L151–L240), `src/verity/cli.py` (L165–L178), `pyproject.toml` (only if a lightweight dependency like `PyYAML` is needed — note: evaluate whether `PyYAML` dependency is justified vs. minimal pure-Python subset, and document dependency choice clearly per `AGENTS.md`).
- **Requirements**:
  - Update `MultiClientConfigScanner.parse_config_file()` and `_collect_config_findings()` to parse `.yaml` / `.yml` files (`.continue/config.yaml`, `librechat.yaml`, or `--config-file path/to/config.yaml`) and extract declared MCP server configurations (`mcpServers` / `mcp_servers` / `servers`).
  - Handle malformed YAML gracefully (consistent with malformed JSON handling).

### 2.3 Fix `ActiveExploitBridge` CLI Command Template
- **Files**: `src/verity/discovery/active_bridge.py` (L41–L91)
- **Requirements**:
  - Replace `DEFAULT_CLI_COMMAND_TEMPLATE = "verity test --server '{package}' --vuln '{vuln_id}'"` with valid `verity` CLI syntax (`verity test --command ...` or `verity test --url ...` / valid subcommand flags matching `build_parser()` in `src/verity/cli.py`).
  - Keep `ActiveExploitPlan.to_dict()` schema compatible with callers in both `verityredteam-free` and `verityredteam`.

### 2.4 Align Pro SARIF Entry-Point Discovery (Zero Pro Coupling)
- **Files**: `src/verity/cli.py` (L46–L54)
- **Requirements**:
  - Keep zero imports from `verity_pro` or `verity_lite` (`AGENTS.md` hygiene rule).
  - Update `_load_sarif_exporter()` so that when a `verity.plugins` entry point (`sarif`, `sarif_export`, or `pro`) is installed and exposes a SARIF exporter attribute/callable (or plugin hook), `--format sarif` resolves cleanly without failing with `"verity-pro is installed but no SARIF exporter entry point is registered"`, while keeping exit code `2` + `PRO_FEATURE_REQUIRED` payload when no Pro plugin is installed.

### 2.5 Unit Tests
- **Files**: `tests/unit/test_cli_and_reporting.py`, `tests/unit/test_static_config_scanner.py` (or dedicated `tests/unit/test_cli_auditor_parity.py`)
- **Requirements**:
  - Test `verity scan --config-file` detects `SEC-STATIC-SECRET-IN-CONFIG` (`HIGH`) and asserts the raw secret value does **not** appear anywhere in `terminal`, `json`, `markdown`, or `html` outputs.
  - Test `verity scan --config-file` detects `SEC-STATIC-UNSAFE-SHELL-WRAPPER` (`MEDIUM`) on `bash -c ...` / `sh -c ...`.
  - Test `verity scan --config-file` flags known OSV CVEs (e.g., `mcp-remote` `0.1.15` -> `CVE-2025-6514`) using mocked/cached OSV engine without requiring live internet access in unit tests.
  - Test `verity scan --config-file` and `MultiClientConfigScanner.scan_all()` parse `.continue/config.yaml` and `librechat.yaml` and extract servers + secrets/shell wrappers.
  - Test `--fail-on-findings` returns exit code `1` for config, schema, and AST findings, and `0` when clean.

---

## 3. Verification Commands

Run in `verityredteam-free`:
```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv sync --extra dev
uv run ruff check src tests
uv run pytest tests/ -q
```

Run Pro regression check in companion `verityredteam` (per `AGENTS.md`):
```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam
uv run pytest tests/unit/test_unified_production_mcp_agent_tools.py -q
```

---

## 4. Acceptance Criteria

- [ ] `verity scan` (default workstation discovery and `--config-file`) invokes `ConsolidatedSecurityAuditor` and reports `SEC-STATIC-SECRET-IN-CONFIG`, `SEC-STATIC-UNSAFE-SHELL-WRAPPER`, static tool schema matches, and OSV CVE findings.
- [ ] Raw secret values from `config.env` never leak unredacted into `terminal`, `json`, `markdown`, or `html` outputs.
- [ ] `.continue/config.yaml` and `librechat.yaml` are parsed accurately in both `MultiClientConfigScanner.parse_config_file()` and `verity scan --config-file`.
- [ ] `ActiveExploitBridge.DEFAULT_CLI_COMMAND_TEMPLATE` references only valid `verity` CLI flags present in `src/verity/cli.py`.
- [ ] `_load_sarif_exporter()` cleanly handles both `sarif`/`sarif_export` and `pro` entry points while returning `PRO_FEATURE_REQUIRED` (exit `2`) when Pro is absent.
- [ ] Zero Pro/proprietary imports (`verity_pro`, `verity_lite`, `snowflake_guard`, `customer_lab`) exist in `verityredteam-free`.
- [ ] `uv run ruff check src tests` and `uv run pytest tests/ -q` pass 100%, and `verityredteam` Pro MCP agent tests pass with zero regressions.

---

## 5. Out of Scope

- Docker / empty-container verification suite (covered in `M8`).
- Animated GIF screencast recording (covered in `M9`).
- Rewriting `README.md` or adding doc-parity tests (covered in `M10`).
- Adding Pro-only features (`SnowflakeSecurityGuard`, live DB canary oracles, etc.) into `verityredteam-free`.
