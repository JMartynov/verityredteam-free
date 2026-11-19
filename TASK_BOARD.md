# Verity RedTeam Free — Engineering Task Board

> **Project**: Verity RedTeam (Free / Open-Core Edition)  
> **GitHub Project Board**: [Project #5: Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)  
> **Target Repository (Free Core)**: [`/Users/ivan/Project/3t.tools.intellij/verityredteam-free`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam-free) (`JMartynov/verityredteam-free`)  
> **Source Repository (Enterprise Pro)**: [`/Users/ivan/Project/3t.tools.intellij/verityredteam`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam)  
> **Status**: Completed (`v0.2.0` Published to PyPI & Verified)  
> **Target Baseline**: `v0.1.0` Baseline (Wave 1 `M1`–`M6`) / `v0.2.0` Released (`M7`–`M11`)  
> **Architecture Plan**: [`open_core_migration_plan.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam/docs/plans/open_core_migration_plan.md)  
> **Verification Plan**: [`architecture_review_and_verification_plan.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam/docs/plans/architecture_review_and_verification_plan.md)  

---

## 🗺️ High-Level Roadmap & 10-Task Delivery Pipeline

```mermaid
flowchart TD
    subgraph Phase1["Phase 1: Architecture & Decoupling"]
        M1["M1: Plugin Foundation & Core MCP Server<br/>(Decouple Pro imports, plugin_loader, stdlib JSON-RPC)"]
    end

    subgraph Phase2["Phase 2: Core Engine Migration"]
        M2["M2: Workstation Discovery & Static Screening<br/>(9 clients, 13 rules &lt;0.2ms, O(1) fingerprinting, OSV CVEs)"]
        M3["M3: Deterministic SQL AST Guard<br/>(245-line SqlSecurityGuard intact, Snowflake in Pro)"]
    end

    subgraph Phase3["Phase 3: Workspace Linkage & DX"]
        M4["M4: Link verity-pro to verity-core via uv Workspace<br/>(Single-source core, src/verity_pro/, zero duplicates)"]
        M5["M5: Net-New Free CLI &amp; 4 In-Memory Targets<br/>(uvx verity scan, verity test --demo, Rich formatters)"]
    end

    subgraph Phase4["Phase 4: Release Readiness"]
        M6["M6: CI/CD &amp; Launch Readiness<br/>(GitHub Actions matrix, wheel build, multi-tier regression)"]
    end

    subgraph Phase5["Phase 5: Customer Experience &amp; Ground-Zero Verification"]
        M7["M7: CLI Parity, Auditor Wiring &amp; YAML Configs<br/>(Secret scrubbing, shell wrappers, OSV CVEs, YAML)"]
        M8["M8: Empty-Container E2E Verification Suite<br/>(Wheel/PyPI install, real + fixture MCP targets)"]
        M9["M9: Dynamic Narrow Screencast GIF<br/>(VHS in Docker, ~860x440, 4 live scenarios)"]
        M10["M10: Customer-Focused README &amp; Parity Guard<br/>(6 pain points, verified outputs, CI doc parity)"]
        M11["M11: Credential Hardening, Polish &amp; v0.2.0 PyPI<br/>(DSN + value secrets, SPDX license, no_wrap, live PyPI)"]
        M12["M12: Real Streaming SSE &amp; Streamable HTTP Transport<br/>(text/event-stream, mcp-session-id, FastMCP E2E)"]
        M13["M13: Expose UCP Rug-Pull Detection<br/>(verity_security_scan action, --baseline CLI, mutable server E2E)"]
        M14["M14: True End-to-End VERITY_OFFLINE &amp; Air-Gapped Mode<br/>(Zero sockets in offline, expired-cache/baseline, --network none E2E)"]
        M15["M15: Flag Unpinned MCP Packages<br/>(SEC-STATIC-UNPINNED-PACKAGE, no guessed version, real npm E2E)"]
        M16["M16: Detect AWS / PEM / Cloud Tokens in Config Values<br/>(Shared credential registry, scrubbing, container E2E)"]
        M17["M17: Dialect-Aware SqlSecurityGuard<br/>(read=dialect, --dialect CLI &amp; verity_database_guard)"]
        M18["M18: Sync SARIF Driver Version with verity.__version__<br/>(Replace hardcoded 0.1.0, container SARIF E2E)"]
        M19["M19: Opt-In --live-probe Flag on verity scan<br/>(Fleet-wide live capability &amp; schema auditing)"]
        M20["M20: Add README.md Hero Badge Row<br/>(PyPI, Python 3.12+, Apache-2.0, CI &amp; parity guard)"]
        M21["M21: Sync README Tables, demo.tape Scene 4 &amp; demo.gif<br/>(Un-ellipsized v0.2.0 snapshots &amp; 4-target demo GIF)"]
        M22["M22: GitHub Release for v0.2.0 &amp; Workflow Guard<br/>(Guard duplicate PyPI trigger, publish v0.2.0 notes)"]
        M23["M23: Remove Stale 'Not Yet on PyPI' Caveat<br/>(Direct PyPI quickstart, collapsible source build)"]
        M24["M24: Container E2E for DSN, CUSTOM_FIELD &amp; Live DVMCP<br/>(DATABASE_URL DSN, sk- leak checks, live DVMCP stdio)"]
        M25["M25: Nightly schedule Trigger on e2e-containers.yml<br/>(cron 0 4 * * * upstream drift detection)"]
        M26["M26: Upgrade actions/checkout &amp; setup-uv Pins<br/>(Node-24-ready pins across all 4 workflows)"]
        M27["M27: Guard uv build in run_e2e.sh When INSTALL_SOURCE=pypi<br/>(Skip wheel build in PyPI mode, purge stale wheels)"]
        M28["M28: Fix Retired verity-core Name in AGENTS.md<br/>(Update AGENTS.md &amp; extend doc parity guard)"]
        M29["M29: Exact GitHub Project #5 Item Links Across TASK_BOARD.md<br/>(Backfill M1-M11 PVTI_... IDs &amp; parity guard)"]
    end

    M1 --> M2
    M1 --> M3
    M2 --> M4
    M3 --> M4
    M4 --> M5
    M5 --> M6
    M6 --> M7
    M7 --> M8
    M8 --> M9
    M8 --> M10
    M9 --> M10
    M10 --> M11
```

---

## 📋 Task Matrix & Status Overview

| Task Key | Task Title | Architectural Scope | Task Spec | Status | GitHub Project #5 Item |
| :---: | :--- | :--- | :--- | :---: | :---: |
| **M1** | **Plugin Foundation & Core MCP Server** | Plugin protocols, entry points, stdlib JSON-RPC MCP server | Inline below | `Done` | [View Item #M1](https://github.com/users/JMartynov/projects/5) |
| **M2** | **Workstation Discovery & Static Screening** | 9-client scanner, 13-rule StaticRuleEvaluator, fingerprinting, OSV cache | Inline below | `Done` | [View Item #M2](https://github.com/users/JMartynov/projects/5) |
| **M3** | **Deterministic SQL AST Guard** | Cohesive 245-line `SqlSecurityGuard` (`sqlglot`), Pro Snowflake guard | Inline below | `Done` | [View Item #M3](https://github.com/users/JMartynov/projects/5) |
| **M4** | **Link `verity-pro` to `verity-core` via `uv` Workspace** | `[tool.uv.sources]`, `src/verity_pro/` packaging, remove duplicated core | Inline below | `Done` | [View Item #M4](https://github.com/users/JMartynov/projects/5) |
| **M5** | **Net-New Free CLI & 4 In-Memory Synthetic Targets** | `verity scan`, `test --demo`, `serve`, Rich tables, 4 zero-Docker targets | Inline below | `Done` | [View Item #M5](https://github.com/users/JMartynov/projects/5) |
| **M6** | **CI/CD & Launch Readiness** | Multi-platform GitHub Actions matrix, `uv build` wheel, Pro regression | Inline below | `Done` | [View Item #M6](https://github.com/users/JMartynov/projects/5) |
| **M7** | **CLI Parity, `ConsolidatedSecurityAuditor` Wiring & YAML Config Support** | Wire secret scrubbing, shell wrappers, OSV CVEs & YAML parsing into `verity scan` | [M7_cli_parity_and_auditor_wiring.md](docs/tasks/M7_cli_parity_and_auditor_wiring.md) | `Done` | [View Item #M7](https://github.com/users/JMartynov/projects/5) |
| **M8** | **Ground-Zero Empty-Container E2E Customer Verification Suite** | Clean-room Docker matrix (`wheel`/`pypi`), real + fixture MCP targets, 6 scenarios | [M8_empty_container_e2e_verification.md](docs/tasks/M8_empty_container_e2e_verification.md) | `Done` | [View Item #M8](https://github.com/users/JMartynov/projects/5) |
| **M9** | **Dynamic, Narrow Terminal Screencast GIF (Charmbracelet VHS in Docker)** | Reproducible VHS `.tape` (`~860x440`), 4 live scenes, `gifsicle`-optimized `demo.gif` | [M9_dynamic_narrow_demo_gif.md](docs/tasks/M9_dynamic_narrow_demo_gif.md) | `Done` | [View Item #M9](https://github.com/users/JMartynov/projects/5) |
| **M10** | **Customer-Focused `README.md` Restructure & CLI Documentation Parity Test** | Pain-point-first README with container-verified outputs, `demo.gif`, CI parity test | [M10_customer_readme_restructure_and_parity.md](docs/tasks/M10_customer_readme_restructure_and_parity.md) | `Done` | [View Item #M10](https://github.com/users/JMartynov/projects/5) |
| **M11** | **Credential Detection Hardening, Packaging/Display Polish & `v0.2.0` PyPI Release** | DSN & value-pattern secret checks, SPDX license, `Rule` `no_wrap=True`, `v0.2.0` publish + live PyPI E2E | [M11_credential_hardening_polish_and_v020_release.md](docs/tasks/M11_credential_hardening_polish_and_v020_release.md) | `Done` | [View Item #M11](https://github.com/users/JMartynov/projects/5) |
| **M12** | **Real Streaming SSE (`text/event-stream`) & Streamable HTTP Transport Support** | Incremental SSE frame parser, Streamable HTTP `mcp-session-id`, legacy SSE endpoint, unit tests & real `FastMCP` E2E | [M12_streaming_sse_streamable_http_transport.md](docs/tasks/M12_streaming_sse_streamable_http_transport.md) | `Done` | [View Item #M12](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKPNQ0`) |
| **M13** | **Expose UCP Rug-Pull Detection (`detect_rug_pull`) in `verity_security_scan` & CLI** | `detect_rug_pull` MCP action, `verity test --save-baseline`/`--baseline`, unit tests & mutable server E2E | [M13_expose_ucp_rug_pull_detection.md](docs/tasks/M13_expose_ucp_rug_pull_detection.md) | `Done` | [View Item #M13](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKPQE0`) |
| **M14** | **True End-to-End `VERITY_OFFLINE` & Air-Gapped Cold-Start Baseline Support** | Zero-socket `VERITY_OFFLINE` across `data_fetcher`/matchers, expired-cache/baseline, unit tests & `--network none` E2E | [M14_true_offline_airgapped_mode.md](docs/tasks/M14_true_offline_airgapped_mode.md) | `Done` | [View Item #M14](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKPSWU`) |
| **M15** | **Flag Unpinned MCP Packages (`SEC-STATIC-UNPINNED-PACKAGE`) Instead of Guessing Latest Version** | Return `None` for unpinned version, emit `SEC-STATIC-UNPINNED-PACKAGE`, unit tests & real `mcp-remote` E2E | [M15_unpinned_mcp_package_detection.md](docs/tasks/M15_unpinned_mcp_package_detection.md) | `Done` | [View Item #M15](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKPUAU`) |
| **M16** | **Detect AWS `AKIA…` Keys, PEM Private Keys & Cloud Tokens in MCP Config Values** | Shared credential pattern registry, extended key names, full scrubbing, unit tests & container E2E | [M16_cloud_credential_pattern_detection.md](docs/tasks/M16_cloud_credential_pattern_detection.md) | `Done` | [View Item #M16](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKPito`) |
| **M17** | **Dialect-Aware `SqlSecurityGuard` (`--dialect` CLI & `verity_database_guard` Support)** | Pass `read=dialect` (default `postgres`), expose `--dialect` on `verity test --sql` & `verity_database_guard`, unit tests & SQLite/MySQL E2E | [M17_dialect_aware_sql_security_guard.md](docs/tasks/M17_dialect_aware_sql_security_guard.md) | `Done` | [View Item #M17](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKQV5Y`) |
| **M18** | **Sync SARIF Exporter Driver Version with `verity.__version__`** | Replace hardcoded `"0.1.0"` in `_stdlib_sarif_exporter` with `verity.__version__`, unit tests & container SARIF E2E | [M18_sarif_driver_version_sync.md](docs/tasks/M18_sarif_driver_version_sync.md) | `Done` | [View Item #M18](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKQWdQ`) |
| **M19** | **Opt-In `--live-probe` Flag on `verity scan` for Fleet-Wide Live Capability Auditing** | Expose `--live-probe` on `verity scan`, thread into `auditor.audit_server()`, isolate dead servers, unit tests & container E2E | [M19_scan_live_probe_flag.md](docs/tasks/M19_scan_live_probe_flag.md) | `Done` | [View Item #M19](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKQWho`) |
| **M20** | **Add `README.md` Hero Badge Row (PyPI, License, Python 3.12+, CI) & Parity Guard** | Add 4-badge Hero row above tagline in `README.md`, doc parity guard & wheel metadata container check | [M20_readme_hero_badges.md](docs/tasks/M20_readme_hero_badges.md) | `Done` | [View Item #M20](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKQWlY`) |
| **M21** | **Sync `README.md` Verbatim Tables, `demo.tape` Scene 4 & `demo.gif` to `v0.2.0` Un-Ellipsized Output** | Sync two ellipsized README tables to snapshots `01`/`02`, run full `verity test --demo` in Scene 4, re-record `demo.gif` & parity tests | [M21_sync_demo_gif_and_readme_tables.md](docs/tasks/M21_sync_demo_gif_and_readme_tables.md) | `Done` | [View Item #M21](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKQWqY`) |
| **M22** | **Publish GitHub Release for `v0.2.0` & Guard Duplicate PyPI Workflow Trigger** | Guard `.github/workflows/workflow.yaml` duplicate PyPI upload, publish `v0.2.0` GitHub Release notes, workflow unit test & PyPI E2E | [M22_github_release_v020_and_workflow_guard.md](docs/tasks/M22_github_release_v020_and_workflow_guard.md) | `Done` | [View Item #M22](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKQWuQ`) |
| **M23** | **Remove Stale "If the package is not yet on PyPI…" Caveat from `README.md`** | Make PyPI primary install path, move source build into `<details>`, add parity test & cold PyPI container check | [M23_remove_stale_pypi_caveat.md](docs/tasks/M23_remove_stale_pypi_caveat.md) | `Done` | [View Item #M23](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKQWx4`) |
| **M24** | **Extend Container E2E (`verify_all_scenarios.sh`) for DSN Credentials, `CUSTOM_FIELD=sk-…` & Live DVMCP `stdio` Probing** | Add `DATABASE_URL` DSN + safe twin, `CUSTOM_FIELD=sk-…` leak assertions, and live DVMCP `verity test --command` probing | [M24_container_e2e_dsn_and_live_dvmcp.md](docs/tasks/M24_container_e2e_dsn_and_live_dvmcp.md) | `Done` | [View Item #M24](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKQW1E`) |
| **M25** | **Add Nightly `schedule` Trigger (`cron: '0 4 * * *'`) to `e2e-containers.yml`** | Add nightly `0 4 * * *` cron trigger to `e2e-containers.yml` and workflow hygiene unit test | [M25_nightly_e2e_containers_cron.md](docs/tasks/M25_nightly_e2e_containers_cron.md) | `Done` | [View Item #M25](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKQW4w`) |
| **M26** | **Upgrade `actions/checkout` and `astral-sh/setup-uv` Pins Across All GitHub Actions Workflows** | Upgrade `actions/checkout` and `astral-sh/setup-uv` to Node-24-ready versions across all 4 workflows + unit test | [M26_upgrade_github_actions_pins.md](docs/tasks/M26_upgrade_github_actions_pins.md) | `Done` | [View Item #M26](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKQW9A`) |
| **M27** | **Guard `uv build` & Local Wheel Staging in `run_e2e.sh` When `INSTALL_SOURCE=pypi`** | Guard `uv build` behind `INSTALL_SOURCE=wheel`, clean stale wheels, unit test & dual-mode container E2E | [M27_guard_uv_build_in_run_e2e.md](docs/tasks/M27_guard_uv_build_in_run_e2e.md) | `Done` | [View Item #M27](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKQXBQ`) |
| **M28** | **Fix Retired `verity-core` Package Name in `AGENTS.md` & Extend Documentation Parity Guard** | Replace `verity-core` with `verity-redteam-core` in `AGENTS.md` and extend `test_no_stale_package_references` | [M28_fix_agents_md_retired_package_name.md](docs/tasks/M28_fix_agents_md_retired_package_name.md) | `Done` | [View Item #M28](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKQXFA`) |
| **M29** | **Populate Exact GitHub Project #5 Item IDs & Links Across `TASK_BOARD.md` (`M1`–`M29`)** | Harvest `PVTI_…` item IDs via `gh project item-list 5`, backfill `M1`–`M11` rows/sections, add dynamic parity guard | [M29_exact_task_board_project_links.md](docs/tasks/M29_exact_task_board_project_links.md) | `Todo` | [View Item #M29](https://github.com/users/JMartynov/projects/5) (`PVTI_lAHOD-xmQM4Br351zhKQXJA`) |

---

## 🏗️ Detailed Migration Task Specifications

---

### M1: Plugin Foundation & Core MCP Server

#### Master Plan Reference
- [`open_core_migration_plan.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam/docs/plans/open_core_migration_plan.md) (Phase 1, Task PRO-1 & PRO-2; Phase 2, Task FREE-1 & FREE-5)
- [`architecture_review_and_verification_plan.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam/docs/plans/architecture_review_and_verification_plan.md) (Gap #1: Zero-framework stdlib JSON-RPC 2.0; Gap #2: Decouple 5 hardcoded Pro imports)

#### Context
Decouple Pro internals behind Python `importlib.metadata.entry_points(group="verity.plugins")` and pure-stdlib JSON-RPC 2.0 MCP server (`server.py`, NO `FastMCP`/`click`/`pydantic` bloat). Establishes the foundational runtime abstraction barrier so that `verity-core` can run completely standalone without any proprietary or heavy external dependencies, while allowing `verity-pro` to dynamically register enterprise extensions when present.

#### Subtask A (`[PRO]` — `verityredteam`)
- Add `src/verity/mcp_server/plugin_loader.py` implementing `discover_and_load_plugins(dispatcher)`.
- Expand `src/verity/mcp_server/protocols.py` to define:
  - `DatabaseOracleProtocol`
  - `GuardExtensionProtocol`
  - `PlanProviderProtocol`
- Decouple the 5 hardcoded Pro imports with `PRO_FEATURE_REQUIRED` graceful degradation:
  1. `DatabaseVerificationOracle` in `src/verity/mcp_server/tools.py#L54`
  2. `SnowflakeSecurityGuard` in `src/verity/mcp_server/handlers/database_guard.py#L8`
  3. `deterministic_plans` (`get_deterministic_plan`) in `src/verity/mcp_server/handlers/database_oracle.py#L19`
  4. `CANARY_MANIFEST` and `_audit_and_generate_exploit_plan` in `src/verity/mcp_server/handlers/database_oracle.py#L43,L71`
  5. `RemediationProProvider` in `src/verity/mcp_server/handlers/remediation.py`
- Add `tests/unit/test_core_degradation.py` validating that when Pro plugins are not loaded, Pro actions return clean `PRO_FEATURE_REQUIRED` payloads instead of `ImportError`.

#### Subtask B (`[FREE]` — `verityredteam-free`)
- Scaffold `pyproject.toml` with:
  - `name = "verity-core"`
  - `requires-python = ">=3.12,<3.15"`
  - Minimal dependencies: `sqlglot>=25.0.0`, `packaging>=24.0`, `mcp-fingerprints>=1.3.6`, `mcp-vulnerabilities>=1.2.2`, `rich>=13.7.0`
- Create `README.md` and `LICENSE` (Apache-2.0).
- Migrate pure-stdlib `src/verity/mcp_server/`:
  - `server.py` (pure stdlib `json`, `http.server.ThreadingHTTPServer` JSON-RPC 2.0)
  - `schemas.py`, `protocols.py`, `plugin_loader.py`, `bootstrap.py`, `stream_logger.py`, `tools.py`, `handlers/`
- Add test suite `tests/unit/test_mcp_server_handshake.py`.

#### Verification (Both Repos)
- **`verityredteam`**:
  ```bash
  uv run pytest tests/unit/test_unified_production_mcp_agent_tools.py -q
  # Pass condition: 17 passed
  uv run pytest tests/unit/test_core_degradation.py -q
  # Pass condition: all degradation scenarios return PRO_FEATURE_REQUIRED
  ```
- **`verityredteam-free`**:
  ```bash
  cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
  uv sync
  uv run pytest tests/unit/test_mcp_server_handshake.py -q
  uv run python -m verity.mcp_server.server --help
  ```

#### Acceptance Criteria
- [ ] Pro MCP agent tools pass 17/17 without regressions in `verityredteam`.
- [ ] `verity-core` MCP server initializes with zero Pro imports and responds to stdio JSON-RPC handshake.
- [ ] Plugin loader discovers plugins registered under entry-point group `"verity.plugins"`.
- [ ] All missing Pro features return `PRO_FEATURE_REQUIRED` gracefully without `ImportError`.

---

### M2: Workstation Discovery & Static Screening

#### Master Plan Reference
- [`open_core_migration_plan.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam/docs/plans/open_core_migration_plan.md) (Phase 2, Task FREE-2 & FREE-3)
- [`architecture_review_and_verification_plan.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam/docs/plans/architecture_review_and_verification_plan.md) (Gap #4: Cover all 13 exact `VERITY-STATIC-*` rules; Gap #2: Parameterize `active_bridge.py`)

#### Context
Deliver the 5-second single-player audit: 9-client workstation secret scanning, 13-rule sub-millisecond `StaticRuleEvaluator`, O(1) fingerprinting, and OSV CVE lookup. Provides instantaneous developer value without requiring any Docker containers, databases, or cloud accounts.

#### Subtask A (`[PRO]` — `verityredteam`)
- Parameterize `recommended_cli_command` in `src/verity/discovery/active_bridge.py` (remove hardcoded `python -m verity_lite.cli`).
- Prepare `verity_pro` import compatibility layer.
- Ensure unified MCP agent scan actions remain fully operational.

#### Subtask B (`[FREE]` — `verityredteam-free`)
- Migrate `src/verity/discovery/`:
  - `config_scanner.py` (9 workstation clients: Cursor, Claude Desktop, VS Code Cline/Roo, Windsurf, Zed, etc.)
  - `models.py`
  - `transports/` (`stdio.py`, `sse.py`)
  - `matcher.py`
  - `auditor.py` (without SARIF/Pro exports)
  - `active_bridge.py` (parameterized CLI command template)
- Migrate `src/verity/scanner/`:
  - `static_rules.py` covering all 13 `VERITY-STATIC-*` rules:
    - `VERITY-STATIC-INJECTION-OVERRIDE`
    - `VERITY-STATIC-INJECTION-DELIMITER`
    - `VERITY-STATIC-TOOL-POISONING`
    - `VERITY-STATIC-EXFIL-WEBHOOK`
    - `VERITY-STATIC-EXFIL-COVERT`
    - `VERITY-STATIC-METADATA-SSRF`
    - `VERITY-STATIC-CREDENTIAL-HARVESTING`
    - `VERITY-STATIC-SHELL-DROPPER`
    - `VERITY-STATIC-SHELL-REVERSE-PIPE`
    - `VERITY-STATIC-CODE-EXECUTION`
    - `VERITY-STATIC-SHELL-DESTRUCTIVE`
    - `VERITY-STATIC-SQL-INJECTION-SCHEMA`
    - `VERITY-STATIC-SCRIPT-INJECTION-XSS`
  - `models.py`, `rules.py`, `python_ast.py`, `engine.py`, `readonly_guard.py`
- Migrate supporting data and lookup modules:
  - `src/verity/fingerprint/` (canonical SHA-256 tool hashing)
  - `src/verity/lookup/` (OSV CVE offline lookup via `mcp-vulnerabilities`)
  - `src/verity/ucp/`
  - `src/verity/data_fetcher.py`
- Add unit tests: `tests/unit/test_config_scanner.py` and `tests/unit/test_static_rules.py`.

#### Verification (Both Repos)
- **`verityredteam`**:
  ```bash
  uv run pytest tests/unit/test_unified_production_mcp_agent_tools.py -q
  # Pass condition: 17 passed
  ```
- **`verityredteam-free`**:
  ```bash
  cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
  uv run pytest tests/unit/test_config_scanner.py tests/unit/test_static_rules.py -q
  # Pass condition: All tests pass, <0.2ms/schema SLA verified
  ```

#### Acceptance Criteria
- [ ] 9 workstation client config paths scanned accurately with credential scrubbing.
- [ ] All 13 `VERITY-STATIC-*` rules evaluate malicious schema fixtures in `<0.2ms` per schema.
- [ ] Canonical fingerprinting and OSV vulnerability lookup function offline with zero network latency.
- [ ] Zero Pro regressions in `verityredteam` MCP test suite.

---

### M3: Deterministic SQL AST Guard

#### Master Plan Reference
- [`open_core_migration_plan.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam/docs/plans/open_core_migration_plan.md) (Phase 2, Task FREE-4)
- [`architecture_review_and_verification_plan.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam/docs/plans/architecture_review_and_verification_plan.md) (Gap #5: Move 245-line `SqlSecurityGuard` intact; keep Snowflake in Pro)

#### Context
Move the cohesive 245-line `SqlSecurityGuard` (`sqlglot`) intact to Free while keeping `SnowflakeSecurityGuard` strictly in Pro. Establishes a clean division: deterministic SQL AST validation (Free) vs. cloud data warehouse RBAC and time-travel policies (Pro).

#### Subtask A (`[PRO]` — `verityredteam`)
- Ensure `src/verity/mcp_server/handlers/database_guard.py` cleanly delegates SQL checks to `SqlSecurityGuard` and Snowflake checks to the registered `"snowflake"` guard plugin.
- Keep `SnowflakeSecurityGuard` isolated in Pro with RBAC role escalation, Time-Travel `AT(TIMESTAMP => ...)`, stage isolation, and tag masking checks intact.
- Verify Pro database guard actions return expected results across both SQL and Snowflake policies.

#### Subtask B (`[FREE]` — `verityredteam-free`)
- Migrate `src/verity/mcp_library/sql_guard.py` intact:
  - `validate_parameterized_query`
  - `validate_single_select_statement` (comment-splitting neutralization + `TokenType.SEMICOLON` + catalog blocklist)
  - `apply_projection`
  - `enforce_tenant_filter`
  - `validate_identifier_allowlist`
  - `validate_statement_timeout`
  - `sanitize_like_pattern` (escapes `\`, `%`, `_`)
- Add unit test suite: `tests/unit/test_sql_guard.py` testing SQL injection evasion vectors, stacked queries, comment tricks, and tenant isolation.

#### Verification (Both Repos)
- **`verityredteam`**:
  ```bash
  uv run pytest tests/unit/test_unified_production_mcp_agent_tools.py -k "database_guard" -q
  # Pass condition: 5 passed
  ```
- **`verityredteam-free`**:
  ```bash
  cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
  uv run pytest tests/unit/test_sql_guard.py -q
  # Pass condition: 100% passed on SQL AST tests
  ```

#### Acceptance Criteria
- [ ] `SqlSecurityGuard` completely blocks comment-split queries (`SEL/**/ECT`), stacked queries (`; DROP TABLE`), and unauthorized catalog accesses.
- [ ] Tenant filtering and projection masking apply correctly via `sqlglot` AST transformation.
- [ ] Pro database guard retains 5/5 passing unit tests for both standard SQL and Snowflake policies.

---

### M4: Link `verity-pro` to `verity-core` via `uv` Workspace

#### Master Plan Reference
- [`open_core_migration_plan.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam/docs/plans/open_core_migration_plan.md) (Phase 3, Task PRO-3, PRO-4 & PRO-5)
- [`architecture_review_and_verification_plan.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam/docs/plans/architecture_review_and_verification_plan.md) (Gap #3: Namespace collision resolution, single-source core)

#### Context
Eliminate duplicate code in `verityredteam` by mounting `verityredteam-free` as an editable dependency via `[tool.uv.sources]` and moving Pro-only modules into `src/verity_pro/`. Resolves Python namespace collisions between the two repositories and creates a seamless local developer workspace.

#### Subtask A (`[PRO]` — `verityredteam`)
- Create `src/verity_pro/plugin.py` with `register_pro_extensions(dispatcher)`.
- Move Pro-only modules into `src/verity_pro/`:
  - `snowflake_guard.py`
  - `fixtures/customer_lab/`
  - `automation/`
  - `vaib/`
  - `penetration/`
  - `oracles/` & canary verification modules
  - `compliance/sarif.py` (OASIS SARIF v2.1.0 exporter)
- Configure `pyproject.toml` in `verityredteam`:
  ```toml
  [project.entry-points."verity.plugins"]
  enterprise = "verity_pro.plugin:register_pro_extensions"

  [tool.uv.sources]
  verity-core = { path = "../verityredteam-free", editable = true }
  ```
- Remove duplicated core files from `verityredteam/src/verity/` so imports cleanly resolve to `verity-core`.

#### Subtask B (`[FREE]` — `verityredteam-free`)
- Stabilize `verity-core` public API exports in `src/verity/__init__.py`.
- Tag version `v0.1.0-alpha`.
- Ensure clean standalone packaging that can be consumed as an editable or published wheel.

#### Verification (Both Repos)
- **`verityredteam`**:
  ```bash
  cd /Users/ivan/Project/3t.tools.intellij/verityredteam
  uv sync
  uv run pytest tests/unit/test_unified_production_mcp_agent_tools.py -q
  # Pass condition: 17 passed
  uv run pytest tests/unit --ignore=tests/unit/test_demo_sh_smoke.py --ignore=tests/unit/test_demo_acceptance.py --ignore=tests/unit/test_agent_router.py -q
  # Pass condition: 551 passed
  uv run ruff check src tests
  # Pass condition: 0 errors
  ```
- **`verityredteam-free`**:
  ```bash
  cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
  uv run pytest tests/ -q
  uv run ruff check src tests
  # Pass condition: 100% green
  ```

#### Acceptance Criteria
- [ ] `verityredteam` imports `verity-core` via `uv` workspace editable linkage with zero duplicate core code.
- [ ] All 17 production MCP agent tool tests and 551 unit regression tests pass in `verityredteam`.
- [ ] Ruff check passes with 0 lint or formatting errors across both codebases.

---

### M5: Net-New Free CLI & 4 In-Memory Synthetic Targets

#### Master Plan Reference
- [`open_core_migration_plan.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam/docs/plans/open_core_migration_plan.md) (Phase 2, Task FREE-6 & FREE-7; Section 8: PLG Strategy)
- [`architecture_review_and_verification_plan.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam/docs/plans/architecture_review_and_verification_plan.md) (Gap #6: Net-new CLI reporting and zero-Docker synthetic targets)

#### Context
Deliver the zero-Docker "5-Second Magic Moment" (`uvx verity scan`, `verity test --demo`, `verity serve`) with Rich terminal Pass/Fail tables and subtle Pro upgrade prompts. Provides the viral developer adoption hook while cleanly funneling enterprise users to Pro.

#### Subtask A (`[PRO]` — `verityredteam`)
- Verify that `verity` CLI automatically unlocks Pro capabilities (e.g. SARIF export, Snowflake guards, live database oracles) when `verity-pro` is installed in the same environment.
- Confirm backwards compatibility for `verity_lite.cli` invocations.

#### Subtask B (`[FREE]` — `verityredteam-free`)
- Implement `src/verity/cli.py` with commands:
  - `verity scan` (workstation client configs & tool schemas)
  - `verity test` (probing target MCP servers over stdio or SSE, plus `--demo` mode)
  - `verity serve` (launch local stdio MCP server)
- Implement `src/verity/reporting/`:
  - `terminal.py` (Rich tables with severity badges, findings summary, and upgrade hints)
  - `markdown.py` (GitHub/GitLab PR comment-ready markdown)
  - `html.py` (standalone offline single-file HTML report)
- Implement `src/verity/targets/` (4 net-new zero-Docker in-memory synthetic targets):
  1. `sqlite_target.py` (SQL injection via unescaped query parameter)
  2. `postgres_target.py` (basic read / BOLA simulation)
  3. `mongo_target.py` (basic Mongo `$regex` / operator injection)
  4. `code_exec_target.py` (Python `eval` code execution dropper)
- Add unit tests in `tests/unit/test_cli.py` and `tests/unit/test_targets.py`.

#### Verification (Both Repos)
- **`verityredteam`**:
  ```bash
  uv run pytest tests/unit/test_unified_production_mcp_agent_tools.py -q
  # Pass condition: 17 passed
  ```
- **`verityredteam-free`**:
  ```bash
  cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
  uv run verity scan --help
  uv run verity test --demo
  uv run pytest tests/ -q
  # Pass condition: CLI runs, demo target catches simulated vulnerabilities, tests green
  ```

#### Acceptance Criteria
- [ ] `verity scan` completes in `<5s` and outputs Rich formatted summary table with actionable advice.
- [ ] `verity test --demo` launches in-memory targets and validates probe responses without external dependencies.
- [ ] Subtle Pro upsell hints appear when cloud warehouse connection strings or advanced compliance formats are encountered.

---

### M6: CI/CD & Launch Readiness

#### Master Plan Reference
- [`open_core_migration_plan.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam/docs/plans/open_core_migration_plan.md) (Phase 3, Task PRO-5; Section 9: Safety Matrix)
- [`architecture_review_and_verification_plan.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam/docs/plans/architecture_review_and_verification_plan.md) (Section 3: Gated Verification Matrix)

#### Context
Automate quality gates on both repositories and prepare public launch assets. Ensures continuous regression defense across both Open Core and Enterprise Pro, verifying wheel packaging and public documentation.

#### Subtask A (`[PRO]` — `verityredteam`)
- Run full multi-tier regression:
  - `./scripts/lite/test.sh unit`
  - `./scripts/lite/test.sh acceptance` (when Docker lab is active)
- Verify end-to-end compatibility of unified production MCP agent tools.

#### Subtask B (`[FREE]` — `verityredteam-free`)
- Add `.github/workflows/ci.yml`:
  - Python 3.12 and 3.13 test matrix on Ubuntu, macOS, and Windows runners
  - Quality checks: `ruff check`, `ruff format --check`, `pytest`
- Polish `README.md` with quickstart instructions (`uvx verity scan`), architecture overview, and feature comparison table (Free vs Pro).
- Verify packaging wheel build via `uv build`.

#### Verification (Both Repos)
- **`verityredteam`**:
  ```bash
  ./scripts/lite/test.sh unit
  # Pass condition: 100% pass on unit regression
  ```
- **`verityredteam-free`**:
  ```bash
  cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
  uv build
  uv run ruff check src tests
  uv run pytest tests/ -q
  # Pass condition: Clean wheel build, ruff passes, all tests pass
  ```

#### Acceptance Criteria
- [ ] GitHub Actions CI runs clean on Python 3.12 and 3.13.
- [ ] `uv build` produces a valid installable wheel (`dist/verity_core-*.whl`).
- [ ] Pro unit and acceptance suites pass with zero regressions.
- [ ] Public documentation accurately reflects the open-core boundary and quickstart workflow.

---

## 🚀 Wave 2: Customer Experience, Ground-Zero Verification & Launch Polish

---

### M7: CLI Parity, `ConsolidatedSecurityAuditor` Wiring & YAML Config Support

#### Task Spec
- [`docs/tasks/M7_cli_parity_and_auditor_wiring.md`](docs/tasks/M7_cli_parity_and_auditor_wiring.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKMCKw`)

#### Context
Today `verity scan` (`src/verity/cli.py`) bypasses `ConsolidatedSecurityAuditor` (`src/verity/discovery/auditor.py`), silently skips `.continue/config.yaml` and `librechat.yaml`, leaves a stale `--server`/`--vuln` template in `src/verity/discovery/active_bridge.py`, and checks only `"sarif"`/`"sarif_export"` in `_load_sarif_exporter()`. Fixing these CLI parity gaps first guarantees every customer-facing promise passes ground-zero verification in `M8` and `M10`.

#### Key Deliverables
- Wire `ConsolidatedSecurityAuditor` into `verity scan` (workstation default & `--config-file`) for plaintext secret scrubbing (`SEC-STATIC-SECRET-IN-CONFIG`), raw shell wrapper checks (`SEC-STATIC-UNSAFE-SHELL-WRAPPER`), Passport fingerprinting, and offline OSV CVE correlation (`VULN-*`).
- Add YAML parsing support for `.continue/config.yaml` and `librechat.yaml` in `config_scanner.py` and `cli.py`.
- Replace stale `ActiveExploitBridge.DEFAULT_CLI_COMMAND_TEMPLATE` flags with valid `verity` CLI syntax and align `_load_sarif_exporter()` entry-point discovery.
- Add unit tests covering secret non-leakage across all output formats (`terminal`, `json`, `markdown`, `html`), shell wrappers, OSV CVEs, YAML configs, and `--fail-on-findings`.

#### Verification
```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/ -q

cd /Users/ivan/Project/3t.tools.intellij/verityredteam
uv run pytest tests/unit/test_unified_production_mcp_agent_tools.py -q
```

#### Acceptance Criteria
- [x] `verity scan` reports scrubbed config secrets (`****`), shell wrappers, static schema findings, and offline OSV CVEs.
- [x] Raw config secrets never appear unmasked in `terminal`, `json`, `markdown`, or `html` output.
- [x] YAML configs for Continue and LibreChat parse cleanly via `scan_all()` and `--config-file`.
- [x] Zero Pro imports exist in `verityredteam-free`, and Pro MCP agent tests pass with zero regressions.

---

### M8: Ground-Zero Empty-Container E2E Customer Verification Suite

#### Task Spec
- [`docs/tasks/M8_empty_container_e2e_verification.md`](docs/tasks/M8_empty_container_e2e_verification.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKMCQA`)

#### Context
Validate every customer workflow from scratch inside empty Docker containers with zero pre-installed `verity`, zero editable host mounts, and zero host caches — installing `verity-redteam-core` (`INSTALL_SOURCE=wheel` or `pypi`) alongside both real public vulnerable MCP packages and self-contained vulnerable fixtures.

#### Key Deliverables
- 4-container verification matrix under `tests/e2e_containers/`: `customer-pip` (`python:3.12-slim-bookworm`), `customer-uvx` (`ghcr.io/astral-sh/uv:python3.12-bookworm-slim`), `customer-full-workstation` (`ubuntu:24.04`), and isolated `target-sse-lab`.
- Ground-zero setup of pinned real targets (`mcp-remote@0.1.15` for `CVE-2025-6514`, pinned DVMCP) AND deterministic fixtures (stdio/SSE poisoned servers, unsafe AST handlers, realistic IDE configs, adversarial SQL corpus).
- `tests/e2e_containers/verify_all_scenarios.sh` exercising all 6 customer scenarios (workstation scan, live stdio/SSE probing, SQL AST guard CLI + Python API, Python AST CI gate, 4-target `--demo`, `verity serve` HTTP `/health` & stdio JSON-RPC) and exporting sanitized output snapshots under `tests/e2e_containers/snapshots/`.
- Opt-in `.github/workflows/e2e-containers.yml` keeping `.github/workflows/ci.yml` strictly zero-Docker.

#### Verification
```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv build
INSTALL_SOURCE=wheel docker compose -f tests/e2e_containers/docker-compose.verify.yml build --no-cache
INSTALL_SOURCE=wheel docker compose -f tests/e2e_containers/docker-compose.verify.yml up --abort-on-container-exit --exit-code-from customer-pip
docker compose -f tests/e2e_containers/docker-compose.verify.yml down -v
```

#### Acceptance Criteria
- [x] Clean-room install succeeds from fresh wheel (and supports `INSTALL_SOURCE=pypi`) with zero host repo mounts.
- [x] Both public vulnerable MCP packages and deterministic fixtures install from scratch and trigger expected findings/exit codes.
- [x] All 6 scenarios pass end-to-end and produce sanitized verbatim snapshots for `M10`.

---

### M9: Dynamic, Narrow Terminal Screencast GIF (Charmbracelet VHS in Docker)

#### Task Spec
- [`docs/tasks/M9_dynamic_narrow_demo_gif.md`](docs/tasks/M9_dynamic_narrow_demo_gif.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKMCU4`)

#### Context
Replace the static, oversized SVG (`docs/assets/demo.svg`, `1285 × 1975.6 px`, stale `verity-core` name) with a genuinely animated, narrow terminal screencast GIF (`docs/assets/demo.gif`) recorded reproducibly via Charmbracelet VHS in Docker from live `verity` runs.

#### Key Deliverables
- `docs/assets/demo.tape` configured at narrow compact geometry (`Width 860`, `Height 440`, `FontSize 14`, `Framerate 18`) covering 4 dynamic ~6s scenes: workstation config/secret scan, live `stdio` poisoned MCP probe, SQL AST injection block vs. pass, and `--demo` + Python AST CI gate.
- `scripts/record_demo_gif.sh` running VHS inside Docker against freshly installed `verity-redteam-core` + `M8` fixtures and optimizing output via `gifsicle -O3 --lossy=30 --colors 128`.
- Generated `docs/assets/demo.gif` (`< 2.5 MB`, `width <= 900 px`, `height <= 480 px`, `n_frames >= 100`).

#### Verification
```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
./scripts/record_demo_gif.sh
python3 -c 'from PIL import Image; im=Image.open("docs/assets/demo.gif"); assert im.is_animated and im.n_frames>=100 and im.size[0]<=900 and im.size[1]<=480'
```

#### Acceptance Criteria
- [x] `docs/assets/demo.gif` animates smoothly across all 4 live scenarios with crisp, unwrapped Rich tables.
- [x] Dimensions stay compact (`<= 900 × 480 px`), file size is `< 2.5 MB`, and zero stale `verity-core` references remain.
- [x] Fully reproducible from `docs/assets/demo.tape` via `./scripts/record_demo_gif.sh`.

---

### M10: Customer-Focused `README.md` Restructure & CLI Documentation Parity Test

#### Task Spec
- [`docs/tasks/M10_customer_readme_restructure_and_parity.md`](docs/tasks/M10_customer_readme_restructure_and_parity.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKMCYw`)

#### Context
Transform `README.md` from an 89-line internal open-core note into a customer-centered product guide focused on real developer/AppSec pain points, exact commands, container-verified outputs from `M8`, and the narrow animated `docs/assets/demo.gif` from `M9`, guarded by an automated CLI documentation parity test.

#### Key Deliverables
- Restructured `README.md` with: `uvx`/`pip` install, `demo.gif` hero, 6 pain-point-to-solution walkthroughs (using verbatim `M8` snapshots), full Free capability tables (9 clients, 13 static rules, 9 AST rules, `SqlSecurityGuard` Python API, formats & exit codes), GitHub Actions CI snippet, `verity serve` MCP JSON setup, and honest Free vs. Enterprise matrix.
- Move plugin `entry_points` boilerplate out to `docs/extensibility.md` and retire static `docs/assets/demo.svg`.
- Add `tests/unit/test_documentation_parity.py` asserting all README `verity` subcommands/flags/choices match `src/verity/cli.py`, zero stale `verity-core` install commands remain, and all local links/assets exist.

#### Verification
```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run pytest tests/unit/test_documentation_parity.py -q
uv run pytest tests/ -q
uv run ruff check src tests
```

#### Acceptance Criteria
- [x] All 6 customer pain points include exact commands, verbatim `M8`-verified outputs, and clear value explanations.
- [x] `README.md` hero displays animated `docs/assets/demo.gif` and accurately reflects all Free features without stale mocks.
- [x] `tests/unit/test_documentation_parity.py` passes alongside full `pytest` and `ruff` checks.

---

### M11: Credential Detection Hardening, Packaging/Display Polish & `v0.2.0` PyPI Release

#### Task Spec
- [`docs/tasks/M11_credential_hardening_polish_and_v020_release.md`](docs/tasks/M11_credential_hardening_polish_and_v020_release.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKNnNg`)

#### Context
Harden secret detection for DSN credential URLs (`postgres://user:pass@...`) and `SECRET_VALUE_PATTERNS` under arbitrary env keys, modernize `pyproject.toml` SPDX license to eliminate `SetuptoolsDeprecationWarning`, prevent rule-ID ellipsis in narrow terminals (`no_wrap=True`), bump to `0.2.0`, publish via PyPI Trusted Publishing, and verify cold live PyPI installs via `INSTALL_SOURCE=pypi ./tests/e2e_containers/run_e2e.sh`.

#### Key Deliverables
- `MultiClientConfigScanner.DSN_CREDENTIAL_PATTERN` and `is_secret_env_entry()` shared across `config_scanner.py`, `auditor.py`, and `cli.py` (with `${VAR}` exemptions including `${DB_PASS}` inside DSN URLs).
- `pyproject.toml` (`setuptools>=77.0.0`, `license = "Apache-2.0"`, `version = "0.2.0"`), `src/verity/__init__.py` (`0.2.0`), `terminal.py` (`no_wrap=True` on `Rule`), and parity unit tests.
- Git push `main` + tag `v0.2.0` -> PyPI Trusted Publishing + `INSTALL_SOURCE=pypi ./tests/e2e_containers/run_e2e.sh`.

#### Acceptance Criteria
- [x] DSN credentials and `SECRET_VALUE_PATTERNS` under arbitrary env keys are flagged and scrubbed cleanly across all formats, with `${VAR}` placeholders exempt.
- [x] `uv build` produces `0.2.0` with zero `SetuptoolsDeprecationWarning`, and `terminal.py` renders un-ellipsized rule IDs.
- [x] `verity-redteam-core==0.2.0` is published on PyPI and `INSTALL_SOURCE=pypi ./tests/e2e_containers/run_e2e.sh` passes across all 4 clean containers.

---

### M12: Real Streaming SSE (`text/event-stream`) & Streamable HTTP Transport Support

#### Task Spec
- [`docs/tasks/M12_streaming_sse_streamable_http_transport.md`](docs/tasks/M12_streaming_sse_streamable_http_transport.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKPNQ0`)

#### Context
Upgrade `HttpSseDiscoveryTransport` (`src/verity/discovery/transports/sse.py`) from read-to-EOF `json.loads()` to an incremental `text/event-stream` frame parser supporting Streamable HTTP (`initialize` + `mcp-session-id` + `tools/list`) and legacy HTTP+SSE (`event: endpoint`), while preserving the finite `application/json` fallback.

#### Key Deliverables
- Stdlib incremental `text/event-stream` & Streamable HTTP support in `src/verity/discovery/transports/sse.py` (zero new runtime dependencies).
- Unit & local integration test suite `tests/unit/test_sse_transport.py` covering streaming `POST /mcp`, `mcp-session-id`, legacy `GET /sse` + `event: endpoint`, multi-line `data:` / keepalive, finite JSON fallback, bounded timeouts, and `verity test --url` CLI.
- Real-server acceptance scenario in `tests/e2e_containers/` running an actual `FastMCP` Streamable HTTP server (poisoned -> exit `1` with `VERITY-STATIC-*` IDs; clean -> exit `0`).

#### Acceptance Criteria
- [x] `HttpSseDiscoveryTransport` parses incremental `text/event-stream` frames with bounded timeout and never hangs waiting for EOF.
- [x] `tests/unit/test_sse_transport.py`, full `pytest tests/`, and `ruff check src tests` pass cleanly.
- [ ] Real `FastMCP` server acceptance scenario passes inside `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh`.

---

### M13: Expose UCP Rug-Pull Detection (`detect_rug_pull`) in `verity_security_scan` & CLI

#### Task Spec
- [`docs/tasks/M13_expose_ucp_rug_pull_detection.md`](docs/tasks/M13_expose_ucp_rug_pull_detection.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKPQE0`)

#### Context
Expose `UnknownCapabilityProfiler.detect_rug_pull()` (`src/verity/ucp/engine.py`) directly to IDE agents via `verity_security_scan(action="detect_rug_pull")` and to CLI/CI users via `verity test --save-baseline` / `--baseline`, with unit tests and a real mutable MCP server E2E scenario.

#### Key Deliverables
- `detect_rug_pull` action in `src/verity/mcp_server/handlers/security_scan.py` & `schemas.py` (non-breaking).
- `--save-baseline <path>` and `--baseline <path>` flags on `verity test` in `src/verity/cli.py`.
- Unit/integration test suite `tests/unit/test_rug_pull_exposure.py` + real mutable MCP server E2E scenario in `tests/e2e_containers/verify_all_scenarios.sh`.

#### Acceptance Criteria
- [x] `verity_security_scan(action="detect_rug_pull")` and `verity test --save-baseline` / `--baseline` detect added, removed, and description-mutated tools cleanly.
- [x] `tests/unit/test_rug_pull_exposure.py`, full `pytest tests/`, and `ruff check src tests` pass cleanly.
- [ ] Real mutable MCP server rug-pull scenario (CLI + `verity serve` JSON-RPC) passes inside `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh`.

---

### M14: True End-to-End `VERITY_OFFLINE` & Air-Gapped Cold-Start Baseline Support

#### Task Spec
- [`docs/tasks/M14_true_offline_airgapped_mode.md`](docs/tasks/M14_true_offline_airgapped_mode.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKPSWU`)

#### Context
Enforce `VERITY_OFFLINE=1` / `verity scan --offline` across `data_fetcher.py`, `FingerprintMatcher`, and `VulnerabilityIndex` so air-gapped scans never attempt outbound network calls, serve expired local caches cleanly, and resolve local baselines transparently.

#### Key Deliverables
- Centralized `_is_offline()` short-circuiting in `src/verity/data_fetcher.py`, `src/verity/fingerprint/matcher.py`, and `src/verity/lookup/index.py`.
- Unit/integration test suite `tests/unit/test_offline_airgap.py` asserting zero network sockets when `VERITY_OFFLINE=1`.
- Real air-gapped container acceptance scenario (`docker run --rm --network none`) inside `tests/e2e_containers/`.

#### Acceptance Criteria
- [x] `VERITY_OFFLINE=1` makes zero outbound network calls across all data/matching layers and serves expired caches cleanly.
- [x] `tests/unit/test_offline_airgap.py`, full `pytest tests/`, and `ruff check src tests` pass cleanly.
- [ ] Real `--network none` container acceptance scenario completes in `<3s` with zero network errors inside `tests/e2e_containers/run_e2e.sh`.

---

### M15: Flag Unpinned MCP Packages (`SEC-STATIC-UNPINNED-PACKAGE`) Instead of Guessing Latest Version

#### Task Spec
- [`docs/tasks/M15_unpinned_mcp_package_detection.md`](docs/tasks/M15_unpinned_mcp_package_detection.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKPUAU`)

#### Context
Stop `HybridDiscoveryMatcher.match_static_config()` (`src/verity/discovery/matcher.py`) from silently substituting `versions[-1].version` or `"1.0.0"` when a package is unpinned, and emit `SEC-STATIC-UNPINNED-PACKAGE` (`MEDIUM`) for floating `npx`/`uvx`/`@latest` configs in `ConsolidatedSecurityAuditor`.

#### Key Deliverables
- Unpinned version handling (`matched_version=None`) in `src/verity/discovery/matcher.py`.
- `SEC-STATIC-UNPINNED-PACKAGE` advisory (and skipping guessed-version OSV queries) in `src/verity/discovery/auditor.py`.
- Unit/integration test suite `tests/unit/test_unpinned_package_detection.py` + real pinned vs. unpinned `mcp-remote` E2E scenario in `tests/e2e_containers/verify_all_scenarios.sh`.

#### Acceptance Criteria
- [x] Unpinned `npx`/`uvx`/`@latest` configs emit `SEC-STATIC-UNPINNED-PACKAGE` with no fabricated version OSV lookups; pinned (`@0.1.15`, `==1.2.0`) and local scripts produce zero false positives.
- [x] `tests/unit/test_unpinned_package_detection.py`, full `pytest tests/`, and `ruff check src tests` pass cleanly.
- [ ] Real pinned vs. unpinned `mcp-remote` acceptance scenario passes inside `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh`.

---

### M16: Detect AWS `AKIA…` Keys, PEM Private Keys & Cloud Tokens in MCP Config Values

#### Task Spec
- [`docs/tasks/M16_cloud_credential_pattern_detection.md`](docs/tasks/M16_cloud_credential_pattern_detection.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKPito`)

#### Context
`MultiClientConfigScanner.SECRET_VALUE_PATTERNS` only covers `sk-`, `ghp_`, `eyJ`, and `SECRET_KEY_PATTERNS` misses `AWS_ACCESS_KEY_ID`, so AWS keys and PEM private keys in MCP `env` blocks are neither flagged nor scrubbed, even though `static_rules.py` already knows those shapes.

#### Key Deliverables
- Shared credential pattern registry reused by `config_scanner.py` and `static_rules.py` (AKIA/ASIA, PEM, Slack, Google, existing shapes) + extended key-name patterns.
- Full `****` scrubbing of matched values (incl. multi-line PEM) in all report formats.
- `tests/unit/test_credential_patterns.py` + container E2E scenario with a real AWS MCP server config and leak scan.

#### Acceptance Criteria
- [ ] AWS, PEM, Slack, and Google credentials are flagged as `SEC-STATIC-SECRET-IN-CONFIG` regardless of env key name and fully redacted; `${VAR}` references and benign values produce zero findings.
- [ ] `tests/unit/test_credential_patterns.py`, full `pytest tests/`, and `ruff check src tests` pass cleanly.
- [ ] Container E2E scenario passes inside `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh` with zero raw secret leaks.

---

### M17: Dialect-Aware `SqlSecurityGuard` (`--dialect` CLI & `verity_database_guard` Support)

#### Task Spec
- [`docs/tasks/M17_dialect_aware_sql_security_guard.md`](docs/tasks/M17_dialect_aware_sql_security_guard.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKQV5Y`)

#### Context
`SqlSecurityGuard.validate_single_select_statement()` (`src/verity/mcp_library/sql_guard.py`) hardcodes `read="postgres"` in all four `sqlglot.tokenize` and `sqlglot.parse` calls (lines 90, 119, 133, 136), causing non-Postgres syntax (MySQL backticks, T-SQL brackets/`TOP`, Snowflake/DuckDB `QUALIFY`, BigQuery `EXCEPT`) to be mis-tokenized or falsely rejected.

#### Key Deliverables
- `dialect: str = "postgres"` parameter on `SqlSecurityGuard.validate_single_select_statement()` passed to all `sqlglot` calls with allowlist validation (`postgres`, `mysql`, `sqlite`, `duckdb`, `tsql`, `bigquery`, `snowflake`).
- `--dialect` CLI option on `verity test --sql` (`src/verity/cli.py`) and `options.dialect` support in `verity_database_guard` (`src/verity/mcp_server/handlers/database_guard.py`).
- Unit test suite `tests/unit/test_sql_guard_dialects.py` + container E2E scenario with a real SQLite/MySQL MCP query flow.

#### Acceptance Criteria
- [ ] `SqlSecurityGuard.validate_single_select_statement()` supports all 7 dialects with `"postgres"` default (100% backward compatible) and blocks stacked/destructive queries across every dialect.
- [ ] `tests/unit/test_sql_guard_dialects.py`, full `pytest tests/`, and `ruff check src tests` pass cleanly.
- [ ] Container E2E scenario passes inside `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh`.

---

### M18: Sync SARIF Exporter Driver Version with `verity.__version__`

#### Task Spec
- [`docs/tasks/M18_sarif_driver_version_sync.md`](docs/tasks/M18_sarif_driver_version_sync.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKQWdQ`)

#### Context
`_stdlib_sarif_exporter()` (`src/verity/cli.py`, line 106) hardcodes `"version": "0.1.0"`, causing SARIF consumers (GitHub Code Scanning, DefectDojo) to attribute `0.2.0+` scan results to `0.1.0`.

#### Key Deliverables
- Reference `verity.__version__` in `_stdlib_sarif_exporter()` (`src/verity/cli.py`).
- Unit tests in `tests/unit/test_cli_auditor_parity.py` asserting `runs[0].tool.driver.version == verity.__version__` and lockstep parity with `pyproject.toml`.
- Container E2E SARIF export check in `tests/e2e_containers/verify_all_scenarios.sh`.

#### Acceptance Criteria
- [ ] `_stdlib_sarif_exporter()` emits `verity.__version__` with zero hardcoded version strings remaining in `src/verity/cli.py`.
- [ ] Unit tests and container E2E SARIF version assertion pass cleanly.

---

### M19: Opt-In `--live-probe` Flag on `verity scan` for Fleet-Wide Live Capability Auditing

#### Task Spec
- [`docs/tasks/M19_scan_live_probe_flag.md`](docs/tasks/M19_scan_live_probe_flag.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKQWho`)

#### Context
`_collect_config_findings()` (`src/verity/cli.py`, line 358) hardcodes `live_probe=False`, forcing users to run `verity test` manually per server to detect live `tools/list` poisoning or capability-fingerprinted CVEs.

#### Key Deliverables
- Opt-in `--live-probe` flag (default `False`) on `verity scan` threaded through `_cmd_scan`, `_collect_scan_data`, and `_collect_config_findings` to `auditor.audit_server(config, live_probe=live_probe)`.
- Per-server exception isolation (`stderr` warning on dead/unreachable servers) and secret scrubbing on live findings.
- `tests/unit/test_scan_live_probe.py` + container E2E live-probe scan scenario in `tests/e2e_containers/verify_all_scenarios.sh`.

#### Acceptance Criteria
- [ ] `verity scan --live-probe` probes configured stdio/HTTP MCP servers and surfaces live `VERITY-STATIC-*` and OSV findings across all report formats while isolating dead servers.
- [ ] `tests/unit/test_scan_live_probe.py`, full `pytest tests/`, `ruff check src tests`, and container E2E pass cleanly.

---

### M20: Add `README.md` Hero Badge Row (PyPI, License, Python 3.12+, CI) & Parity Guard

#### Task Spec
- [`docs/tasks/M20_readme_hero_badges.md`](docs/tasks/M20_readme_hero_badges.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKQWlY`)

#### Context
`M10` §2.1 specified a Hero badge row (`PyPI`, `Python 3.12+`, `License: Apache-2.0`, `CI`), but `README.md` currently opens with only the H1 title, tagline, and `demo.gif`.

#### Key Deliverables
- 4-badge Hero row in `README.md` (lines 1–8) linking to PyPI `verity-redteam-core`, Python `3.12+`, `LICENSE`, and `ci.yml`.
- `test_readme_hero_badges_present_and_valid` in `tests/unit/test_documentation_parity.py` + packaged wheel metadata verification in container E2E.

#### Acceptance Criteria
- [ ] All 4 badges render above the fold in `README.md` with valid targets and zero stale `verity-core` references.
- [ ] `tests/unit/test_documentation_parity.py` and container E2E wheel-metadata parity check pass cleanly.

---

### M21: Sync `README.md` Verbatim Tables, `demo.tape` Scene 4 & `demo.gif` to `v0.2.0` Un-Ellipsized Output

#### Task Spec
- [`docs/tasks/M21_sync_demo_gif_and_readme_tables.md`](docs/tasks/M21_sync_demo_gif_and_readme_tables.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKQWqY`)

#### Context
Two embedded terminal tables in `README.md` (lines 76–104 and 206–218) still contain pre-`M11` ellipsized rule IDs (`SEC-STATIC-SECRET-IN-CONF…`, `VERITY-STATIC-INJECTION-O…`), and `docs/assets/demo.tape` Scene 4 runs `--target sqlite-basic` instead of the full 4-target `verity test --demo` suite.

#### Key Deliverables
- Sync both `README.md` tables verbatim with `tests/e2e_containers/snapshots/01_workstation_scan.txt` and `02_schema_scan.txt`.
- Update `docs/assets/demo.tape` Scene 4 to `verity test --demo` and re-record `docs/assets/demo.gif` via `scripts/record_demo_gif.sh`.
- Snapshot parity and no-ellipsized-rule-ID guard tests in `tests/unit/test_documentation_parity.py`.

#### Acceptance Criteria
- [ ] `README.md` tables match snapshots `01` and `02` with zero ellipsized rule IDs, and `demo.gif` is re-recorded against `0.2.0` with all 4 demo targets.
- [ ] `tests/unit/test_documentation_parity.py`, `scripts/record_demo_gif.sh`, and container E2E pass cleanly.

---

### M22: Publish GitHub Release for `v0.2.0` & Guard Duplicate PyPI Workflow Trigger

#### Task Spec
- [`docs/tasks/M22_github_release_v020_and_workflow_guard.md`](docs/tasks/M22_github_release_v020_and_workflow_guard.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKQWuQ`)

#### Context
`verity-redteam-core==0.2.0` is live on PyPI and tagged `v0.2.0`, but zero GitHub Releases exist on `JMartynov/verityredteam-free`, and `.github/workflows/workflow.yaml` triggers on both `push: tags: ["v*"]` and `release: types: [published]`, which risks a duplicate PyPI upload failure when publishing a GitHub Release.

#### Key Deliverables
- Duplicate-upload guard in `.github/workflows/workflow.yaml` + unit test in `tests/unit/test_workflow_hygiene.py`.
- Official `v0.2.0` GitHub Release on `JMartynov/verityredteam-free` summarizing `M7`–`M11`, verified via `gh release view v0.2.0` and `INSTALL_SOURCE=pypi` container E2E.

#### Acceptance Criteria
- [x] `.github/workflows/workflow.yaml` is guarded against duplicate PyPI uploads and `tests/unit/test_workflow_hygiene.py` passes.
- [x] GitHub Release `v0.2.0` is published and verified alongside `INSTALL_SOURCE=pypi ./tests/e2e_containers/run_e2e.sh`.

---

### M23: Remove Stale "If the package is not yet on PyPI…" Caveat from `README.md`

#### Task Spec
- [`docs/tasks/M23_remove_stale_pypi_caveat.md`](docs/tasks/M23_remove_stale_pypi_caveat.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKQWx4`)

#### Context
`README.md` (lines 17–24) still leads with *"If the package is not yet on PyPI, install from source or from a built wheel:"* even though `verity-redteam-core==0.2.0` is live on PyPI.

#### Key Deliverables
- Remove the stale caveat in `README.md`, keep PyPI (`uvx`/`pip`) as the primary quickstart, and move contributor source-build instructions into a collapsible `<details>` block.
- Add `test_readme_has_no_stale_pypi_caveat` in `tests/unit/test_documentation_parity.py` + cold `INSTALL_SOURCE=pypi` container verification.

#### Acceptance Criteria
- [x] `README.md` contains no `"not yet on PyPI"` caveat, `tests/unit/test_documentation_parity.py` guards against regression, and `INSTALL_SOURCE=pypi` container E2E passes.

---

### M24: Extend Container E2E (`verify_all_scenarios.sh`) for DSN Credentials, `CUSTOM_FIELD=sk-…` & Live DVMCP `stdio` Probing

#### Task Spec
- [`docs/tasks/M24_container_e2e_dsn_and_live_dvmcp.md`](docs/tasks/M24_container_e2e_dsn_and_live_dvmcp.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKQW1E`)

#### Context
`M11` added DSN credential detection (`DATABASE_URL=postgres://user:pass@...`) and arbitrary-key value secret detection (`CUSTOM_FIELD=sk-...`), and `M8` §4 Scenario 2 specified live `stdio` probing of DVMCP, but `tests/e2e_containers/verify_all_scenarios.sh` currently checks only classic env key names and static `--path /opt/dvmcp`.

#### Key Deliverables
- Add `DATABASE_URL` DSN (with embedded password + safe `${DB_PASS}` twin) and `CUSTOM_FIELD=sk-...` to Scenario 1 in `tests/e2e_containers/verify_all_scenarios.sh` and `SECRETS=( ... )` leak assertions.
- Add live `verity test --command "python3 /opt/dvmcp/..."` `stdio` probing in `verify_all_scenarios.sh`.
- Unit parity tests in `tests/unit/test_cli_auditor_parity.py`.

#### Acceptance Criteria
- [x] Container E2E verifies `DATABASE_URL` DSN flagging/exemption, `CUSTOM_FIELD=sk-...` detection, zero raw leaks across all outputs/snapshots, and live DVMCP `stdio` probing.

---

### M25: Add Nightly `schedule` Trigger (`cron: '0 4 * * *'`) to `e2e-containers.yml`

#### Task Spec
- [`docs/tasks/M25_nightly_e2e_containers_cron.md`](docs/tasks/M25_nightly_e2e_containers_cron.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKQW4w`)

#### Context
`.github/workflows/e2e-containers.yml` lacks a scheduled trigger, so upstream drift in PyPI dependencies, `mcp-remote@0.1.15`, DVMCP, or Docker base images is not caught between PRs/tags.

#### Key Deliverables
- Add `schedule: - cron: '0 4 * * *'` to `.github/workflows/e2e-containers.yml` (one hour after `full-tests.yml` at `0 3 * * *`).
- Add YAML trigger assertions in `tests/unit/test_workflow_hygiene.py`.

#### Acceptance Criteria
- [x] `.github/workflows/e2e-containers.yml` includes `cron: '0 4 * * *'` while preserving existing triggers, and `tests/unit/test_workflow_hygiene.py` passes.

---

### M26: Upgrade `actions/checkout` and `astral-sh/setup-uv` Pins Across All GitHub Actions Workflows

#### Task Spec
- [`docs/tasks/M26_upgrade_github_actions_pins.md`](docs/tasks/M26_upgrade_github_actions_pins.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKQW9A`)

#### Context
`.github/workflows/ci.yml`, `full-tests.yml`, `workflow.yaml`, and `e2e-containers.yml` still pin `actions/checkout@v4` (4/4) and `astral-sh/setup-uv@v4` (3/4), emitting GitHub Actions Node 20 deprecation warnings.

#### Key Deliverables
- Upgrade `actions/checkout` and `astral-sh/setup-uv` consistently to Node-24-ready versions across all 4 workflows.
- Add pin consistency assertions in `tests/unit/test_workflow_hygiene.py`.

#### Acceptance Criteria
- [x] All 4 workflows use consistent Node-24-ready `actions/checkout` and `astral-sh/setup-uv` pins with zero `@v4` references remaining, and `tests/unit/test_workflow_hygiene.py` passes.

---

### M27: Guard `uv build` & Local Wheel Staging in `run_e2e.sh` When `INSTALL_SOURCE=pypi`

#### Task Spec
- [`docs/tasks/M27_guard_uv_build_in_run_e2e.md`](docs/tasks/M27_guard_uv_build_in_run_e2e.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKQXBQ`)

#### Context
`tests/e2e_containers/run_e2e.sh` (lines 21–36) runs `uv build` and stages `${wheels[0]}` into `.wheel_stage/` even when `INSTALL_SOURCE=pypi`, wasting build time and risking stale wheel selection if `dist/` was not cleaned.

#### Key Deliverables
- Guard `uv build` and wheel staging in `tests/e2e_containers/run_e2e.sh` behind `if [ "$INSTALL_SOURCE" = "wheel" ]; then ... fi` while keeping `.wheel_stage/` present for Docker build context and cleaning stale wheels before building.
- Add `tests/unit/test_e2e_runner_hygiene.py` verifying both `wheel` and `pypi` branches.

#### Acceptance Criteria
- [x] `INSTALL_SOURCE=pypi` skips `uv build`, `INSTALL_SOURCE=wheel` purges stale wheels before building, and `tests/unit/test_e2e_runner_hygiene.py` plus both container E2E modes pass.

---

### M28: Fix Retired `verity-core` Package Name in `AGENTS.md` & Extend Documentation Parity Guard

#### Task Spec
- [`docs/tasks/M28_fix_agents_md_retired_package_name.md`](docs/tasks/M28_fix_agents_md_retired_package_name.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKQXFA`)

#### Context
`AGENTS.md` still references the retired package name `verity-core` on lines 5 and 12 (and hardcodes `"Tasks M1–M6"`), because `test_no_stale_package_references` in `tests/unit/test_documentation_parity.py` scans only `README.md` and `docs/extensibility.md`.

#### Key Deliverables
- Replace `verity-core` with `verity-redteam-core` and update the task board pointer in `AGENTS.md`.
- Extend `test_no_stale_package_references` in `tests/unit/test_documentation_parity.py` to include `AGENTS.md`.

#### Acceptance Criteria
- [x] `AGENTS.md` contains zero `verity-core` occurrences and `tests/unit/test_documentation_parity.py` guards `README.md`, `docs/extensibility.md`, and `AGENTS.md`.

---

### M29: Populate Exact GitHub Project #5 Item IDs & Links Across `TASK_BOARD.md` (`M1`–`M29`)

#### Task Spec
- [`docs/tasks/M29_exact_task_board_project_links.md`](docs/tasks/M29_exact_task_board_project_links.md) (GitHub Project #5 Item: `PVTI_lAHOD-xmQM4Br351zhKQXJA`)

#### Context
Task Matrix rows `M1`–`M11` in `TASK_BOARD.md` link only to the generic Project #5 root URL without exact `PVTI_…` item identifiers, unlike `M12`–`M29`.

#### Key Deliverables
- Harvest canonical `PVTI_…` item IDs from `gh project item-list 5 --owner JMartynov --format json` and backfill `M1`–`M11` in the `TASK_BOARD.md` Task Matrix and detailed sections.
- Add dynamic task-board parity tests in `tests/unit/test_documentation_parity.py` asserting every discovered `M<N>` row has a unique `PVTI_…` ID and a valid spec link.

#### Acceptance Criteria
- [ ] Every row `M1`–`M29` in `TASK_BOARD.md` carries its exact, verified `PVTI_…` item ID in both the Task Matrix and detailed section, and `tests/unit/test_documentation_parity.py` passes.
