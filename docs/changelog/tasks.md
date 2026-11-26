# Task Changelog (M01 - M53)

This changelog is generated from `TASK_BOARD.md` and
`docs/tasks/*.md` by `scripts/build_docs_portal.py`. It merges the
release narrative with the engineering ledger so auditors can trace
any behaviour back to a milestone and a verification command.

Discovered task specifications with frontmatter `task_id`:

`M30`, `M31`, `M32`, `M33`, `M34`, `M35`, `M36`, `M37`, `TASK-94`, `M39`, `M40`, `M41`, `M42`, `M43`, `M44`, `M45`, `M46`, `M47`, `M48`, `M49`, `M50`, `M51`, `M52`, `M53`

## Release Notes

### v0.2.0 — Open-Core Release

The first published open-core release. It ships the standalone
`verity-redteam-core` distribution with the workstation scanner, the
free CLI (`scan`, `test`, `serve`), the deterministic SQL AST guard,
and the four zero-Docker targets. The release was verified inside
empty containers from both the built wheel and PyPI.

### v0.2.1 — Hardening Patch

A hardening patch on top of the 0.2.0 surface. It tightens
credential-shape detection, dialect-aware SQL validation, offline and
air-gapped behaviour, and the reporting/parity guards that keep the
documentation honest.

### v0.2.2 — Unified Scan CLI, SBOM & Inventory Drift

Extends `verity scan` with 17-client discovery and JSONC comment
stripping (`--client`, `--scan-global`), composable `--scanners`,
offline BK-Tree typosquatting, multi-server conflict detection,
transitive call-graph reachability (`--call-analysis`, `--reachable-only`,
`--manifest`), OWASP MCP Top 10 / LLM Top 10 compliance scorecards
(`--compliance`, `--fail-on-non-compliant`), CycloneDX 1.6 and SPDX 2.3
SBOM export (`--format cyclonedx|spdx`), inventory drift baselines
(`--save-inventory-baseline`, `--compare-inventory-baseline`,
`--fail-on-drift`), and `verity_security_scan` MCP parity.

### Continuous Engineering Ledger (M12-M53)

Every change after the 0.2.0 cut lands as a tracked milestone:

- **M12** — Real Streaming SSE (`text/event-stream`) & Streamable HTTP Transport Support (Done)
- **M13** — Expose UCP Rug-Pull Detection (`detect_rug_pull`) in `verity_security_scan` & CLI (Done)
- **M14** — True End-to-End `VERITY_OFFLINE` & Air-Gapped Cold-Start Baseline Support (Done)
- **M15** — Flag Unpinned MCP Packages (`SEC-STATIC-UNPINNED-PACKAGE`) Instead of Guessing Latest Version (Done)
- **M16** — Detect AWS `AKIA…` Keys, PEM Private Keys & Cloud Tokens in MCP Config Values (Done)
- **M17** — Dialect-Aware `SqlSecurityGuard` (`--dialect` CLI & `verity_database_guard` Support) (Done)
- **M18** — Sync SARIF Exporter Driver Version with `verity.__version__` (Done)
- **M19** — Opt-In `--live-probe` Flag on `verity scan` for Fleet-Wide Live Capability Auditing (Done)
- **M20** — Add `README.md` Hero Badge Row (PyPI, License, Python 3.12+, CI) & Parity Guard (Done)
- **M21** — Sync `README.md` Verbatim Tables, `demo.tape` Scene 4 & `demo.gif` to `v0.2.0` Un-Ellipsized Output (Done)
- **M22** — Publish GitHub Release for `v0.2.0` & Guard Duplicate PyPI Workflow Trigger (Done)
- **M23** — Remove Stale "If the package is not yet on PyPI…" Caveat from `README.md` (Done)
- **M24** — Extend Container E2E (`verify_all_scenarios.sh`) for DSN Credentials, `CUSTOM_FIELD=sk-…` & Live DVMCP `stdio` Probing (Done)
- **M25** — Add Nightly `schedule` Trigger (`cron: '0 4 * * *'`) to `e2e-containers.yml` (Done)
- **M26** — Upgrade `actions/checkout` and `astral-sh/setup-uv` Pins Across All GitHub Actions Workflows (Done)
- **M27** — Guard `uv build` & Local Wheel Staging in `run_e2e.sh` When `INSTALL_SOURCE=pypi` (Done)
- **M28** — Fix Retired `verity-core` Package Name in `AGENTS.md` & Extend Documentation Parity Guard (Done)
- **M29** — Populate Exact GitHub Project #5 Item IDs & Links Across `TASK_BOARD.md` (`M1`–`M29`) (Done)
- **M30** — `uvx` Single-Token Execution & Homebrew Distribution (`TASK-79`) (Done)
- **M31** — CLI CI Prerequisites & Brownfield Baseline / Ignore Engine (`TASK-80`) (Done)
- **M32** — Official GitHub Action (`verity-scan-action@v1`) & Pre-Commit Hooks (`TASK-81`) (Not Done)
- **M33** — TypeScript / JavaScript MCP SAST Scanner (`TASK-90`) (Not Done)
- **M34** — Agent Skill / Instruction File Scanner & Cross-Tool Toxic Flow Analysis (`TASK-91`) (Not Done)
- **M35** — Authenticated Remote Probing (OAuth/Bearer) & `--identify-as` Bait-and-Switch Detection (`TASK-92`) (Not Done)
- **M36** — ANSI Terminal Deception & Unicode BiDi/Tag-Char Findings (`TASK-93`) (Not Done)
- **M37** — MCP Schema-Handler Drift & Structured Agent Guidance (`TASK-85`) (Not Done)
- **M38** — Web Documentation Portal & Automated Task-to-Docs Pipeline (`TASK-94`) (Done)
- **M39** — Python AST Real-World Rules & Import Aliases (`TASK-102`) (Done)
- **M40** — Free CLI SARIF Pro Gate & Line Precision (`TASK-103-FREE`) (Done)
- **M41** — Homepage Tier 1/2 Focus & Registry Parity (`TASK-104`) (Done)
- **M42** — Pro Features Showcase & Comparison Docs in Free (`TASK-107`) (Done)
- **M43** — Free MCP Database Guard Pro Gating (`TASK-109-FREE`) (Done)
- **M44** — Free Read-Only Guard & Router Decoupling (`TASK-106-FREE`) (Done)
- **M45** — Free README Tier 1/2 Focus, Pro Showcase & Parity (`TASK-110-FREE`) (Done)
- **M46** — Unified `verity scan` CLI (`mcp-fingerprints` + `mcp-vulnerabilities`, SBOM & Drift) (`TASK-82-FREE`) (Done)
- **M47** — Zero-Signup Local Web Viewer (`verity view` Core SPA & Server) (`TASK-83-FREE`) (Not Done)
- **M48** — Interactive Onboarding Wizard (`verity init`) & Safe Config Fix (`verity fix`) (`TASK-84-FREE`) (Partially Done)
- **M49** — Opt-In `--llm-assist` Semantic Alignment Analyzer on UCP Path B (`TASK-87-FREE`) (Partially Done)
- **M50** — Free `PRO_FEATURE_REQUIRED` Plugin Hooks for `--autofix` and `--explain` (`TASK-88-89-FREE`) (Not Done)
- **M51** — Bundled Snapshot Sync (`passports`/`vulns`), Sigstore Verification & Config Scanner Dedup (`TASK-94-FREE`) (Not Done)
- **M52** — Multi-Framework Agent SAST (LangChain/CrewAI/AutoGen) & Optional YARA Engine (`TASK-95-FREE`) (Not Done)
- **M53** — Pre-Boot Maintainer & Package Reputation Scoring (0-100) (`TASK-97-FREE`) (Not Done)

## Task Verification Matrix

| Task | Milestone | Status | Verification |
| --- | --- | --- | --- |
| — | M01 | Done | `uv run pytest tests/ -q` |
| — | M02 | Done | `uv run pytest tests/ -q` |
| — | M03 | Done | `uv run pytest tests/ -q` |
| — | M04 | Done | `uv run pytest tests/ -q` |
| — | M05 | Done | `uv run pytest tests/ -q` |
| — | M06 | Done | `uv run pytest tests/ -q` |
| — | M07 | Done | `uvx --from verity-redteam-core verity scan --offline` |
| — | M08 | Done | `uvx --from verity-redteam-core verity scan --offline` |
| — | M09 | Done | `uvx --from verity-redteam-core verity scan --offline` |
| — | M10 | Done | `uvx --from verity-redteam-core verity scan --offline` |
| — | M11 | Done | `uvx --from verity-redteam-core verity scan --offline` |
| — | M12 | Done | `uv run pytest tests/unit -q` |
| — | M13 | Done | `uv run pytest tests/unit -q` |
| — | M14 | Done | `uv run pytest tests/unit -q` |
| — | M15 | Done | `uv run pytest tests/unit -q` |
| — | M16 | Done | `uv run pytest tests/unit -q` |
| — | M17 | Done | `uv run pytest tests/unit -q` |
| — | M18 | Done | `uv run pytest tests/unit -q` |
| — | M19 | Done | `uv run pytest tests/unit -q` |
| — | M20 | Done | `uv run pytest tests/unit -q` |
| — | M21 | Done | `uv run pytest tests/unit -q` |
| — | M22 | Done | `uv run pytest tests/unit -q` |
| — | M23 | Done | `uv run pytest tests/unit -q` |
| — | M24 | Done | `uv run pytest tests/unit -q` |
| — | M25 | Done | `uv run pytest tests/unit -q` |
| — | M26 | Done | `uv run pytest tests/unit -q` |
| — | M27 | Done | `uv run pytest tests/unit -q` |
| — | M28 | Done | `uv run pytest tests/unit -q` |
| — | M29 | Done | `uv run pytest tests/unit -q` |
| TASK-79 | M30 | Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-80 | M31 | Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-81 | M32 | Not Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-90 | M33 | Not Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-91 | M34 | Not Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-92 | M35 | Not Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-93 | M36 | Not Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-85 | M37 | Not Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-94 | M38 | Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-102 | M39 | Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-103 | M40 | Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-104 | M41 | Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-107 | M42 | Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-109 | M43 | Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-106 | M44 | Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-110 | M45 | Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-82 | M46 | Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-83 | M47 | Not Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-84 | M48 | Partially Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-87 | M49 | Partially Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-88 | M50 | Not Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-94 | M51 | Not Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-95 | M52 | Not Done | `uv run pytest tests/ -q && uv run ruff check src tests` |
| TASK-97 | M53 | Not Done | `uv run pytest tests/ -q && uv run ruff check src tests` |

## Detailed Engineering Notes

### M01 — Plugin Foundation & Core MCP Server

- **Phase:** Foundation
- **Status:** Done
- **Scope:** Plugin protocols, entry points, stdlib JSON-RPC MCP server
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/ -q`

### M02 — Workstation Discovery & Static Screening

- **Phase:** Foundation
- **Status:** Done
- **Scope:** 9-client scanner, 13-rule StaticRuleEvaluator, fingerprinting, OSV cache
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/ -q`

### M03 — Deterministic SQL AST Guard

- **Phase:** Foundation
- **Status:** Done
- **Scope:** Cohesive 245-line `SqlSecurityGuard` (`sqlglot`), Pro Snowflake guard
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/ -q`

### M04 — Link `verity-pro` to `verity-core` via `uv` Workspace

- **Phase:** Foundation
- **Status:** Done
- **Scope:** `[tool.uv.sources]`, `src/verity_pro/` packaging, remove duplicated core
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/ -q`

### M05 — Net-New Free CLI & 4 In-Memory Synthetic Targets

- **Phase:** Foundation
- **Status:** Done
- **Scope:** `verity scan`, `test --demo`, `serve`, Rich tables, 4 zero-Docker targets
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/ -q`

### M06 — CI/CD & Launch Readiness

- **Phase:** Foundation
- **Status:** Done
- **Scope:** Multi-platform GitHub Actions matrix, `uv build` wheel, Pro regression
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/ -q`

### M07 — CLI Parity, `ConsolidatedSecurityAuditor` Wiring & YAML Config Support

- **Phase:** v0.2.0 Open-Core Engine
- **Status:** Done
- **Scope:** Wire secret scrubbing, shell wrappers, OSV CVEs & YAML parsing into `verity scan`
- **Task references:** no linked task file
- **Verification:** `uvx --from verity-redteam-core verity scan --offline`

### M08 — Ground-Zero Empty-Container E2E Customer Verification Suite

- **Phase:** v0.2.0 Open-Core Engine
- **Status:** Done
- **Scope:** Clean-room Docker matrix (`wheel`/`pypi`), real + fixture MCP targets, 6 scenarios
- **Task references:** no linked task file
- **Verification:** `uvx --from verity-redteam-core verity scan --offline`

### M09 — Dynamic, Narrow Terminal Screencast GIF (Charmbracelet VHS in Docker)

- **Phase:** v0.2.0 Open-Core Engine
- **Status:** Done
- **Scope:** Reproducible VHS `.tape` (`~860x440`), 4 live scenes, `gifsicle`-optimized `demo.gif`
- **Task references:** no linked task file
- **Verification:** `uvx --from verity-redteam-core verity scan --offline`

### M10 — Customer-Focused `README.md` Restructure & CLI Documentation Parity Test

- **Phase:** v0.2.0 Open-Core Engine
- **Status:** Done
- **Scope:** Pain-point-first README with container-verified outputs, `demo.gif`, CI parity test
- **Task references:** no linked task file
- **Verification:** `uvx --from verity-redteam-core verity scan --offline`

### M11 — Credential Detection Hardening, Packaging/Display Polish & `v0.2.0` PyPI Release

- **Phase:** v0.2.0 Open-Core Engine
- **Status:** Done
- **Scope:** DSN & value-pattern secret checks, SPDX license, `Rule` `no_wrap=True`, `v0.2.0` publish + live PyPI E2E
- **Task references:** no linked task file
- **Verification:** `uvx --from verity-redteam-core verity scan --offline`

### M12 — Real Streaming SSE (`text/event-stream`) & Streamable HTTP Transport Support

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Incremental SSE frame parser, Streamable HTTP `mcp-session-id`, legacy SSE endpoint, unit tests & real `FastMCP` E2E
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M13 — Expose UCP Rug-Pull Detection (`detect_rug_pull`) in `verity_security_scan` & CLI

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** `detect_rug_pull` MCP action, `verity test --save-baseline`/`--baseline`, unit tests & mutable server E2E
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M14 — True End-to-End `VERITY_OFFLINE` & Air-Gapped Cold-Start Baseline Support

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Zero-socket `VERITY_OFFLINE` across `data_fetcher`/matchers, expired-cache/baseline, unit tests & `--network none` E2E
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M15 — Flag Unpinned MCP Packages (`SEC-STATIC-UNPINNED-PACKAGE`) Instead of Guessing Latest Version

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Return `None` for unpinned version, emit `SEC-STATIC-UNPINNED-PACKAGE`, unit tests & real `mcp-remote` E2E
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M16 — Detect AWS `AKIA…` Keys, PEM Private Keys & Cloud Tokens in MCP Config Values

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Shared credential pattern registry, extended key names, full scrubbing, unit tests & container E2E
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M17 — Dialect-Aware `SqlSecurityGuard` (`--dialect` CLI & `verity_database_guard` Support)

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Pass `read=dialect` (default `postgres`), expose `--dialect` on `verity test --sql` & `verity_database_guard`, unit tests & SQLite/MySQL E2E
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M18 — Sync SARIF Exporter Driver Version with `verity.__version__`

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Replace hardcoded `"0.1.0"` in `_stdlib_sarif_exporter` with `verity.__version__`, unit tests & container SARIF E2E
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M19 — Opt-In `--live-probe` Flag on `verity scan` for Fleet-Wide Live Capability Auditing

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Expose `--live-probe` on `verity scan`, thread into `auditor.audit_server()`, isolate dead servers, unit tests & container E2E
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M20 — Add `README.md` Hero Badge Row (PyPI, License, Python 3.12+, CI) & Parity Guard

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Add 4-badge Hero row above tagline in `README.md`, doc parity guard & wheel metadata container check
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M21 — Sync `README.md` Verbatim Tables, `demo.tape` Scene 4 & `demo.gif` to `v0.2.0` Un-Ellipsized Output

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Sync two ellipsized README tables to snapshots `01`/`02`, run full `verity test --demo` in Scene 4, re-record `demo.gif` & parity tests
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M22 — Publish GitHub Release for `v0.2.0` & Guard Duplicate PyPI Workflow Trigger

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Guard `.github/workflows/workflow.yaml` duplicate PyPI upload, publish `v0.2.0` GitHub Release notes, workflow unit test & PyPI E2E
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M23 — Remove Stale "If the package is not yet on PyPI…" Caveat from `README.md`

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Make PyPI primary install path, move source build into `<details>`, add parity test & cold PyPI container check
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M24 — Extend Container E2E (`verify_all_scenarios.sh`) for DSN Credentials, `CUSTOM_FIELD=sk-…` & Live DVMCP `stdio` Probing

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Add `DATABASE_URL` DSN + safe twin, `CUSTOM_FIELD=sk-…` leak assertions, and live DVMCP `verity test --command` probing
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M25 — Add Nightly `schedule` Trigger (`cron: '0 4 * * *'`) to `e2e-containers.yml`

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Add nightly `0 4 * * *` cron trigger to `e2e-containers.yml` and workflow hygiene unit test
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M26 — Upgrade `actions/checkout` and `astral-sh/setup-uv` Pins Across All GitHub Actions Workflows

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Upgrade `actions/checkout` and `astral-sh/setup-uv` to Node-24-ready versions across all 4 workflows + unit test
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M27 — Guard `uv build` & Local Wheel Staging in `run_e2e.sh` When `INSTALL_SOURCE=pypi`

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Guard `uv build` behind `INSTALL_SOURCE=wheel`, clean stale wheels, unit test & dual-mode container E2E
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M28 — Fix Retired `verity-core` Package Name in `AGENTS.md` & Extend Documentation Parity Guard

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Replace `verity-core` with `verity-redteam-core` in `AGENTS.md` and extend `test_no_stale_package_references`
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M29 — Populate Exact GitHub Project #5 Item IDs & Links Across `TASK_BOARD.md` (`M1`–`M29`)

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Harvest `PVTI_…` item IDs via `gh project item-list 5`, backfill `M1`–`M11` rows/sections, add dynamic parity guard
- **Task references:** no linked task file
- **Verification:** `uv run pytest tests/unit -q`

### M30 — `uvx` Single-Token Execution & Homebrew Distribution (`TASK-79`)

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Dual `verity-redteam-core` script entrypoint, `-V`/`--version`, `[project.urls]`, `generate_homebrew_formula.py`, `JMartynov/homebrew-tap`
- **Task references:** TASK-79
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M31 — CLI CI Prerequisites & Brownfield Baseline / Ignore Engine (`TASK-80`)

- **Phase:** Hardening & Parity
- **Status:** Done
- **Scope:** Stdlib `verity.baseline` (`paths`, `fingerprint`, `ignore`, `inline`, `store`), `--fail-on-severity`, multi-file `--path`, Pro-gated SARIF `partialFingerprints` & suppressions
- **Task references:** TASK-80
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M32 — Official GitHub Action (`verity-scan-action@v1`) & Pre-Commit Hooks (`TASK-81`)

- **Phase:** Hardening & Parity
- **Status:** Not Done
- **Scope:** `.pre-commit-hooks.yaml` (`verity-scan`, `verity-scan-configs`, `verity-scan-uvx`), README snippet, `JMartynov/verity-scan-action`
- **Task references:** TASK-81
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M33 — TypeScript / JavaScript MCP SAST Scanner (`TASK-90`)

- **Phase:** Hardening & Parity
- **Status:** Not Done
- **Scope:** Polyglot `.ts`/`.tsx`/`.js`/`.mjs` discovery in `McpAstScannerEngine`, `typescript_ast.py`, 5 `VERITY-AST-TS-*` sink rules, UCP/StaticRule wiring
- **Task references:** TASK-90
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M34 — Agent Skill / Instruction File Scanner & Cross-Tool Toxic Flow Analysis (`TASK-91`)

- **Phase:** Hardening & Parity
- **Status:** Not Done
- **Scope:** `InstructionFileScanner` (6 formats), `ToxicFlowAnalyzer` lethal-trifecta correlation (`VERITY-TOXIC-FLOW-*`), `--skills` / `--toxic-flows`
- **Task references:** TASK-91
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M35 — Authenticated Remote Probing (OAuth/Bearer) & `--identify-as` Bait-and-Switch Detection (`TASK-92`)

- **Phase:** Hardening & Parity
- **Status:** Not Done
- **Scope:** `DiscoveredServerConfig.headers` (redacted), `--header`/`--bearer-token`, `--identify-as`, differential `--detect-bait-and-switch`
- **Task references:** TASK-92
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M36 — ANSI Terminal Deception & Unicode BiDi/Tag-Char Findings (`TASK-93`)

- **Phase:** Hardening & Parity
- **Status:** Not Done
- **Scope:** Explicit ANSI/BiDi/Tag/zero-width `StaticRuleEvaluator` rules, `VERITY-UCP-UNICODE-ANOMALY` wiring, `--visualize-ansi-codes`
- **Task references:** TASK-93
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M37 — MCP Schema-Handler Drift & Structured Agent Guidance (`TASK-85`)

- **Phase:** Hardening & Parity
- **Status:** Not Done
- **Scope:** Expose `verify_physical_database` / `generate_safe_parameterized_query` in `schemas.py`, `DualPathRouter` + `next_recommended_actions`, `--unified-only`
- **Task references:** TASK-85
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M38 — Web Documentation Portal & Automated Task-to-Docs Pipeline (`TASK-94`)

- **Phase:** Customer Documentation Portal
- **Status:** Done
- **Scope:** MkDocs Material portal (`mkdocs.yml`), 10 deep guides/catalogs, `scripts/build_docs_portal.py`, GitHub Pages workflow
- **Task references:** TASK-94
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M39 — Python AST Real-World Rules & Import Aliases (`TASK-102`)

- **Phase:** Feature Realism & Product Alignment
- **Status:** Done
- **Scope:** Alias resolution in `visit_Call` plus real def-use CWE-22 / CWE-89 / CWE-862 rules in `src/verity/scanner/python_ast.py`
- **Task references:** TASK-102
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M40 — Free CLI SARIF Pro Gate & Line Precision (`TASK-103-FREE`)

- **Phase:** Feature Realism & Product Alignment
- **Status:** Done
- **Scope:** `_pro_plugin_available()` SARIF gate (`PRO_FEATURE_REQUIRED`, exit code `2`) and real `line_number` / `uri` in `src/verity/cli.py`
- **Task references:** TASK-103
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M41 — Homepage Tier 1/2 Focus & Registry Parity (`TASK-104`)

- **Phase:** Feature Realism & Product Alignment
- **Status:** Done
- **Scope:** Tier 1 / Tier 2 homepage, single auxiliary appendix, and runtime-registry parity (`STATIC_RULE_IDS`, `AST_RULE_IDS`, `TARGET_SLUGS`, `MCP_TOOL_NAMES`)
- **Task references:** TASK-104
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M42 — Pro Features Showcase & Comparison Docs in Free (`TASK-107`)

- **Phase:** Feature Realism & Product Alignment
- **Status:** Done
- **Scope:** `docs/pro/enterprise_features.md`, Free vs Pro matrix, `PRO_FEATURE_REQUIRED` contract
- **Task references:** TASK-107
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M43 — Free MCP Database Guard Pro Gating (`TASK-109-FREE`)

- **Phase:** Feature Realism & Product Alignment
- **Status:** Done
- **Scope:** `PRO_FEATURE_REQUIRED` gate for `validate_nosql_filter` and `enforce_volume_policy` in `src/verity/mcp_server/handlers/database_guard.py`
- **Task references:** TASK-109
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M44 — Free Read-Only Guard & Router Decoupling (`TASK-106-FREE`)

- **Phase:** Feature Realism & Product Alignment
- **Status:** Done
- **Scope:** Destructive-verb blocking in `readonly_guard.py` and formula de-hardcoding in `dual_path_router.py`
- **Task references:** TASK-106
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M45 — Free README Tier 1/2 Focus, Pro Showcase & Parity (`TASK-110-FREE`)

- **Phase:** Feature Realism & Product Alignment
- **Status:** Done
- **Scope:** `README.md` Tier 1 / Tier 2 focus, Pro showcase, and registry / badge parity
- **Task references:** TASK-110
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M46 — Unified `verity scan` CLI (`mcp-fingerprints` + `mcp-vulnerabilities`, SBOM & Drift) (`TASK-82-FREE`)

- **Phase:** Next-Gen SAST, UX & Supply-Chain Roadmap
- **Status:** Done
- **Scope:** 15+ client discovery with JSONC, composable `--scanners`, offline BK-Tree typosquat, conflicts, reachability, CycloneDX/SPDX SBOM, inventory drift
- **Task references:** TASK-82
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M47 — Zero-Signup Local Web Viewer (`verity view` Core SPA & Server) (`TASK-83-FREE`)

- **Phase:** Next-Gen SAST, UX & Supply-Chain Roadmap
- **Status:** Not Done
- **Scope:** Loopback HTTP+SSE server, DNS-rebinding/CSP/token guards, JSON/JSONL artifact indexer, zero-build ES module SPA, `ViewerRegistry`
- **Task references:** TASK-83
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M48 — Interactive Onboarding Wizard (`verity init`) & Safe Config Fix (`verity fix`) (`TASK-84-FREE`)

- **Phase:** Next-Gen SAST, UX & Supply-Chain Roadmap
- **Status:** Partially Done
- **Scope:** Lossless `JsoncPatcher`, `AtomicBackupManager` rollback, `verity init` wizard & `verity fix` dry-run/write config remediation
- **Task references:** TASK-84
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M49 — Opt-In `--llm-assist` Semantic Alignment Analyzer on UCP Path B (`TASK-87-FREE`)

- **Phase:** Next-Gen SAST, UX & Supply-Chain Roadmap
- **Status:** Partially Done
- **Scope:** Wire `DualPathRouter` in `auditor.py`, fix `TEMPLATE_INDICATORS`, pure-stdlib `semantic_assist.py` with exact `evidence_span` guard, `--llm-assist`
- **Task references:** TASK-87
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M50 — Free `PRO_FEATURE_REQUIRED` Plugin Hooks for `--autofix` and `--explain` (`TASK-88-89-FREE`)

- **Phase:** Next-Gen SAST, UX & Supply-Chain Roadmap
- **Status:** Not Done
- **Scope:** `set_autofix_provider`/`set_explain_provider`, `synthesize_verified_patch`/`explain_finding_context` schemas, `PRO_FEATURE_REQUIRED` gates
- **Task references:** TASK-88
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M51 — Bundled Snapshot Sync (`passports`/`vulns`), Sigstore Verification & Config Scanner Dedup (`TASK-94-FREE`)

- **Phase:** Next-Gen SAST, UX & Supply-Chain Roadmap
- **Status:** Not Done
- **Scope:** Sync `passports.json.gz`/`vulnerabilities.json.gz`, Sigstore verification in `data_fetcher.py`, dedup `StaticConfigScanner`
- **Task references:** TASK-94
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M52 — Multi-Framework Agent SAST (LangChain/CrewAI/AutoGen) & Optional YARA Engine (`TASK-95-FREE`)

- **Phase:** Next-Gen SAST, UX & Supply-Chain Roadmap
- **Status:** Not Done
- **Scope:** `langchain_ast.py`, `crewai_ast.py`, `autogen_ast.py` visitors + optional `yara_engine.py` graceful fallback
- **Task references:** TASK-95
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

### M53 — Pre-Boot Maintainer & Package Reputation Scoring (0-100) (`TASK-97-FREE`)

- **Phase:** Next-Gen SAST, UX & Supply-Chain Roadmap
- **Status:** Not Done
- **Scope:** Opt-in `ReputationScorer` (0-100) on `DualPathRouter` Path B respecting `VERITY_OFFLINE=1`
- **Task references:** TASK-97
- **Verification:** `uv run pytest tests/ -q && uv run ruff check src tests`

## Customer Upgrade Guide

Upgrade the CLI distribution in place:

```bash
pip install --upgrade verity-redteam-core
```

Run the latest scanner without installing it:

```bash
uvx --from verity-redteam-core verity scan
```

After upgrading, re-run your CI gate with the same policy flags. The
rule ids are stable, so existing suppressions and baselines continue
to apply. New rules added in this window are additive: they never
reuse an existing id, so a green build only turns red when a genuine
new finding appears.
