# M10: Customer-Focused README.md Restructure & CLI Documentation Parity Test

- **Task ID**: `M10`
- **Priority**: `P1`
- **Status**: `Done`
- **Dependencies**: `M7`, `M8`, `M9`
- **Blocks**: Launch / Release `v0.2.0`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Problem Statement & Audit Summary

Currently, `verityredteam-free/README.md` (89 lines) reads like an internal open-core migration note instead of a customer-facing product guide:
1. **No end-user install path**: Only shows `uv run verity ...` (assumes contributor git clone); omits `uvx --from verity-redteam-core verity ...` and `pip install verity-redteam-core`.
2. **Misses major Free capabilities already in code**:
   - Python AST code scanner (`verity scan --path`, 9 `VERITY-AST-*` rules covering `CWE-94`, `CWE-78`, `CWE-22`, `CWE-502`, `CWE-79`, `CWE-862`),
   - Live MCP server probing (`verity test --command` for `stdio` and `--url` for `HTTP/SSE`),
   - CI/CD gating (`--fail-on-findings` exit code `1`), `--config-file`, `--schema-file`, `--format json|markdown|html`, `--output`,
   - Exact list of the **9 supported AI clients** (`Claude Desktop`, `Cursor`, `VS Code Cline`, `VS Code Roo`, `Continue`, `Windsurf`, `Zed`, `LibreChat`, workspace `.mcp.json`),
   - Threat categories caught by all **13 `VERITY-STATIC-*` rules** (+ NFKC / zero-width Unicode normalization),
   - IDE MCP server mode (`verity serve --transport {stdio,sse,http}`, `/health`, 4 unified MCP tools + `python -m verity.mcp_server.manage`),
   - Unknown Capability Profiler (`src/verity/ucp/engine.py`) rug-pull drift detection (`detect_rug_pull`),
   - Embeddable `SqlSecurityGuard` Python library API (`src/verity/mcp_library/sql_guard.py`).
3. **Contains inaccurate / mismatched output**:
   - Hand-mocked `verity test --demo` table (`Target | CWE | Result` -> `VULN`) does not match actual CLI output (`Status | Check | Severity | Message` -> `PASS` with `Vulnerable breached=True, Secure defended=True`).
   - Static `docs/assets/demo.svg` uses wrong package name `verity-core`.
4. **Heavy focus on plugin internals**: ~25% of the README is Python `entry_points` boilerplate better suited for a linked `docs/extensibility.md`.

---

## 2. Target `README.md` Structure (Pain-Point & Result Driven)

Restructure `verityredteam-free/README.md` using verified snapshots from `M8` and the animated narrow GIF from `M9`:

1. **Hero & Value Proposition**:
   - Clear positioning statement (catch poisoned MCP servers, leaked workstation secrets, prompt-injected SQL, and RCE in AI agent tools — offline, deterministic, zero Docker).
   - PyPI / License (`Apache-2.0`) / Python (`3.12+`) / CI badges.
   - Animated narrow screencast GIF: `![Verity RedTeam Free Terminal Demo](docs/assets/demo.gif)` (remove stale `docs/assets/demo.svg`).
2. **Install & 5-Second Quickstart**:
   - End-user install via `uvx --from verity-redteam-core verity ...` and `pip install verity-redteam-core` (plus note on cloning from source if not yet on PyPI).
   - 3 immediate copy-paste commands (`verity scan`, `verity test --demo`, `verity test --sql "..."`).
3. **Customer Pain Points & Verified Solutions (6 End-to-End Scenarios)**:
   Every scenario follows a consistent, scannable format:
   - **Pain Point** (who feels it & what breaks without Verity)
   - **What You Run** (exact CLI command / config / Python snippet)
   - **Detailed Result** (verbatim sanitized output captured from `M8` empty-container snapshots, with verbose JSON/Markdown inside `<details>` blocks)
   - **How It Solves Your Problem** (concrete remediation & risk reduction)
   Covering all 6 scenarios:
   1. *Shadow MCP Servers, Leaked API Keys & Known CVEs on Developer Laptops* (`verity scan`, `--config-file`, `--fail-on-findings` -> `SEC-STATIC-SECRET-IN-CONFIG`, `SEC-STATIC-UNSAFE-SHELL-WRAPPER`, `VULN-CVE-*`).
   2. *Tool Poisoning, Hidden Prompt Injection & Exfiltration in 3rd-Party MCP Servers* (`verity test --command`, `verity test --url`, `verity scan --schema-file` -> `CWE-74`, `CWE-358`, `CWE-200`, `CWE-918`).
   3. *LLM-Generated SQL Injection, Comment-Splitting & Cross-Tenant Leaks* (`verity test --sql` + embeddable `SqlSecurityGuard` Python example with `validate_single_select_statement`, `enforce_tenant_filter`, `apply_projection`).
   4. *RCE & Unsafe Patterns in Custom Python MCP Servers (CI/CD Gate)* (`verity scan --path ./src --fail-on-findings` -> `VERITY-AST-CWE-94-EVAL`, `CWE-78`, `CWE-502`, `CWE-22`, `CWE-79`, `CWE-862`).
   5. *Proving Exploitability vs. Defense in 5 Seconds (Zero Docker, Zero API Keys)* (`verity test --demo` real CLI output + `--format html|markdown|json` executive report export).
   6. *In-IDE Self-Auditing & Rug-Pull Detection* (`verity serve` MCP JSON snippet for Cursor / Claude Desktop / Antigravity + 4 unified MCP tools + UCP `detect_rug_pull`).
4. **Full Free Capability Reference**:
   - Compact reference tables for: 9 supported AI clients, 13 `VERITY-STATIC-*` rules (+ CWEs), 9 `VERITY-AST-*` rules (+ CWEs), output formats (`terminal`, `json`, `markdown`, `html`), and exit codes (`0`, `1`, `2`).
5. **CI/CD Integration & Reproducible Verification**:
   - Ready-to-paste GitHub Actions workflow snippet (`verity scan --path ... --schema-file ... --fail-on-findings`).
   - Link to `tests/e2e_containers/README.md` so users can verify everything themselves from scratch in empty containers.
6. **Free vs. Enterprise (`verity-pro`)**:
   - Accurate feature matrix; move `entry_points(group="verity.plugins")` plugin authoring details into `docs/extensibility.md` and link it concisely.
7. **Development & License**:
   - Contributor quick commands (`uv sync --extra dev`, `pytest`, `ruff`) and Apache-2.0 license link.

---

## 3. Automated Documentation Parity Guard (`tests/unit/test_documentation_parity.py`)

Model after `mcp-vulnerabilities/tests/test_documentation_parity.py` to prevent README drift in CI:
- Parse `build_parser()` in `src/verity/cli.py` programmatically to extract all subcommands (`scan`, `test`, `serve`), flags (`--config-file`, `--schema-file`, `--path`, `--format`, `--output`, `--fail-on-findings`, `--demo`, `--target`, `--sql`, `--url`, `--command`, `--transport`, `--host`, `--port`), and format choices.
- Inspect `README.md` to assert:
  1. Every `verity <subcommand> [--flag ...]` CLI invocation shown in `README.md` uses only valid subcommands, valid flags, and valid `--format` choices present in `build_parser()`.
  2. No stale `verity-core` install or `uvx --from verity-core` references exist in `README.md`.
  3. All relative local links and media embeds in `README.md` (including `docs/assets/demo.gif`, `docs/extensibility.md`, `LICENSE`) resolve to existing files on disk.
  4. `README.md` documents every Free subcommand and key capability groups (all 4 `verity test --demo` target concepts, AST scanning, live probing, SQL guard, `verity serve`).

---

## 4. Deliverables

- Updated `verityredteam-free/README.md`
- New `verityredteam-free/docs/extensibility.md` (extracted from current README `## Extensibility` section)
- Removal of static `verityredteam-free/docs/assets/demo.svg` (replaced by `docs/assets/demo.gif` from `M9`)
- New `verityredteam-free/tests/unit/test_documentation_parity.py`

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run pytest tests/unit/test_documentation_parity.py -q
uv run pytest tests/ -q
uv run ruff check src tests
```

---

## 6. Acceptance Criteria

- [x] `README.md` leads with real customer pain points, copy-paste commands, container-verified outputs (verbatim from `M8` snapshots), and clear explanations of how each pain point is solved.
- [x] Hero embeds narrow animated `docs/assets/demo.gif` (`M9`), and stale `docs/assets/demo.svg` is retired.
- [x] All Free capabilities (`scan` config/schema/AST/OSV/secrets, `test` demo/sql/url/command, `serve` MCP server + UCP, `SqlSecurityGuard` Python API, formats & exit codes) are accurately documented with zero exaggerated claims.
- [x] `tests/unit/test_documentation_parity.py` enforces CLI/flag/link/package-name parity and passes in CI.
- [x] `uv run pytest tests/ -q` and `uv run ruff check src tests` pass cleanly.

---

## 7. Out of Scope

- Changing core Python runtime behavior (belongs in `M7`).
- Recording new GIFs or changing container topologies (belongs in `M8` / `M9`).
