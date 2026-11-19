# M8: Ground-Zero Empty-Container E2E Customer Verification Suite

- **Task ID**: `M8`
- **Priority**: `P0`
- **Status**: `Done`
- **Dependencies**: `M7`
- **Blocks**: `M9`, `M10`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Problem Statement & Goal

To make sure every customer workflow documented in `README.md` works reliably in the real world (not just against host-cached dev environments or editable workspace installs), we must validate `verity-redteam-core` inside **empty, clean containers from scratch**:
- Zero pre-installed `verity` package,
- Zero editable source mounts from the host repository,
- Zero host `~/.cursor` / `~/.claude` / `~/.cache/verity` mounts,
- Fresh installation of `verity-redteam-core`,
- Fresh installation of **both** real open-source vulnerable MCP servers and deterministic self-contained vulnerable fixtures,
- Automated execution of all 6 customer scenarios, asserting exact exit codes, expected Rule IDs/CWEs, secret scrubbing, and valid report artifacts, while capturing sanitized verbatim CLI output snapshots for `M10`.

---

## 2. Confirmed Decisions & Architecture

1. **Package Install Toggle (`INSTALL_SOURCE`)**:
   - `INSTALL_SOURCE=wheel` *(default right now before PyPI release)*: Builds a clean distribution wheel via `uv build` (`dist/verity_redteam_core-*.whl`), copies only the `.whl` file into the fresh container, and runs `pip install /tmp/dist/*.whl` (or `uvx --from /tmp/dist/*.whl verity ...`).
   - `INSTALL_SOURCE=pypi`: Installs directly from live PyPI (`pip install verity-redteam-core` and `uvx --from verity-redteam-core verity ...`) once `v0.1.0+` is published.
2. **Both Vulnerable Target Tiers Installed From Scratch**:
   - **Tier A — Real Public Vulnerable MCP Packages**:
     - **Pinned `mcp-remote@0.1.15`** (npm package with known `CVE-2025-6514` in `mcp-vulnerabilities` OSV database), installed inside the container to verify real config/OSV CVE detection.
     - **Open-source DVMCP** (*Damn Vulnerable MCP Server*, `harishsg993010/damn-vulnerable-mcp-server`, pinned commit/tag) installed inside the container and probed live + scanned via Python AST.
   - **Tier B — Deterministic Self-Contained Vulnerable Fixtures** (`tests/e2e_containers/fixtures/`):
     - Standalone installable vulnerable Python MCP server fixture (`stdio` and `HTTP/SSE` modes) exposing poisoned tool descriptions (`VERITY-STATIC-INJECTION-OVERRIDE` `CWE-74`, `VERITY-STATIC-TOOL-POISONING` `CWE-358`, `VERITY-STATIC-EXFIL-WEBHOOK` `CWE-200`, `VERITY-STATIC-METADATA-SSRF` `CWE-918`) plus unsafe Python handler code (`eval()` `CWE-94`, `subprocess.run(..., shell=True)` `CWE-78`, `yaml.load()` `CWE-502`) for `verity scan --path`.
     - Realistic generated workstation IDE configs created clean inside the container's `$HOME` (`~/.cursor/mcp.json`, `~/.config/Claude/claude_desktop_config.json`, `~/.continue/config.yaml`, `./.mcp.json`) containing plaintext API keys/DB URLs, a raw `bash -c` wrapper, and `mcp-remote@0.1.15`.
     - Adversarial SQL payload corpus (`; DROP TABLE`, `DE/**/LETE`, `pg_shadow`, safe parameterized `SELECT`) + exported `vendor-tools.json` schema.

---

## 3. Proposed 4-Container Verification Matrix

All container artifacts live under `tests/e2e_containers/` (keeping core `verity-redteam-core` runtime strictly zero-Docker per `AGENTS.md`).

| Container | Base Image | Purpose | Installed From Scratch Inside Container |
| :--- | :--- | :--- | :--- |
| **`customer-pip`** *(Primary)* | `python:3.12-slim-bookworm` | Cleanest Python 3.12 pip install & full 6-scenario verification runner | `verity-redteam-core` (`wheel` or `pypi`), DVMCP + local vulnerable fixture, realistic IDE configs |
| **`customer-uvx`** *(5-Sec Quickstart)* | `ghcr.io/astral-sh/uv:python3.12-bookworm-slim` | Cold-start `uvx` 5-second quickstart verification | Nothing pre-installed; runs `uvx` cold for `verity scan`, `verity test --demo`, `verity test --sql` |
| **`customer-full-workstation`** *(Bare OS + Node + Python)* | `ubuntu:24.04` | Proves full ground-zero setup on a fresh Linux workstation | `python3.12`, `nodejs`/`npm`, `mcp-remote@0.1.15`, DVMCP, realistic `~/.cursor/mcp.json`, `verity-redteam-core` |
| **`target-sse-lab`** *(Isolated Network Target)* | `python:3.12-slim-bookworm` | Separate Compose service on internal Docker network (zero host ports) | Freshly installed vulnerable HTTP/SSE MCP server target probed over network by `customer-pip` via `verity test --url http://target-sse-lab:8000/sse` |

---

## 4. Customer Use Cases & Pass/Fail Assertions (`verify_all_scenarios.sh`)

`tests/e2e_containers/verify_all_scenarios.sh` executes and validates all 6 customer scenarios, exporting sanitized verbatim outputs into `tests/e2e_containers/snapshots/`:

1. **Scenario 1 — Workstation Config, Secret Scrubbing, Shell Wrapper & OSV CVE Audit**:
   - Commands:
     - `verity scan` (auto-discovers generated `~/.cursor/mcp.json`, `~/.config/Claude/claude_desktop_config.json`, `~/.continue/config.yaml`, `./.mcp.json`)
     - `verity scan --config-file ~/.cursor/mcp.json --fail-on-findings`
     - `verity scan --format json --output /tmp/out/scan.json`
     - `verity scan --format markdown --output /tmp/out/scan.md`
     - `verity scan --format html --output /tmp/out/scan.html`
   - Assertions:
     - `--fail-on-findings` exits `1`.
     - Reports `SEC-STATIC-SECRET-IN-CONFIG`, `SEC-STATIC-UNSAFE-SHELL-WRAPPER`, YAML Continue config findings, and OSV CVE match (`CVE-2025-6514` for `mcp-remote@0.1.15` when dataset/cache is present or pre-warmed cleanly).
     - **Zero raw secret values** appear anywhere in `stdout`, `scan.json`, `scan.md`, or `scan.html` (must show `****`).
     - JSON is valid via `python3 -m json.tool`; HTML/Markdown are non-empty.

2. **Scenario 2 — Live Vulnerable MCP Server Probing (`stdio` & `HTTP/SSE`) + Schema Screen**:
   - Commands:
     - `verity test --command "python3 /opt/targets/vuln_stdio_mcp.py"`
     - `verity test --command "python3 /opt/dvmcp/..."` (pinned DVMCP challenge server)
     - `verity test --url http://target-sse-lab:8000/sse`
     - `verity scan --schema-file /opt/fixtures/vendor-tools.json --fail-on-findings`
   - Assertions:
     - All vulnerable server/schema checks exit `1` and report expected static rule IDs / CWEs (`CWE-74`, `CWE-358`, `CWE-200`, `CWE-918`).
     - Also probe a clean/benign fixture MCP server and assert exit `0`.

3. **Scenario 3 — Deterministic SQL AST Guard (CLI + Python Library Import)**:
   - Commands:
     - `verity test --sql "SELECT id FROM users; DROP TABLE users;--"` -> assert `FAIL`, exit `1`
     - `verity test --sql "DE/**/LETE FROM users"` -> assert `FAIL`, exit `1`
     - `verity test --sql "SELECT usename, passwd FROM pg_shadow"` -> assert `FAIL`, exit `1`
     - `verity test --sql "SELECT id, email FROM orders WHERE tenant_id = :tenant_id"` -> assert `PASS`, exit `0`
     - Python import smoke test of `SqlSecurityGuard` (`validate_single_select_statement`, `enforce_tenant_filter`, `apply_projection`) verifying tenant isolation and `password_hash` projection masking.

4. **Scenario 4 — Python AST Source Code Scanner (CI/CD PR Gate)**:
   - Commands:
     - `verity scan --path /opt/targets/ast_vuln_samples --fail-on-findings --format markdown --output /tmp/out/ast.md`
   - Assertions:
     - Exits `1`, detects `VERITY-AST-CWE-94-EVAL`, `VERITY-AST-CWE-78-SHELL`, `VERITY-AST-CWE-502-YAML` (and additional AST rules included in fixture).
     - Clean Python directory with `--fail-on-findings` exits `0`.

5. **Scenario 5 — 5-Second Zero-Docker 4-Target Demo & Report Exports**:
   - Commands:
     - `verity test --demo`
     - `verity test --demo --format html --output /tmp/out/demo.html`
     - `verity test --demo --format json --output /tmp/out/demo.json`
   - Assertions:
     - Exits `0`, `Passed: 4`, `Failed: 0` across `sqlite-basic`, `postgres-basic`, `mongo-basic`, `code-exec-basic`, valid HTML and JSON output.

6. **Scenario 6 — IDE MCP Server Mode (`verity serve`)**:
   - Commands:
     - Start `verity serve --transport http --host 127.0.0.1 --port 8765` in background, curl `/health` (`200 OK`).
     - Run `verity serve --transport stdio` JSON-RPC client check (`initialize`, `tools/list`, `tools/call` on `verity_security_scan` & `verity_database_guard`).
   - Assertions:
     - `/health` returns `200`; `tools/list` exposes the 4 unified tools; `tools/call` returns structured findings and SQL validation verdicts without errors.

---

## 5. Deliverables & File Layout

```text
verityredteam-free/
├── .github/workflows/
│   └── e2e-containers.yml              # Opt-in / release / manual workflow (keeps ci.yml zero-Docker)
└── tests/e2e_containers/
    ├── README.md                       # How to run locally with INSTALL_SOURCE=wheel|pypi
    ├── docker-compose.verify.yml       # customer-pip, customer-uvx, customer-full-workstation, target-sse-lab
    ├── Dockerfile.customer-pip
    ├── Dockerfile.customer-uvx
    ├── Dockerfile.customer-workstation
    ├── Dockerfile.target-sse-lab
    ├── fixtures/                       # Self-contained vulnerable stdio/SSE MCP servers, AST sample, configs
    ├── verify_all_scenarios.sh         # Full pass/fail assertions + snapshot exporter
    └── snapshots/                      # Sanitized verbatim CLI transcripts used by M10 README
```

---

## 6. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv build
INSTALL_SOURCE=wheel docker compose -f tests/e2e_containers/docker-compose.verify.yml build --no-cache
INSTALL_SOURCE=wheel docker compose -f tests/e2e_containers/docker-compose.verify.yml up --abort-on-container-exit --exit-code-from customer-pip
docker compose -f tests/e2e_containers/docker-compose.verify.yml down -v
```

---

## 7. Acceptance Criteria

- [x] Containers start strictly empty (no mounted host repo source, no host user IDE configs, no pre-installed `verity`).
- [x] `INSTALL_SOURCE=wheel` passes across all 4 containers (`customer-pip`, `customer-uvx`, `customer-full-workstation`, `target-sse-lab`); `INSTALL_SOURCE=pypi` is cleanly parameterized and documented.
- [x] Both pinned public targets (`mcp-remote@0.1.15`, DVMCP) and self-contained vulnerable fixtures install cleanly from scratch inside the containers and are caught by `verity`.
- [x] All 6 customer scenarios execute end-to-end with verified exit codes, expected rule IDs/CWEs, and zero raw secret leaks.
- [x] Sanitized output snapshots are saved under `tests/e2e_containers/snapshots/` for `M10`.
- [x] Core `.github/workflows/ci.yml` remains zero-Docker; container suite runs via `.github/workflows/e2e-containers.yml`.

---

## 8. Out of Scope

- Modifying core scanner/guard business logic (any newly discovered CLI bugs go back to `M7` or a tracked follow-up).
- Testing `verity-pro` proprietary features inside `verityredteam-free` containers.
