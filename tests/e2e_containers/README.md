# End-to-End Empty-Container Verification Suite

Ground-zero verification that every customer workflow in `README.md` works from a clean,
empty container with **no** mounted host source, **no** host IDE configs, and **no**
pre-installed `verity` package.

## Layout

| Path | Purpose |
| :--- | :--- |
| `run_e2e.sh` | One-shot runner: builds wheel, stages it, builds images, runs all customers. |
| `docker-compose.verify.yml` | Defines the 4 containers on an internal `verity-e2e-net` network. |
| `Dockerfile.target-sse-lab` | Isolated vulnerable HTTP/SSE MCP target (no host ports). |
| `Dockerfile.customer-pip` | `python:3.12-slim` + pip install (wheel or pypi) + DVMCP + fixtures. |
| `Dockerfile.customer-uvx` | Cold-start `uvx` quickstart checks (no global install). |
| `Dockerfile.customer-workstation` | Fresh `ubuntu:24.04` + Node + Python venv + `mcp-remote@0.1.15`. |
| `verify_all_scenarios.sh` | Executes and asserts all 6 customer scenarios + exports snapshots. |
| `fixtures/` | Deterministic vulnerable/clean MCP servers, AST sample, schema. |
| `snapshots/` | Sanitized verbatim transcripts (populated by `customer-pip`). |

## Install source toggle

`INSTALL_SOURCE` selects how `verity-redteam-core` is installed inside the containers:

- `INSTALL_SOURCE=wheel` *(default)* — builds a clean `.whl` via `uv build`, stages it in
  `tests/e2e_containers/.build_dist/`, and installs from the wheel.
- `INSTALL_SOURCE=pypi` — installs `verity-redteam-core` directly from PyPI.

## Run

```bash
INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
INSTALL_SOURCE=pypi  ./tests/e2e_containers/run_e2e.sh
```

`run_e2e.sh` always builds/stages the wheel first (`.build_dist/`), then:

1. `docker compose build --no-cache` with the selected `INSTALL_SOURCE`.
2. `docker compose up -d --wait target-sse-lab`.
3. Runs each customer container independently (`docker compose run --rm ...`) so that one
   finishing never aborts the others. Every exit code is asserted.

> `docker compose build` directly requires `.build_dist/` to exist (created by
> `run_e2e.sh`), because the wheel is `COPY`-ed into the image at build time.

## Scenarios verified

1. **Workstation scan** — auto-discovers `~/.cursor/mcp.json`,
   `~/.config/Claude/claude_desktop_config.json`, `~/.continue/config.yaml`,
   `./.mcp.json`; asserts `SEC-STATIC-SECRET-IN-CONFIG`,
   `SEC-STATIC-UNSAFE-SHELL-WRAPPER`, and `VULN-CVE-2025-6514`; verifies `****` masking;
   verifies no raw secret leaks and that `${OPENAI_API_KEY}` env references are **not**
   flagged.
2. **Live probes** — vulnerable/clean `stdio` servers, network `HTTP/SSE` target, and
   `--schema-file` screen; asserts FAIL/PASS and rule IDs.
3. **SQL AST guard** — stacked statements, comment-split (`DE/**/LETE`), `pg_shadow`
   catalog access all rejected; parameterized tenant query allowed; runtime
   `SqlSecurityGuard` import checks.
4. **Python AST scanner** — vulnerable fixture, DVMCP checkout, and clean file gates.
5. **Zero-Docker demo** — 4 in-memory targets pass with HTML/JSON exports.
6. **IDE MCP server** — `verity serve --transport http` `/health` and
   `verity serve --transport stdio` JSON-RPC (`initialize`, `tools/list`, `tools/call`).

## Clean-room guarantees

- Compose build context is `tests/e2e_containers/` only.
- No `src/` mount, no host `~/.cache`, `~/.cursor`, or `~/.claude` mounts.
- Only `./snapshots` is mounted (into `customer-pip`).
- `target-sse-lab` exposes **no** host ports.
