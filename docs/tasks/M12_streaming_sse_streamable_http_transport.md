# M12: Real Streaming SSE (`text/event-stream`) & Streamable HTTP Transport Support

- **Task ID**: `M12`
- **Priority**: `P1` (Master Rank `#1`, Track A — Product & Customer Value)
- **Status**: `Todo`
- **Dependencies**: `M8`, `M11`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

In `src/verity/discovery/transports/sse.py`, `HttpSseDiscoveryTransport._probe_single_url()` currently sends `Accept: application/json, text/event-stream` on `POST` and `GET`, but reads the entire HTTP response body to EOF (`resp.read()`) and parses it with `json.loads(body)`:
- Real remote MCP servers (FastMCP, official Python/TypeScript MCP SDK servers, DVMCP SSE servers) serve **Streamable HTTP** (`POST /mcp` returning `text/event-stream` or `application/json` with `mcp-session-id` after `initialize`) or **legacy HTTP+SSE** (`GET /sse` emitting `event: endpoint` + persistent `data:` frames while client posts JSON-RPC to the advertised messages URL).
- Calling `resp.read()` on an open `text/event-stream` response blocks until socket timeout or fails `json.loads()`, causing `verity test --url <endpoint>` to hang or return zero findings against real remote MCP servers.
- Today, `tests/e2e_containers/fixtures/vuln_sse_mcp.py` works around this limitation by returning finite `application/json` on `GET /sse`.

---

## 2. Requirements & Target Files

### Core Transport (`src/verity/discovery/transports/sse.py`)
1. **Incremental `text/event-stream` Frame Parser (Zero Extra Runtime Dependencies)**:
   - Use Python stdlib (`http.client` / `urllib`) to read streaming responses line-by-line with a strict wall-clock deadline (`timeout_seconds`), never blocking for EOF on an open stream.
   - Parse standard SSE frames (`event:`, multi-line `data:`, blank-line frame delimiter, comment `:` keepalive lines).
   - Stop reading and close the connection as soon as the matching JSON-RPC `id` response (`result` or `error`) is received.
2. **Streamable HTTP Handshake (`/mcp` Standard)**:
   - Send JSON-RPC `initialize` via `POST` with `Accept: application/json, text/event-stream`.
   - Capture `mcp-session-id` (case-insensitive header) if returned, send `notifications/initialized` if appropriate, and send `tools/list` (plus `prompts/list` / `resources/list` best-effort) carrying `mcp-session-id`.
   - Handle both `Content-Type: text/event-stream` and `Content-Type: application/json` responses seamlessly.
3. **Legacy HTTP+SSE Handshake (`/sse` + `event: endpoint`)**:
   - When `POST` is rejected (`405`/`404`) or `GET` returns `text/event-stream` with `event: endpoint`, extract the relative/absolute messages URI from `data:`, post `initialize` + `tools/list` to that endpoint, and read the corresponding JSON-RPC response frame from the open `GET` SSE stream within `timeout_seconds`.
4. **Backward-Compatible Finite JSON Fallback**:
   - Preserve the existing finite `application/json` `POST`/`GET` path so `tests/e2e_containers/fixtures/vuln_sse_mcp.py` and existing unit tests continue to pass unchanged.

---

## 3. Automated Tests to Verify

### A. Unit & Local Integration Tests (`tests/unit/test_sse_transport.py`)
Create a dedicated unit/integration test module spinning up real local `ThreadingHTTPServer` instances on ephemeral `127.0.0.1:0` ports (zero external network, zero Docker, runs in `<2s` in `pytest`):
1. **Streamable HTTP (`text/event-stream` `POST /mcp`)**:
   - Server keeps connection open after flushing `event: message\ndata: {"jsonrpc":"2.0","id":...,"result":{"tools":[...]}}\n\n` (chunked transfer, no EOF).
   - Assert `HttpSseDiscoveryTransport(timeout_seconds=3.0).inspect(cfg)` returns `is_responsive=True`, extracts all tools, and completes in `<1.5s` (proving it does NOT wait for EOF/timeout).
2. **Streamable HTTP Session Binding (`mcp-session-id`)**:
   - Server requires `POST initialize` first, returns `Mcp-Session-Id: sess-123`, and rejects `tools/list` without that header (`400`/`401`).
   - Assert `inspect()` captures `mcp-session-id` and retrieves `tools/list` cleanly.
3. **Legacy HTTP+SSE (`GET /sse` + `event: endpoint` + `POST /messages`)**:
   - Server rejects `POST /sse` (`405`), streams `event: endpoint\ndata: /messages?session_id=abc\n\n` on `GET /sse`, and pushes the JSON-RPC `tools/list` response onto the open SSE stream when `POST /messages?session_id=abc` is called.
   - Assert `inspect()` discovers all tools and closes the stream cleanly.
4. **Multi-line `data:` & Keepalive Comment (`: ping`) Resilience**:
   - Server emits `: keepalive\n\n` and a pretty-printed JSON payload split across multiple `data:` lines.
   - Assert payload reassembly and tool extraction succeed.
5. **Finite `application/json` Backward Compatibility**:
   - Server behaves like `vuln_sse_mcp.py` (immediate finite `application/json` on `POST` / `GET`).
   - Assert `inspect()` returns `is_responsive=True` with all tools.
6. **Bounded Timeout & Malformed Stream Handling**:
   - Server holds `text/event-stream` open sending only `: ping` and never sends a JSON-RPC result.
   - Assert `inspect()` terminates cleanly near `timeout_seconds` without hanging or raising an unhandled exception.
7. **CLI End-to-End (`verity test --url`)**:
   - Invoke `verity.cli.main(["test", "--url", ..., "--format", "json"])` against both a poisoned streaming SSE server (assert exit `1` and `VERITY-STATIC-INJECTION-OVERRIDE` / `VERITY-STATIC-EXFIL-WEBHOOK` in `message` & `details`) and a clean streaming SSE server (assert exit `0` and `PASS`).

---

## 4. Acceptance Scenario with a Real MCP Server

Verify `verity test --url` against a **real third-party streaming MCP server** (not a hand-written `BaseHTTPRequestHandler` mock) inside the clean-room container harness (`tests/e2e_containers/`):

1. **Real Target Setup (`tests/e2e_containers/Dockerfile.target-sse-lab` & `docker-compose.verify.yml`)**:
   - Install the official Python **`mcp` SDK (`FastMCP`)** inside the `target-sse-lab` container (keeping `verity-redteam-core`'s own runtime dependencies strictly unchanged and zero-Docker).
   - Run a real `FastMCP` server exposing:
     - **Poisoned Streamable HTTP endpoint** (`http://target-sse-lab:8001/mcp`, `transport="streamable-http"`) with poisoned tool descriptions (`VERITY-STATIC-INJECTION-OVERRIDE`, `VERITY-STATIC-EXFIL-WEBHOOK`, `VERITY-STATIC-METADATA-SSRF`).
     - **Clean Streamable HTTP endpoint** (`http://target-sse-lab:8002/mcp`, `transport="streamable-http"`) with benign read-only tools.
     - *(Keep existing finite-JSON `vuln_sse_mcp.py` on `:8000/sse` to verify backward compatibility.)*
2. **Real-Server Acceptance Commands (in `tests/e2e_containers/verify_all_scenarios.sh`)**:
   ```bash
   # 1. Poisoned real FastMCP Streamable HTTP server -> must exit 1 & report static rule IDs without hanging
   verity test --url "http://target-sse-lab:8001/mcp" --format json

   # 2. Clean real FastMCP Streamable HTTP server -> must exit 0 & report PASS
   verity test --url "http://target-sse-lab:8002/mcp"

   # 3. Existing finite-JSON endpoint -> must continue to exit 1 & report static rule IDs
   verity test --url "http://target-sse-lab:8000/sse" --format json
   ```
3. **Acceptance Assertions**:
   - Poisoned real `FastMCP` server returns exit code `1`, `status == "FAIL"`, and includes `VERITY-STATIC-INJECTION-OVERRIDE`, `VERITY-STATIC-EXFIL-WEBHOOK`, and `VERITY-STATIC-METADATA-SSRF` in both `message` and `details`, completing in `<5s`.
   - Clean real `FastMCP` server returns exit code `0` and `status == "PASS"`.
   - Full `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh` passes across all 4 containers.

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/unit/test_sse_transport.py -v
uv run pytest tests/
INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] `HttpSseDiscoveryTransport` parses incremental `text/event-stream` frames (`event:` / `data:`) with bounded timeout and never hangs waiting for EOF on open streams.
- [ ] Streamable HTTP (`initialize` + `mcp-session-id` + `tools/list`) and legacy HTTP+SSE (`event: endpoint`) both work alongside the existing finite `application/json` fallback.
- [ ] All unit/integration tests in `tests/unit/test_sse_transport.py` pass (`ruff` clean, full `pytest tests/` green, zero new runtime dependencies in `pyproject.toml`).
- [ ] Real-server acceptance scenario against a live `FastMCP` Streamable HTTP server passes in `tests/e2e_containers/run_e2e.sh` (poisoned server exits `1` with expected `VERITY-STATIC-*` IDs; clean server exits `0`).
