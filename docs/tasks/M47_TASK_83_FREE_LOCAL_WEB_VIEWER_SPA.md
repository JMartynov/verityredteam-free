---
task_id: M47
alias: TASK-83-FREE
title: "Zero-Signup Local Web Viewer (verity view Core SPA & Server)"
status: Not Done
priority: Medium (P1)
size: L
estimate_days: 6
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhMEjFQ
target_repos: [verityredteam-free]
---

# M47 (`TASK-83-FREE`): Zero-Signup Local Web Viewer (`verity view` Core SPA & Server)

## Purpose & Architectural Decisions
- **Loopback-Hardened Pure-Stdlib Server**: Expose `verity view` binding `ThreadingHTTPServer` strictly to loopback (`127.0.0.1`, `::1`, `localhost`), rejecting non-loopback `--host` at CLI startup, enforcing DNS-rebinding `Host`/`Origin` validation (`403 Forbidden`), strict `Content-Security-Policy` (`script-src 'self'; object-src 'none'; frame-ancestors 'none'`), and `X-Verity-View-Token` gating on `--allow-live-scan` (`POST /api/v1/scan`) and `POST /api/v1/explain` (returns Pro-gated `501`/`403` JSON without `verity-pro`).
- **Artifact Indexer & Live SSE Watch**: Index Free artifacts (`verity.scan.v1`, `verity.test.v1`, `verity.stream.jsonl`) with `?offset=&limit=` pagination and stream `text/event-stream` `artifact_added`/`artifact_updated` events on `GET /api/v1/events` when `--watch` is enabled.
- **Zero-Build Vanilla ES Module SPA + Plugin Registry**: Package static SPA assets (`index.html`, `style.css`, `app.js`, `views/*.js`) via `importlib.resources` with zero external CDN `<script>`/`<link>` tags, plus `ViewerRegistry` extension hooks for optional Pro tab renderers.

## Target Files
| File | Change |
| :--- | :--- |
| `src/verity/viewer/__init__.py` | `ViewerRegistry` plugin hook for optional Pro tabs/parsers |
| `src/verity/viewer/indexer.py` | JSON/JSONL artifact classifier (`verity.scan.v1`, `verity.test.v1`, `verity.stream.jsonl`) |
| `src/verity/viewer/server.py` | Loopback HTTP + `--watch` SSE server with CSP & DNS-rebinding guards |
| `src/verity/viewer/static/` | Zero-build vanilla ES module SPA (`index.html`, `style.css`, `app.js`, `views/*.js`) |
| `src/verity/cli.py` | `verity view` subcommand (`--host`, `--port`, `--watch`, `--allow-live-scan`) |
| `pyproject.toml` | Package data inclusion for `verity.viewer` static assets |
| `tests/unit/viewer/test_viewer_server.py` | Loopback, CSP, token-gating, SSE, and asset packaging tests |

## ATDD Traceability Matrix
| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-47.1` | `verity view` binds loopback only and rejects non-loopback `--host` at startup. | Default `127.0.0.1` with ephemeral fallback starts cleanly. | `unit` | `tests/unit/viewer/test_viewer_server.py::test_loopback_binding` |
| `AC-47.2` | Server enforces `Host`/`Origin` DNS-rebinding checks (`403`), CSP headers, and `X-Verity-View-Token` on mutations. | Valid loopback `Host` + token succeeds. | `unit` | `tests/unit/viewer/test_viewer_server.py::test_security_headers_and_tokens` |
| `AC-47.3` | Artifact indexer classifies Free JSON/JSONL artifacts, streams `--watch` SSE events, and gates `/api/v1/explain` in Free. | Empty directory returns empty paginated index cleanly. | `unit` | `tests/unit/viewer/test_viewer_server.py::test_indexer_sse_and_pro_gate` |
| `AC-47.4` | `importlib.resources` resolves SPA static files with zero external CDN references; ruff clean. | All static files load without network egress. | `ruff` | `uv run ruff check src tests` |
