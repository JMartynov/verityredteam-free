---
task_id: M35
alias: TASK-92
title: "Authenticated Remote Probing (OAuth/Bearer) & Bait-and-Switch Detection"
status: Not Done
priority: High (P0)
size: S
estimate_days: 3
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhLJPm8
target_repos: [verityredteam-free]
---

# M35 (`TASK-92`): Authenticated Remote Probing (OAuth/Bearer) & Bait-and-Switch Detection

## Purpose & Architectural Decisions
- **Redacted Auth Header Support**: Add `headers` parsing to `DiscoveredServerConfig` (exposing only redacted `header_keys` in `to_dict()`, flagging plaintext auth tokens via `SEC-STATIC-SECRET-IN-CONFIG`), and forward configured/CLI `--bearer-token` and `--header` headers in `HttpSseDiscoveryTransport` across Streamable HTTP `POST` and legacy SSE `GET`/`POST`.
- **Client Identity & Bait-and-Switch Detection**: Parameterize `initialize.params.clientInfo.name` via `--identify-as <client>` across both `HttpSseDiscoveryTransport` and `StdioDiscoveryTransport`, and add differential `--detect-bait-and-switch` probing comparing canonical SHA-256 `tools/list` hashes across `VerityDiscovery`, `claude-desktop`, and `cursor` (`BAIT_AND_SWITCH_DETECTED`, `CRITICAL`).
- **Strict Secret Scrubbing**: Reject malformed `--header` (missing `:`) with exit code `2` and scrub all sensitive header/token values across CLI and audit outputs.

## Target Files
| File | Change |
| :--- | :--- |
| `src/verity/discovery/models.py` | Redacted `headers` field and `header_keys` serialization on `DiscoveredServerConfig` |
| `src/verity/discovery/config_scanner.py` | Parse config `headers` and flag hardcoded plaintext auth tokens |
| `src/verity/discovery/transports/sse.py` | Forward auth headers on HTTP/SSE and parameterize `clientInfo.name` |
| `src/verity/discovery/transports/stdio.py` | Parameterize `initialize.params.clientInfo.name` via `identify_as` |
| `src/verity/cli.py` | Add `--header`, `--bearer-token`, `--identify-as`, `--detect-bait-and-switch` with scrubbing |
| `tests/unit/test_auth_and_bait_switch.py` | Paired unit tests for auth headers, client spoofing diff, and secret scrubbing |

## ATDD Traceability Matrix
| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-35.1` | `DiscoveredServerConfig` parses `headers`, exposes only `header_keys`, and flags plaintext auth headers. | `${ENV_VAR}` placeholder headers are clean and never flagged. | `unit` | `tests/unit/test_auth_and_bait_switch.py::test_config_headers_redacted` |
| `AC-35.2` | `HttpSseDiscoveryTransport` sends `--bearer-token` and `--header` on Streamable HTTP and legacy SSE. | Unauthenticated probe against protected server fails cleanly without crash. | `unit` | `tests/unit/test_auth_and_bait_switch.py::test_authenticated_sse_probe` |
| `AC-35.3` | `--identify-as <client>` overrides `clientInfo.name` on SSE and stdio; default remains `VerityDiscovery`. | Omitting `--identify-as` preserves `VerityDiscovery`. | `unit` | `tests/unit/test_auth_and_bait_switch.py::test_identify_as_override` |
| `AC-35.4` | `--detect-bait-and-switch` diffs canonical `tools/list` hashes across 3 client names (`BAIT_AND_SWITCH_DETECTED`). | Identical responses across all 3 identities return `PASS`. | `unit` | `tests/unit/test_auth_and_bait_switch.py::test_bait_and_switch_detection` |
| `AC-35.5` | Malformed `--header` exits `2`; bearer/auth secrets never leak in reports; ruff clean. | Valid `Header: Value` parses cleanly. | `ruff` | `uv run ruff check src tests` |
