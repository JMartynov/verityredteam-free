# M14: True End-to-End `VERITY_OFFLINE` & Air-Gapped Cold-Start Baseline Support

- **Task ID**: `M14`
- **Priority**: `P2` (Master Rank `#3`, Track A — Product & Customer Value)
- **Status**: `Todo`
- **Dependencies**: `M7`, `M8`, `M11`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

When a user runs `verity scan --offline` (which sets `VERITY_OFFLINE=1` inside `src/verity/cli.py`), only `VulnerabilityIndex.load_auto()` (`src/verity/lookup/index.py`) currently honors `VERITY_OFFLINE`:
- `src/verity/data_fetcher.py::fetch_remote_snapshot()` never checks `VERITY_OFFLINE` and still attempts outbound HTTP fetches with `timeout=15.0`.
- `src/verity/fingerprint/matcher.py::FingerprintMatcher.load_auto()` calls `fetch_passports_snapshot()` and `load_from_directory()` calls `get_passports_path(download_if_missing=True)` unconditionally.
- `src/verity/lookup/index.py::VulnerabilityIndex.load_from_directory()` still calls `fetch_vulnerabilities_snapshot()` when the directory is missing or empty.
- On a cold air-gapped install (empty cache, zero internet egress), `verity scan --offline` can stall on outbound fetches and returns `0` OSV CVE advisories because no baseline snapshot is resolved locally.

---

## 2. Requirements & Target Files

1. **Centralize `VERITY_OFFLINE` Enforcement (`src/verity/data_fetcher.py`)**:
   - Add a helper `_is_offline()` checking `os.environ.get("VERITY_OFFLINE", "").lower() in ("1", "true", "yes")`.
   - Inside `fetch_remote_snapshot()`, when `_is_offline()` is `True`: read the local disk cache if present (regardless of TTL expiration) and **return immediately without opening any network connection**.
2. **Offline-Safe Fingerprinting & Vulnerability Loading (`src/verity/fingerprint/matcher.py`, `src/verity/lookup/index.py`)**:
   - Guard `FingerprintMatcher.load_from_directory()` (`download_if_missing=not _is_offline()`) and `load_auto()` so zero outbound network requests occur when `VERITY_OFFLINE=1`.
   - Guard `VulnerabilityIndex.load_from_directory()` when `_is_offline()` is `True` to avoid triggering remote fetches.
3. **Cold-Start Local Baseline Resolution (`pyproject.toml` / `data_fetcher.py` / `index.py` / `matcher.py`)**:
   - Resolve packaged baseline snapshots (from installed `mcp_fingerprints` / `mcp_vulnerabilities` package data if bundled, or a compact fallback snapshot / clear stderr notice when running offline on a cold cache with no local dataset) so air-gapped cold-start scans are fast, deterministic, and transparent.

---

## 3. Automated Tests to Verify

### Unit & Integration Tests (`tests/unit/test_offline_airgap.py`)
1. **Zero-Socket Hard Assertion (`VERITY_OFFLINE=1`)**:
   - Monkeypatch `urllib.request.urlopen` (and `socket.create_connection`) to `raise AssertionError("Network call forbidden in offline mode")`.
   - Construct `ConsolidatedSecurityAuditor()` and run `verity.cli.main(["scan", "--config-file", ..., "--offline"])` with an empty `VERITY_CACHE_DIR`.
   - Assert **zero network calls** are attempted across `VulnerabilityIndex`, `FingerprintMatcher`, and `data_fetcher.py`, and scan completes in `<1s`.
2. **Expired-Cache Offline Fallback**:
   - Pre-populate `VERITY_CACHE_DIR` with valid `passports.json.gz` and `vulnerabilities.json.gz` whose mtimes are older than `DEFAULT_TTL_SECONDS` (expired).
   - Run `verity scan --config-file ... --offline` with network blocked; assert expired caches are loaded cleanly and `VULN-CVE-2025-6514` is still detected for `mcp-remote@0.1.15`.
3. **Direct `load_from_directory()` Offline Safety**:
   - Call `FingerprintMatcher().load_from_directory(empty_dir)` and `VulnerabilityIndex().load_from_directory(empty_dir)` with `VERITY_OFFLINE=1` and network blocked; assert zero network calls and clean return.
4. **Online Default Preserved**:
   - Verify that when `VERITY_OFFLINE` is unset, normal online/conditional-ETag behavior in `fetch_remote_snapshot()` is unchanged.

---

## 4. Acceptance Scenario with a Real Air-Gapped Container & Local MCP Server

Verify true zero-network air-gapped execution inside a **Docker container with `--network none`** (kernel-level zero internet egress):

1. **Air-Gapped Container Test (`tests/e2e_containers/verify_all_scenarios.sh` or dedicated `--network none` step in `run_e2e.sh`)**:
   - Launch the already-built `customer-pip` image with **`docker run --rm --network none`** (completely severed from the internet and host network) and an empty `VERITY_CACHE_DIR=/tmp/cold_cache`.
   - Run against a local realistic workstation config (`~/.cursor/mcp.json` with plaintext secrets, `bash -c`, and `mcp-remote@0.1.15`) AND a real local `stdio` MCP server:
     ```bash
     # 1. Cold-cache air-gapped scan -> must complete in <3s with zero network errors
     VERITY_CACHE_DIR=/tmp/cold_cache verity scan --config-file /tmp/airgap_mcp.json --offline --fail-on-findings

     # 2. Local stdio probe in --network none container -> must catch poisoned tools & exit 1
     verity test --command "python3 /opt/fixtures/vuln_stdio_mcp.py"
     ```
2. **Acceptance Assertions**:
   - Command 1 completes in `<3s` (proving no 15-second HTTP timeout stall), exits `1`, detects `SEC-STATIC-SECRET-IN-CONFIG` + `SEC-STATIC-UNSAFE-SHELL-WRAPPER` (plus `VULN-CVE-2025-6514` when baseline/cache is present), and emits zero unhandled network tracebacks.
   - Command 2 exits `1` and detects all 4 `VERITY-STATIC-*` rules against the local MCP server with `--network none`.

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/unit/test_offline_airgap.py -v
uv run pytest tests/
INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] `VERITY_OFFLINE=1` / `verity scan --offline` makes **zero outbound network calls** across `data_fetcher.py`, `FingerprintMatcher`, and `VulnerabilityIndex`.
- [ ] Expired local caches are served cleanly in offline mode without attempting HTTP revalidation.
- [ ] `tests/unit/test_offline_airgap.py`, full `pytest tests/`, and `ruff check src tests` pass cleanly.
- [ ] Real air-gapped container acceptance scenario (`docker run --network none`) completes in `<3s` with zero network errors and passes inside `tests/e2e_containers/run_e2e.sh`.
