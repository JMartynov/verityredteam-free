---
task_id: M51
alias: TASK-94-FREE
title: "Bundled Snapshot Sync (passports/vulns), Sigstore Verification & Config Scanner Dedup"
status: Not Done
priority: Medium (P1)
size: M
estimate_days: 3
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhMEjXY
target_repos: [verityredteam-free]
---

# M51 (`TASK-94-FREE`): Bundled Snapshot Sync (`passports`/`vulns`), Sigstore Verification & Config Scanner Dedup

## Purpose & Architectural Decisions
- **Upstream Snapshot Sync**: Refresh bundled `src/verity/data/passports.json.gz` (from `mcp-fingerprints`) and `src/verity/data/vulnerabilities.json.gz` (from `mcp-vulnerabilities`) so offline customers receive current coverage out of the box.
- **Keyless Sigstore & Manifest Verification**: Enforce cryptographic Sigstore bundle and manifest checksum verification in `src/verity/data_fetcher.py` on remote snapshot updates while keeping offline fallback intact.
- **Config Scanner Consolidation**: Alias/consolidate `StaticConfigScanner` (`src/verity/onboarding/config_scanner.py`) into `MultiClientConfigScanner` (`src/verity/discovery/config_scanner.py`) and prune stale namespace/pycache artifacts.

## Target Files
| File | Change |
| :--- | :--- |
| `src/verity/data/passports.json.gz` | Synced upstream passport snapshot |
| `src/verity/data/vulnerabilities.json.gz` | Synced upstream OSV v1.6.0 vulnerability snapshot |
| `src/verity/data_fetcher.py` | Keyless Sigstore bundle & manifest verification |
| `src/verity/onboarding/config_scanner.py` | Consolidate/alias `StaticConfigScanner` to `MultiClientConfigScanner` |
| `tests/unit/test_snapshot_sigstore_and_dedup.py` | Snapshot schema, Sigstore valid/tampered bundle, and scanner dedup tests |

## ATDD Traceability Matrix
| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-51.1` | Bundled `passports.json.gz` and `vulnerabilities.json.gz` load cleanly and validate against schema. | Corrupted/empty gzip payload raises explicit validation error. | `unit` | `tests/unit/test_snapshot_sigstore_and_dedup.py::test_bundled_snapshots_valid` |
| `AC-51.2` | `data_fetcher.py` verifies Sigstore bundles & manifests on remote fetch. | Tampered digest or invalid bundle is rejected; valid bundle succeeds. | `unit` | `tests/unit/test_snapshot_sigstore_and_dedup.py::test_sigstore_verification` |
| `AC-51.3` | `StaticConfigScanner` delegates to `MultiClientConfigScanner` with zero duplicate discovery logic. | Existing onboarding callers remain backward-compatible. | `unit` | `tests/unit/test_snapshot_sigstore_and_dedup.py::test_config_scanner_dedup` |
| `AC-51.4` | Ruff linter and unit test suite pass with zero violations. | Clean code conforms to ruff rules. | `ruff` | `uv run ruff check src tests` |
