---
task_id: M46
alias: TASK-82-FREE
title: "Unified verity scan CLI (mcp-fingerprints + mcp-vulnerabilities, SBOM & Drift)"
status: Done
priority: Low (P2)
size: L
estimate_days: 6
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhMEjAI
target_repos: [verityredteam-free]
---

# M46 (`TASK-82-FREE`): Unified `verity scan` CLI (`mcp-fingerprints` + `mcp-vulnerabilities`, SBOM & Drift)

## Purpose & Architectural Decisions
- **15+ Client Discovery & JSONC Support**: Expand `MultiClientConfigScanner` to resolve 15+ IDE/agent clients (`claude_code`, `goose`, `junie`, `vscode`, `antigravity`, `openhands`, `trae`, `lmstudio`), strip JSONC `//` comments cleanly, and support global npm package discovery.
- **Composable `--scanners` Orchestrator**: Add `parse_scanners_arg` running offline-safe default scanners (`config,vuln,secret,ast,typosquat,conflict` + `taint` when `--path` is set), offline BK-Tree `TyposquatDetector` against the 6,000+ passport corpus, `ConflictDetector` (`TOOL_COLLISION`), transitive dependency reachability (`--call-analysis`, `--reachable-only`, `--manifest`), and deduplicated `taint`/`ast` findings.
- **OWASP Mapping, SBOM & Inventory Drift**: Attach additive OWASP MCP/LLM Top 10 fields, emit schema-valid CycloneDX 1.6 (`--format cyclonedx`) and SPDX 2.3 (`--format spdx`) SBOM JSON, and add `--save-inventory-baseline` / `--compare-inventory-baseline` / `--fail-on-drift` (exiting `2` on drift) plus `verity_security_scan` MCP options parity.

## Target Files
| File | Change |
| :--- | :--- |
| `src/verity/discovery/config_scanner.py` | 15+ client discovery, JSONC stripping, global npm scan |
| `src/verity/scanner/engine.py` | Composable `--scanners` orchestrator & `taint`/`ast` dedup |
| `src/verity/scanner/typosquat.py` | Offline BK-Tree `TyposquatDetector` |
| `src/verity/scanner/conflicts.py` | Multi-server `ConflictDetector` (`TOOL_COLLISION`) |
| `src/verity/scanner/reachability.py` | `TransitiveDependencyAuditor` & `AstReachabilityAnalyzer` |
| `src/verity/reporting/sbom.py` | CycloneDX 1.6 & SPDX 2.3 SBOM emitters + OWASP mapping |
| `src/verity/cli.py` | `--scanners`, `--format cyclonedx/spdx`, and inventory drift flags |
| `src/verity/mcp_server/handlers/security_scan.py` | Options parity (`scanners`, `include_reachability`, inventory drift) |

## ATDD Traceability Matrix
| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-46.1` | `MultiClientConfigScanner` discovers 15+ clients and parses JSONC configs cleanly. | Non-MCP JSON files are skipped cleanly. | `unit` | `tests/unit/test_unified_scan_discovery.py` |
| `AC-46.2` | Offline `TyposquatDetector`, `ConflictDetector`, and reachability/dedup run via `--scanners`. | Official packages & disjoint tool names yield 0 typosquat/conflict findings. | `unit` | `tests/unit/test_unified_scanners.py` |
| `AC-46.3` | `--format cyclonedx` and `--format spdx` emit valid CycloneDX 1.6 / SPDX 2.3 SBOMs with OWASP metadata. | Inventory-only mode omits CVE blocks cleanly. | `unit` | `tests/unit/test_sbom_export.py` |
| `AC-46.4` | Inventory drift flags detect drift (`exit 2`) and expose parity options in `verity_security_scan`; ruff clean. | Unchanged inventory exits `0`. | `ruff` | `uv run ruff check src tests` |

## Deliverables Checklist
- [x] **AC-46.1 (Red -> Green)**: `MultiClientConfigScanner` resolves 15+ IDE/agent clients, strips JSONC `//`/`/* */` comments and trailing commas without corrupting URLs, and supports `--client` filtering and opt-in `--scan-global` (`tests/unit/test_unified_scan_discovery.py`).
- [x] **AC-46.2 (Red -> Green)**: `parse_scanners_arg`, offline BK-Tree `TyposquatDetector`, `ConflictDetector` (`TOOL_COLLISION`), `TransitiveDependencyAuditor` + `AstReachabilityAnalyzer` (`--call-analysis`, `--reachable-only`, `--manifest`, `--offline` guard), and `ast`/`taint` deduplication (`tests/unit/test_unified_scanners.py`).
- [x] **AC-46.3 (Red -> Green)**: Additive OWASP MCP/LLM Top 10 enrichment + compliance scorecards (`--compliance`, `--fail-on-non-compliant`), CycloneDX 1.6 (`--format cyclonedx`) and SPDX 2.3 (`--format spdx`) SBOM export (`tests/unit/test_sbom_export.py`).
- [x] **AC-46.4 (Red -> Green)**: Inventory drift flags (`--save-inventory-baseline`, `--compare-inventory-baseline`, `--fail-on-drift` exiting `2`), `verity_security_scan` MCP parity options, and `ruff` clean (`tests/unit/test_sbom_export.py`).
- [x] **Pass 1 & Pass 2 (DeepSeek)**: Phase A (`48fe803`, `621f605`) and Phase B (`7176895`, `e4c1124`, `861aeb0`) implemented and self-reviewed in isolated worktrees.
- [x] **Free Repo Gates**: `uv run pytest tests/`, `uv run ruff check src tests scripts`, `uv run verity test --demo`, and `uv run mkdocs build --strict` pass cleanly.
