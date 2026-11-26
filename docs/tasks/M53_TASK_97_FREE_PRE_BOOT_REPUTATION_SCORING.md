---
task_id: M53
alias: TASK-97-FREE
title: "Pre-Boot Maintainer & Package Reputation Scoring (0-100)"
status: Not Done
priority: Low (P2)
size: S
estimate_days: 3
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhMEjic
target_repos: [verityredteam-free]
---

# M53 (`TASK-97-FREE`): Pre-Boot Maintainer & Package Reputation Scoring (0-100)

## Purpose & Architectural Decisions
- **Deterministic 0–100 `ReputationScorer`**: Compute a deterministic pre-boot reputation score (0–100) for uncataloged Path B MCP packages from GitHub repository/maintainer signals, npm/PyPI download metrics, and registry metadata (`REPUTATION-LOW-SCORE`, `REPUTATION-TYPOSQUAT-SUSPECT`).
- **Offline-First & Opt-In Guardrail**: Wire opt-in reputation scoring into `DualPathRouter` (`src/verity/scanner/dual_path_router.py`) and `ConsolidatedSecurityAuditor` (`--min-reputation-score`), strictly respecting `--offline` / `VERITY_OFFLINE=1` (returning neutral fallback scores with zero network calls when offline).

## Target Files
| File | Change |
| :--- | :--- |
| `src/verity/scanner/reputation.py` | New deterministic 0–100 `ReputationScorer` with offline fallback |
| `src/verity/scanner/dual_path_router.py` | Wire opt-in Path B reputation scoring |
| `src/verity/discovery/auditor.py` | Surface `REPUTATION-LOW-SCORE` / `REPUTATION-TYPOSQUAT-SUSPECT` when enabled |
| `src/verity/cli.py` | Opt-in `--min-reputation-score` on `verity scan` |
| `tests/unit/test_reputation.py` | Deterministic scoring, verified publisher control & offline fallback tests |

## ATDD Traceability Matrix
| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-53.1` | `ReputationScorer` computes deterministic 0–100 scores from maintainer and package signals. | Established verified publisher scores 100/100 with zero low-reputation warnings. | `unit` | `tests/unit/test_reputation.py::test_reputation_scoring` |
| `AC-53.2` | `DualPathRouter` integrates opt-in Path B reputation checks while respecting `VERITY_OFFLINE=1`. | Offline mode skips all remote queries and returns neutral fallback score. | `unit` | `tests/unit/test_dual_path_router.py::test_reputation_integration` |
| `AC-53.3` | Ruff linter and unit test suite pass with zero violations. | Clean code conforms to ruff rules. | `ruff` | `uv run ruff check src tests` |
