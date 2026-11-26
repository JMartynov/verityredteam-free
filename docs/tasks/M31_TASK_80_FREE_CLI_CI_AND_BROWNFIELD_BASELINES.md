---
task_id: M31
alias: TASK-80-FREE
title: "Free CLI CI Prerequisites & Brownfield Baseline / Ignore Engine"
status: Done
priority: Medium (P1)
size: M
estimate_days: 3
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhLJPYA
target_repos: [verityredteam-free]
---

# M31 (`TASK-80-FREE`): Free CLI CI Prerequisites & Brownfield Baseline / Ignore Engine

## Purpose & Architectural Decisions
- **100% Stdlib `verity.baseline` Engine**: Deliver deterministic, pre-scrubbed finding fingerprints (`verity:v1:<16-hex>_<occ>`), `.verityignore` (with cycle-protected `:include .gitignore` and `!` negation), `verity.toml` `[[ignore]]` / `[[allowlists]]` with expiry, inline `# verity-ignore` / `# nosemgrep` suppressions, and `.verity-baseline.json` storage (`schema_version: "1.0"`).
- **CI Exit-Code & Multi-Path Ergonomics**: Support `--fail-on-severity` / `--fail-on`, `--baseline` / `--save-baseline` / `--fail-on-new`, and multi-file `--path a.py b.py cfg.json` routing plus nested monorepo config discovery.
- **Edition Boundary Note**: Free covers subtasks `80.1`–`80.2` (`verity.baseline` + CLI CI flags/reporters + MCP `security_scan` parity). Per `M40` (`TASK-103-FREE`), `--format sarif` remains **Pro-only** (`PRO_FEATURE_REQUIRED`, exit code `2` in Free).

## Target Files
| File | Change |
| :--- | :--- |
| `src/verity/baseline/__init__.py` | Public baseline, ignore, and fingerprint API |
| `src/verity/baseline/paths.py` | Repo-root discovery and POSIX relative path canonicalization |
| `src/verity/baseline/fingerprint.py` | Line-shift-stable pre-scrubbing `verity:v1:` fingerprints |
| `src/verity/baseline/ignore.py` | `.verityignore` and `verity.toml` ignore/allowlist/expiry evaluation |
| `src/verity/baseline/inline.py` | Inline `# verity-ignore` and `# nosemgrep` parser |
| `src/verity/baseline/store.py` | Deterministic `.verity-baseline.json` reader/writer & schema-mismatch guard |
| `src/verity/cli.py` | Multi-file `--path`, `--baseline`, `--save-baseline`, `--fail-on-new`, `--fail-on-severity` |
| `src/verity/discovery/config_scanner.py` | Nested monorepo config discovery filtered by `.verityignore` |
| `src/verity/reporting/` | Surface `suppressed_counts` and `resolved_count` across terminal, JSON, Markdown, HTML |
| `src/verity/mcp_server/handlers/security_scan.py` | `baseline_path`, `fail_on_new`, and `respect_ignores` parity |

## ATDD Traceability Matrix
| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-31.1` | Repo-relative path canonicalization and line-shift-stable `verity:v1:<16-hex>_<occ>` fingerprints. | Duplicate findings disambiguate `_0` / `_1`; rotated secrets invalidate old hash without leaking plaintext. | `unit` | `tests/unit/test_baseline_fingerprint.py` |
| `AC-31.2` | `.verityignore`, `verity.toml` `[[ignore]]`/`[[allowlists]]`, and inline `# verity-ignore`/`# nosemgrep` suppress matching findings. | Expired rules re-activate with stderr warning; unmatched rules stay active. | `unit` | `tests/unit/test_baseline_ignore.py` |
| `AC-31.3` | `--save-baseline`, `--baseline --fail-on-new`, and `verity test` baseline schema-mismatch guard (`exit 2`). | Zero new findings exits `0`; new findings exit `1`. | `unit` | `tests/unit/test_cli_baseline.py` |
| `AC-31.4` | Multi-file `--path` routing, nested monorepo discovery, `--fail-on-severity`, and MCP `security_scan` parity. | `--format sarif` stays Pro-gated (`PRO_FEATURE_REQUIRED`, exit `2`) per `M40`. | `unit` | `tests/unit/test_cli_ci_flags.py` |
| `AC-31.5` | Ruff linter and unit test suite pass with zero violations. | Clean code conforms to ruff rules. | `ruff` | `uv run ruff check src tests` |

## Completion & Verification Summary
- **Implemented Commits (`verityredteam-free`)**:
  - `f72e2e7` (`test(m31)`): Locked ATDD test suites (`tests/unit/test_baseline_fingerprint.py`, `tests/unit/test_baseline_ignore.py`, `tests/unit/test_cli_baseline.py`, `tests/unit/test_cli_ci_flags.py`).
  - `a89df8e` (`feat(m31)`): Stdlib `src/verity/baseline/` package (`__init__.py`, `paths.py`, `fingerprint.py`, `ignore.py`, `inline.py`, `store.py`), relative path canonicalization in `src/verity/scanner/engine.py`, and `.verityignore`-filtered nested monorepo discovery in `src/verity/discovery/config_scanner.py`.
  - `7df0948` (`feat(m31)`): CLI CI flags (`--fail-on-severity`/`--fail-on`, `--save-baseline`, `--baseline`, `--fail-on-new`, `--ignore-file`, `--config`, `--root`, `--show-suppressed`, `--strict-policy`, `--no-inline-ignores`, `--no-default-ignores`, multi-file `--path`), `verity test --baseline` schema-mismatch guard (`exit 2`), suppression/baseline summaries across `terminal`/`markdown`/`html`/`json` reporters, and MCP `verity_security_scan` parity (`baseline_path`, `fail_on_new`, `respect_ignores`) in `src/verity/mcp_server/{schemas.py,handlers/security_scan.py}`.
- **Acceptance Criteria**: `AC-31.1` through `AC-31.5` verified green (`uv run pytest tests/`, `uv run ruff check src tests scripts`, `uv run verity test --demo`, and `uv run mkdocs build --strict`).
