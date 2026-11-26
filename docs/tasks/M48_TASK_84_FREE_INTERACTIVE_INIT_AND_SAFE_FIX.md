---
task_id: M48
alias: TASK-84-FREE
title: "Interactive Onboarding Wizard (verity init) & Safe Config Fix (verity fix)"
status: Partially Done
priority: Medium (P1)
size: L
estimate_days: 6
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhMEjKw
target_repos: [verityredteam-free]
---

# M48 (`TASK-84-FREE`): Interactive Onboarding Wizard (`verity init`) & Safe Config Fix (`verity fix`)

## Status Note (`Partially Done`)
- **Already Implemented (from M2)**: Legacy `src/verity/onboarding/{controller.py,models.py,config_scanner.py}` provide initial config scanning and controller primitives.
- **Remaining in M48**: Lossless `JsoncPatcher`, `AtomicBackupManager` with handshake rollback, `verity init` 5-step wizard & `--register-mcp`, `verity fix` core remediation engine (`pin-versions`, `externalize-secrets`, `harden-config`), and Pro-gating for AST/PR strategies.

## Purpose & Architectural Decisions
- **Lossless JSONC & Atomic Rollback**: Add `JsoncPatcher` preserving `//` and `/* */` comments and URLs, plus `AtomicBackupManager` rolling back target config files byte-for-byte if the pre-flight `StdioDiscoveryTransport` `initialize` handshake fails.
- **`verity init` & Policy Scaffolding**: Support interactive 5-step onboarding plus `--all-clients --workspace --non-interactive -y` (`verity.toml`, `.verityignore`, CI scaffolding) and idempotent `--register-mcp --auto-approve` (`.agents/policies.yaml`, `.vscode/settings.json`).
- **Safe `verity fix` Core Strategies**: Run in dry-run preview by default (`--write` required for disk mutation), scrub secrets via `_scrub_secrets()`, execute Free strategies (`pin-versions`, `externalize-secrets` to `0o600` `.env.verity`, `harden-config`), and fail closed (`PRO_FEATURE_REQUIRED`, exit `2`) when `--strategy ast-sql`/`ast-guard`/`remediate-pr` or `--path` is requested without `verity-pro`.

## Target Files
| File | Change |
| :--- | :--- |
| `src/verity/onboarding/jsonc_patcher.py` | Lossless JSONC comment-preserving patcher |
| `src/verity/onboarding/backup.py` | `AtomicBackupManager` with handshake verification & rollback |
| `src/verity/onboarding/wizard.py` | `verity init` 5-step interactive wizard & `--non-interactive` CI scaffolding |
| `src/verity/remediation/__init__.py` | Core `verity fix` engine & `pin-versions` / `externalize-secrets` / `harden-config` |
| `src/verity/cli.py` | `verity init` and `verity fix` subcommands + Pro AST gate (`exit 2`) |
| `tests/unit/test_init_and_fix.py` | JSONC lossless patch, rollback, idempotency, dry-run fix & Pro-gate tests |

## ATDD Traceability Matrix
| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-48.1` | `JsoncPatcher` losslessly injects `verity serve` while preserving comments and URLs. | Repeated `--register-mcp` performs an idempotent no-op. | `unit` | `tests/unit/test_init_and_fix.py::test_jsonc_patcher_and_idempotency` |
| `AC-48.2` | Failed pre-flight `StdioDiscoveryTransport` handshake triggers byte-for-byte rollback. | Healthy handshake commits registration cleanly. | `unit` | `tests/unit/test_init_and_fix.py::test_atomic_backup_rollback` |
| `AC-48.3` | `verity init --all-clients --workspace --non-interactive -y` scaffolds project files & policies. | Clean dry-run/non-interactive run writes no duplicate keys. | `unit` | `tests/unit/test_init_and_fix.py::test_init_scaffolding` |
| `AC-48.4` | `verity fix` defaults to dry-run with masked secrets; Free strategies work with `--write`; Pro AST strategies return `PRO_FEATURE_REQUIRED` (`exit 2`); ruff clean. | Default dry-run never mutates disk. | `ruff` | `uv run ruff check src tests` |
