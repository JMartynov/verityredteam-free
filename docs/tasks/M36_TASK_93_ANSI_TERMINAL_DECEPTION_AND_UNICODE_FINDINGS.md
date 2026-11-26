---
task_id: M36
alias: TASK-93
title: "ANSI Terminal Deception & Unicode BiDi / Tag-Char Findings"
status: Not Done
priority: High (P0)
size: S
estimate_days: 2
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhLJPrY
target_repos: [verityredteam-free]
---

# M36 (`TASK-93`): ANSI Terminal Deception & Unicode BiDi / Tag-Char Findings

## Purpose & Architectural Decisions
- **Explicit Deception Rules**: Add deterministic `StaticRuleEvaluator` rules against raw unescaped text for ANSI CSI/OSC-8/`\r` overwriting (`VERITY-STATIC-ANSI-ESCAPE`, `CWE-150`, `HIGH`), BiDi overrides (`VERITY-STATIC-UNICODE-BIDI`), Unicode Tag smuggling `U+E0000–U+E007F` (`VERITY-STATIC-UNICODE-TAG-SMUGGLING`), and zero-width obfuscation.
- **UCP Auditor Wiring**: Extend `MetadataNormalizer.detect_unicode_anomalies()` / `sanitize_text()` to explicitly catch `U+E0000–U+E007F` and `\x1b`, and wire `ToolProfile.has_unicode_anomalies` into `ConsolidatedSecurityAuditor.audit_server(..., live_probe=True)` (`VERITY-UCP-UNICODE-ANOMALY`).
- **Safe Report Visualization**: Add `--visualize-ansi-codes` to `verity scan` and `verity test`, escaping raw `\x1b` / `\r` into `[ESC]`, `[CR]`, `[U+202E]`, and `[TAG:...]` tokens across terminal, Markdown, and HTML outputs so Verity never injects raw escape sequences into operator terminals.

## Target Files
| File | Change |
| :--- | :--- |
| `src/verity/scanner/static_rules.py` | Add ANSI escape, BiDi, Tag-char, and zero-width `VERITY-STATIC-*` rules |
| `src/verity/ucp/normalizer.py` | Handle `U+E0000–U+E007F` and `\x1b` in anomaly detection & sanitization |
| `src/verity/discovery/auditor.py` | Emit `VERITY-UCP-UNICODE-ANOMALY` when `ToolProfile.has_unicode_anomalies` is true |
| `src/verity/reporting/__init__.py` | Add `--visualize-ansi-codes` token escaping across terminal, Markdown, HTML |
| `src/verity/cli.py` | Expose `--visualize-ansi-codes` on `verity scan` and `verity test` |
| `tests/unit/test_ansi_unicode_deception.py` | Paired deception vs clean ASCII/emoji UTF-8 control tests |

## ATDD Traceability Matrix
| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-36.1` | `StaticRuleEvaluator.scan_text()` flags ANSI CSI, OSC-8, raw ESC, and `\r` (`VERITY-STATIC-ANSI-ESCAPE`). | Normal ASCII and standard UTF-8 punctuation produce 0 findings. | `unit` | `tests/unit/test_ansi_unicode_deception.py::test_ansi_escape_detection` |
| `AC-36.2` | `StaticRuleEvaluator.scan_text()` flags BiDi overrides, `U+E0000–U+E007F` tags, and zero-width chars. | Benign multilingual UTF-8 / standard emoji produce 0 findings. | `unit` | `tests/unit/test_ansi_unicode_deception.py::test_unicode_bidi_and_tag_detection` |
| `AC-36.3` | `ConsolidatedSecurityAuditor.audit_server(..., live_probe=True)` emits `VERITY-UCP-UNICODE-ANOMALY`. | Clean live tool schemas produce 0 Unicode anomaly findings. | `unit` | `tests/unit/test_ansi_unicode_deception.py::test_auditor_ucp_unicode_wiring` |
| `AC-36.4` | `--visualize-ansi-codes` renders `[ESC]`, `[CR]`, `[U+202E]`, `[TAG:...]` with zero raw `\x1b` leaks. | Clean reports remain unchanged. | `unit` | `tests/unit/test_ansi_unicode_deception.py::test_visualize_ansi_codes` |
| `AC-36.5` | Ruff linter and unit test suite pass with zero violations. | Clean code conforms to ruff rules. | `ruff` | `uv run ruff check src tests` |
