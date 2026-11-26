---
task_id: M34
alias: TASK-91
title: "Agent Skill / Instruction File Scanner & Cross-Tool Toxic Flow Analysis"
status: Not Done
priority: High (P0)
size: M
estimate_days: 4
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhLJPjE
target_repos: [verityredteam-free]
---

# M34 (`TASK-91`): Agent Skill / Instruction File Scanner & Cross-Tool Toxic Flow Analysis

## Purpose & Architectural Decisions
- **Agent Instruction & Skill Scanning**: Add `InstructionFileScanner` (`src/verity/scanner/instruction_scanner.py`) covering 6 standard formats (`SKILL.md`, `.cursorrules`, `.cursor/rules/*.mdc`, `CLAUDE.md`, `AGENTS.md`, `.github/copilot-instructions.md`), inspecting Markdown body, YAML frontmatter, and hidden HTML comments (`<!-- ... -->`) via `StaticRuleEvaluator`.
- **Deterministic Cross-Tool Toxic Flows**: Add `ToxicFlowAnalyzer` (`src/verity/ucp/toxic_flows.py`) correlating `UCP` `ToolProfile` capability tags across single-server and multi-server configurations to detect lethal trifectas (`VERITY-TOXIC-FLOW-LETHAL-TRIFECTA`) and poisoned exfiltration pairs (`VERITY-TOXIC-FLOW-POISONED-EXFIL`).
- **CLI & Auditor Wiring**: Expose `--skills` and `--toxic-flows` on `verity scan`, and aggregate multi-server `ToolProfile`s in `ConsolidatedSecurityAuditor.audit_all(live_probe=True)`.

## Target Files
| File | Change |
| :--- | :--- |
| `src/verity/scanner/instruction_scanner.py` | New `InstructionFileScanner` for 6 agent instruction/skill formats |
| `src/verity/ucp/toxic_flows.py` | New deterministic `ToxicFlowAnalyzer` (`LETHAL_TRIFECTA`, `POISONED_EXFIL`) |
| `src/verity/discovery/auditor.py` | Aggregate `ToolProfile`s in `audit_all()` and attach `VERITY-TOXIC-FLOW-*` findings |
| `src/verity/cli.py` | Add `--skills` and `--toxic-flows` options on `verity scan` |
| `tests/unit/scanner/test_instruction_scanner.py` | Paired vulnerable/clean tests across all 6 instruction file formats |
| `tests/unit/ucp/test_toxic_flows.py` | Single- and multi-server toxic flow and benign control tests |

## ATDD Traceability Matrix
| AC ID | Acceptance Criterion | Paired Benign / Negative Control | Verification Tier | Test Target |
| :--- | :--- | :--- | :--- | :--- |
| `AC-34.1` | `InstructionFileScanner.discover_files()` locates all 6 instruction/skill file formats. | Unrelated `.md` files are ignored. | `unit` | `tests/unit/scanner/test_instruction_scanner.py::test_discover_instruction_files` |
| `AC-34.2` | `scan_file()` detects prompt overrides, hidden HTML comments, droppers, and poisoned YAML frontmatter. | Normal project `AGENTS.md` / `SKILL.md` produces 0 findings. | `unit` | `tests/unit/scanner/test_instruction_scanner.py::test_scan_instruction_payloads` |
| `AC-34.3` | `ToxicFlowAnalyzer` emits `VERITY-TOXIC-FLOW-LETHAL-TRIFECTA` and `VERITY-TOXIC-FLOW-POISONED-EXFIL`. | Read-only or non-egress servers produce 0 toxic-flow findings. | `unit` | `tests/unit/ucp/test_toxic_flows.py` |
| `AC-34.4` | `ConsolidatedSecurityAuditor.audit_all(live_probe=True)` and `verity scan --skills --toxic-flows` surface findings across all formats. | Clean tree exits `0`. | `unit` | `tests/unit/test_cli_skills_and_toxic_flows.py` |
| `AC-34.5` | Ruff linter and unit test suite pass with zero violations. | Clean code conforms to ruff rules. | `ruff` | `uv run ruff check src tests` |
