# AGENTS.md — Verity RedTeam Free (Open-Core Repository)

## 1. Project Identity & Open-Core Purpose

**Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-core`)  
**Companion Enterprise Repo**: `/Users/ivan/Project/3t.tools.intellij/verityredteam` (`verity-pro` & `verity_lite`)  
**Task Board**: [GitHub Project #5 (`Verity RedTeam Free Task Board`)](https://github.com/users/JMartynov/projects/5) & [`TASK_BOARD.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam-free/TASK_BOARD.md)  
**Master Architecture Specs**:
- [`../verityredteam/docs/plans/open_core_migration_plan.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam/docs/plans/open_core_migration_plan.md)
- [`../verityredteam/docs/plans/architecture_review_and_verification_plan.md`](file:///Users/ivan/Project/3t.tools.intellij/verityredteam/docs/plans/architecture_review_and_verification_plan.md)

**Verity RedTeam Free (`verity-core`)** is the open-source (Apache-2.0) security scanner, deterministic SQL AST guard, and MCP security server for developers building or using Model Context Protocol (MCP) tools.

### Core Product Principles
1. **5-Second Magic Moment (Zero Docker, Zero API Keys)**:
   - `verity scan`: Audits 9 local AI client configs (Claude Desktop, Cursor, VS Code Cline/Roo, Windsurf, Zed, Continue, LibreChat, workspace `.mcp.json`) for leaked secrets, screens MCP tool schemas with the 13-rule `StaticRuleEvaluator` (<0.2ms/tool), fingerprints servers against 3,903+ passports (`mcp-fingerprints`), and checks 508+ OSV advisories (`mcp-vulnerabilities`).
   - `verity test`: Probes local `stdio` or `HTTP/SSE` MCP servers deterministically and includes 4 zero-Docker in-memory demo targets (`verity test --demo`).
   - `verity serve`: Runs the zero-framework pure-stdlib JSON-RPC 2.0 MCP server so external IDE agents (Antigravity, Cursor, Claude Desktop, Codex) can invoke `verity_security_scan` and `verity_database_guard`.
2. **Clean Open-Core Plugin Boundary (Method 1)**:
   - Discovers commercial extensions dynamically via `importlib.metadata.entry_points(group="verity.plugins")` in `src/verity/mcp_server/plugin_loader.py`.
   - When `verity-pro` is not installed, Pro-only actions (`validate_snowflake_policy`, `check_canary_proof`, `verify_physical_database`, `generate_guard_patch`, `generate_safe_parameterized_query`, SARIF/AIVSS exports) return a structured `PRO_FEATURE_REQUIRED` response without crashing.
   - **Strict Git Hygiene**: This repository has a clean git history. Never copy or commit proprietary modules (`snowflake_guard.py`, `customer_lab`, `VAIB` 29-target catalog, `DatabaseVerificationOracle`, `Task 57` patch synthesizers) or `.env` secrets into this repository.

---

## 2. Mandatory DeepSeek 2-Pass Parallel Development Workflow

All implementation and test authoring in `verityredteam-free` MUST use the **Aider-DeepSeek Token-Sparse Sub-Agent** (`~/.gemini/config/skills/aider-deepseek/scripts/aider_bridge.py` with `deepseek/deepseek-flash`) following a strict **2-Pass + Gated Merge** workflow.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                 Lead Architect (Antigravity Coordinator)                 │
│  • Formulates contracts from TASK_BOARD.md (Tasks M1–M6)                 │
│  • Dispatches parallel worker sub-agents for [FREE] and [PRO] subtasks   │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
         ┌───────────────────────────┴───────────────────────────┐
         ▼ (Worker: [FREE] Subtask in Worktree)                  ▼ (Worker: [PRO] Subtask in Worktree)
┌─────────────────────────────────────────┐             ┌─────────────────────────────────────────┐
│ 1. Isolate: git worktree .worktrees/<id>│             │ 1. Isolate: git worktree .worktrees/<id>│
│ 2. PASS 1: Implementation (DeepSeek)    │             │ 2. PASS 1: Implementation (DeepSeek)    │
│ 3. PASS 2: Code Review (--restore)      │             │ 3. PASS 2: Code Review (--restore)      │
│ 4. Verify: Free + Pro pytest & ruff     │             │ 4. Verify: Pro 17/17 MCP + 551 unit     │
│ 5. Merge: ONLY after Pass 1+2+Tests pass│             │ 5. Merge: ONLY after Pass 1+2+Tests pass│
└─────────────────────────────────────────┘             └─────────────────────────────────────────┘
```

### Step-by-Step Execution Protocol for Every Task

1. **Isolated Worktree Setup (Parallel-Safe)**:
   - Create an isolated worktree `.worktrees/<task_id>` on branch `task/<task_id>` and copy `.env` (containing `DEEPSEEK_API_KEY`) into the worktree root.
   - Multiple independent tasks across `verityredteam-free` and `verityredteam` run in parallel inside their own worktrees.

2. **Pass 1 — Implementation**:
   - Invoke `aider_bridge.py turn` via an ephemeral sub-agent (`flash_lite` / `flash`) with explicit `--files` and `--read-files` (never use broad globs):
     ```bash
     python3 ~/.gemini/config/skills/aider-deepseek/scripts/aider_bridge.py turn \
       --task-id "<task_id>" \
       --cwd "/Users/ivan/Project/3t.tools.intellij/verityredteam-free/.worktrees/<task_id>" \
       --files <explicit_editable_files> \
       --read-files <explicit_reference_files> \
       --message "<Task specification from TASK_BOARD.md. Zero unrelated changes.>"
     ```
   - If exit code is `10` (`INTERACTIVE_QUESTION`), answer the question from the architecture spec and re-run with `--restore`.

3. **Pass 2 — Mandatory Code Review (Prefix-Cached via `--restore`)**:
   - Before running final merge gates, always run a second pass on the same `--task-id` with `--restore`:
     ```bash
     python3 ~/.gemini/config/skills/aider-deepseek/scripts/aider_bridge.py turn \
       --task-id "<task_id>" \
       --restore \
       --cwd "/Users/ivan/Project/3t.tools.intellij/verityredteam-free/.worktrees/<task_id>" \
       --files <explicit_editable_files> \
       --read-files <explicit_reference_files> \
       --message "PASS 2 CODE REVIEW: Audit your Pass 1 changes for: (1) strict compliance with task scope and zero unrelated edits, (2) zero imports from verity_pro or verity_lite, (3) edge-case exception handling and resource cleanup, (4) complete Python 3.12+ type hints and docstrings. Apply surgical fixes if needed."
     ```

4. **Dual-Repository Verification Gate (Before Merge)**:
   - Run standalone tests and linter in `verityredteam-free`:
     ```bash
     uv run pytest tests/ -q
     uv run ruff check src tests
     ```
   - If any test fails, compact failure output via `aider_bridge.py compact-log --log-file pytest.log --max-lines 40` and repair with `--restore`.
   - Verify zero regression in `verityredteam` (Pro):
     ```bash
     cd /Users/ivan/Project/3t.tools.intellij/verityredteam
     uv run pytest tests/unit/test_unified_production_mcp_agent_tools.py -q
     ```

5. **Session Cleanup & Merge**:
   - Run `aider_bridge.py cleanup --task-id "<task_id>"`, commit on `task/<task_id>`, merge into `main`, and remove the worktree **only after Pass 1, Pass 2, and all verification gates pass**.
