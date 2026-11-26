---
task_id: M39
alias: TASK-102
title: "Python AST Real-World Rules & Import Aliases"
status: Done
priority: P0
size: S
estimate_days: 2
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhLvl0M
target_repos: [verityredteam-free]
---


## Context & Objectives

The Python AST scanner must catch the same dangerous sinks in real MCP server code
that it currently catches only in synthetic fixtures. Two gaps remain:

1. Aliased imports (`import pickle as p`, `from subprocess import Popen as run_cmd`)
   bypass dotted-name dispatch because `visit_Call` never consults the alias map.
2. Two rules (`VERITY-AST-CWE-22-TRAVERSAL`, `VERITY-AST-CWE-862-BOLA`) still depend
   on literal marker strings (`is_traversal`, `is_cross_tenant`) that never appear in
   customer code.

This task replaces marker-string heuristics with real AST def-use analysis, resolves
import aliases before rule dispatch, and adds a genuine SQL-injection AST rule so
findings on real-world MCP servers are deterministic and defensible.

## Scope

| File | Change |
| --- | --- |
| `src/verity/scanner/python_ast.py` | Alias-aware dispatch plus three real AST rules |
| `tests/unit/scanner/test_python_ast.py` | Paired vulnerable/benign controls per rule |

Out of scope: non-Python languages, rules not listed below, and any change to existing
`RuleCatalog` identifiers or severity assignments.

## Subtasks

### M39.1 — Wire the import alias map into call dispatch

`visit_Import` and `visit_ImportFrom` already populate `self.imports`
(`python_ast.py#L63-L76`), but `visit_Call` (`#L133-L222`) only inspects literal
`ast.Name` / `ast.Attribute` chains. Resolve the leftmost name of an attribute chain
through `self.imports` before rule dispatch so aliases map to canonical dotted names:

- `import pickle as p` then `p.loads(buf)` resolves to `pickle.loads`.
- `from subprocess import Popen as run_cmd` then `run_cmd(cmd, shell=True)` resolves
  to `subprocess.Popen`.
- Attribute-chain rewriting must be safe: rewrite only the root name, leave
  intermediate attributes untouched, and never raise on unknown roots.

### M39.2 — Real CWE-22 traversal def-use check

Replace the synthetic `is_traversal` string check with a parameter-to-sink def-use
analysis for `VERITY-AST-CWE-22-TRAVERSAL`. A finding requires all three conditions:

1. A function parameter, or a value derived from one, reaches a path sink:
   builtin `open`, `pathlib.Path`, `os.path.join`, or `os.open`.
2. The sink result is not contained by `Path.resolve` plus `Path.is_relative_to`,
   `os.path.realpath`, or `os.path.commonpath`.
3. The tainted value is not a module-level `Constant`.

Benign construction such as `open(os.path.join(BASE_DIR, "static", name))` combined
with a containment check must not fire.

### M39.3 — Real CWE-89 SQL injection AST rule

Add a real AST rule for `VERITY-AST-CWE-89-SQLI` covering `cursor.execute`,
`cursor.executemany`, `connection.execute`, `session.raw`, and `session.text`. Flag
when the SQL argument is:

- a `JoinedStr` (f-string) containing a non-constant expression,
- a `Call` to `.format(...)` on a string literal, or
- a `BinOp` using `%` where the left operand is a string literal and the right operand
  is parameter- or input-derived.

Parameterized calls whose SQL argument is a `Constant` string, with or without a
separate params tuple, must not fire.

### M39.4 — Real CWE-862 BOLA AST rule

Replace the synthetic `bola_violation` / `is_cross_tenant` strings with a real rule for
`VERITY-AST-CWE-862-BOLA`: a function decorated with `@mcp.tool` (or an equivalent tool
registration) that queries by a record identifier (`get_*`, `fetch_*`, `find_*`,
`read_*` on a `session`, `cursor`, or repository object) whose body contains no
tenant/session ownership check (`session_tenant`, `current_user`, `owner_id`,
`tenant_id` comparison) and no authorization guard.

## ATDD Traceability Matrix

| Acceptance Criterion | Test Level | Target File / Function | Description | Status |
| --- | --- | --- | --- | --- |
| AC-39.1 | unit | `tests/unit/scanner/test_python_ast.py::test_import_alias_resolution`, `::test_benign_os_path_join` | Aliased imports resolve to canonical dotted names; benign `os.path.join` stays clean. | Verified (Green) |
| AC-39.2 | unit | `tests/unit/scanner/test_python_ast.py::test_cwe22_traversal_flagged`, `::test_cwe22_traversal_defended` | Real def-use traversal is flagged; `resolve` plus `is_relative_to` containment is clean. | Verified (Green) |
| AC-39.3 | unit | `tests/unit/scanner/test_python_ast.py::test_cwe89_sqli_fstring`, `::test_cwe89_sqli_parameterized` | f-string, `.format()`, and `%` interpolation are flagged; `Constant` parameterized SQL is clean. | Verified (Green) |
| AC-39.4 | unit | `tests/unit/scanner/test_python_ast.py::test_cwe862_bola_flagged`, `::test_cwe862_bola_defended` | Tenant-less ID lookup is flagged; ownership-checked lookup is clean. | Verified (Green) |
| AC-39.5 | static | `uv run ruff check src tests` | Zero lint findings across the touched files. | Verified (Green) |

## Validation Commands

~~~bash
uv run pytest tests/unit/scanner/test_python_ast.py -q
uv run ruff check src tests
~~~

## Delivery Checklist

- [x] M39.1 alias map wired into `visit_Call` with safe attribute-chain rewriting.
- [x] M39.2 real CWE-22 def-use check replaces the `is_traversal` string heuristic.
- [x] M39.3 real CWE-89 rule added with a parameterized-SQL benign control.
- [x] M39.4 real CWE-862 rule added with an ownership-check benign control.
- [x] AC-39.1 through AC-39.4 paired tests committed.
- [x] `uv run ruff check src tests` clean.
