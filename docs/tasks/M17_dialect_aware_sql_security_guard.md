# M17: Dialect-Aware `SqlSecurityGuard` (`--dialect` CLI & `verity_database_guard` Support)

- **Task ID**: `M17`
- **Priority**: `P2` (Master Rank `#6`, Track A — Product & Customer Value)
- **Status**: `Todo`
- **Dependencies**: `M3`, `M5`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

`SqlSecurityGuard.validate_single_select_statement()` (`src/verity/mcp_library/sql_guard.py`) hardcodes `read="postgres"` for every `sqlglot.tokenize` / `sqlglot.parse` call (lines 90, 119, 133, 136). Non-Postgres SQL is therefore mis-tokenized/mis-parsed: MySQL backticks, T-SQL square-bracket identifiers, `LIMIT`/`TOP`/`QUALIFY` variants, and Snowflake/DuckDB/BigQuery specific constructs cause either **false positives** (valid read queries blocked) or **false negatives** (dialect-only keywords slipped past the prohibited-token scan). The `verity test --sql` subcommand and the `verity_database_guard` MCP handler also lack any way to select the dialect, so callers facing a MySQL/SQLite/Snowflake warehouse cannot obtain accurate validation.

---

## 2. Requirements & Target Files

1. **`src/verity/mcp_library/sql_guard.py`**
   - Add `dialect: str = "postgres"` keyword parameter to `SqlSecurityGuard.validate_single_select_statement(query, dialect="postgres")`.
   - Replace every `read="postgres"` with `read=dialect` in the `sqlglot.tokenize(...)` calls on **lines 90, 119** (decommented variants use same dialect) and the two `sqlglot.parse(...)` calls (lines 133, 136).
   - Keep the default `"postgres"` so existing callers are **100% backward compatible**.
   - Validate the supplied dialect against the allowlist (`postgres`, `mysql`, `sqlite`, `duckdb`, `tsql`, `bigquery`, `snowflake`); raise `SqlSecurityError` for unknown dialects.
   - Preserve all existing checks (semicolon/stacked detection, keyword token scan, prohibited AST nodes, catalog access, etc.) but evaluate them under the active dialect.

2. **`src/verity/cli.py`**
   - Add `--dialect` argument to the `test` subparser (`_cmd_test`), `choices=("postgres","mysql","sqlite","duckdb","tsql","bigquery","snowflake")`, `default="postgres"`.
   - Pass the value through to `SqlSecurityGuard.validate_single_select_statement(args.sql, dialect=args.dialect)`; include `#dialect=<name>` in the PASS/FAIL result `details` for observability.
   - Also thread a compatible `dialect` option into any scan path that surfaces the SQL validator (no behavior change when omitted).

3. **`src/verity/mcp_server/handlers/database_guard.py`**
   - In the `validate_sql_query` action of `_execute_database_guard`, read `options.get("dialect", "postgres")`.
   - Pass `dialect=` into `SqlSecurityGuard.validate_single_select_statement(...)`.
   - Return the resolved `"dialect"` field in both `ALLOWED` and `BLOCKED` responses so MCP clients see what was actually applied.

4. **`src/verity/scanner/static_rules.py`** *(optional, only if SQL strings are evaluated there)* — no new dialect behavior required; leave unchanged unless a clear call-site is found.

---

## 3. Automated Tests to Verify (`tests/unit/test_sql_guard_dialects.py`)

1. **Backward compatibility**: `validate_single_select_statement("SELECT 1")` with no `dialect` behaves exactly as before (still accepts, still blocks `DROP`/stacked queries).
2. **MySQL**: a query with backtick-quoted identifiers (`` SELECT `id`, `email` FROM `users` WHERE `tenant` = ? ``) passes with `dialect="mysql"` and does not crash under the default `"postgres"` dialect.
3. **SQLite**: `SELECT * FROM users LIMIT 10 OFFSET 5` passes under `dialect="sqlite"`; a stacked `SELECT 1; DROP TABLE users` still raises `SqlSecurityError` under every dialect.
4. **T-SQL**: `SELECT TOP 5 [id] FROM [dbo].[users]` passes under `dialect="tsql"`.
5. **Snowflake/BigQuery/DuckDB**: representative `QUALIFY` (Snowflake/DuckDB) and `SELECT * EXCEPT(col)` (BigQuery) queries pass under their respective dialects and remain subject to the prohibited-keyword/AST scans.
6. **Unknown dialect**: `validate_single_select_statement("SELECT 1", dialect="oracle")` raises `SqlSecurityError` mentioning the unknown dialect.
7. **Universal prohibitions**: parametrized `SELECT 1; DROP TABLE x`, `DELETE FROM`, `GRANT`, `pg_catalog` / `information_schema` access must raise `SqlSecurityError` across **all seven** dialects.
8. **Handler parity**: `_execute_database_guard({"action": "validate_sql_query", "options": {"sql_query": ..., "dialect": "mysql"}})` returns `ok=True` with `"dialect": "mysql"` for a valid backtick query.
9. **CLI parity**: invoking `_cmd_test(Namespace(sql=..., dialect="mysql"))` yields a `PASS` result whose `details` include `mysql`.

---

## 4. Acceptance Scenario in Clean Container with Real MCP Server/Database Flow

Extend `tests/e2e_containers/verify_all_scenarios.sh` with a new Scenario (Dialect-aware SQL guard):

1. **SQLite path** — start a real SQLite-backed database flow (`/tmp/verity_demo.db`) and populate a `users` table with one row.
   - Run a valid query through `verity test --sql 'SELECT `id`, `name` FROM `users` LIMIT 1' --dialect mysql` → expect exit `0`, `PASS`, `details` containing `mysql`.
   - Validate and execute a real SQLite query (`SELECT id, name FROM users LIMIT 1 OFFSET 0`) under `dialect="sqlite"` against `sqlite3.connect('/tmp/verity_demo.db')` → expect `PASS`.
2. **MCP handler flow** — call the `verity_database_guard` tool via an MCP client (`verity serve`) with:
   ```json
   {"action": "validate_sql_query",
    "options": {"sql_query": "SELECT TOP 5 [id] FROM [dbo].[users]", "dialect": "tsql"}}
   ```
   Assert `ok=true`, `verdict="ALLOWED"`, and `"dialect": "tsql"` in the response.
3. **Regression** — confirm a stacked `SELECT 1; DROP TABLE users` is blocked in **every** dialect used above.

**Assertions**: exit codes as described; all SQL/MCP command variants produce the expected `PASS`/`FAIL`; `scan_for_leaks` finds no unexpected data; full `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh` passes.

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/unit/test_sql_guard_dialects.py -v
uv run pytest tests/
uv run verity test --sql 'SELECT `id` FROM `users` LIMIT 1' --dialect mysql --format json
INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] `SqlSecurityGuard.validate_single_select_statement()` accepts `dialect` (default `"postgres"`) and forwards it to every `sqlglot.tokenize` / `sqlglot.parse` call; existing callers remain unaffected.
- [ ] All seven dialects (`postgres`, `mysql`, `sqlite`, `duckdb`, `tsql`, `bigquery`, `snowflake`) are supported end-to-end via `verity test --sql --dialect` and via `verity_database_guard`'s `options.dialect`.
- [ ] Unknown dialects raise a clear `SqlSecurityError`; unsafe/stacked/destructive queries remain blocked under every dialect.
- [ ] MCP handler responses echo the applied `"dialect"` in both `ALLOWED` and `BLOCKED` outputs.
- [ ] `tests/unit/test_sql_guard_dialects.py`, the full `pytest tests/`, `ruff check src tests`, and the container E2E scenario pass cleanly.
