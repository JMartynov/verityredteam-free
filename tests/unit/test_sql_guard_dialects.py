"""Unit tests for dialect-aware SqlSecurityGuard behavior (M17)."""

from __future__ import annotations

import argparse
import contextlib
import json
from pathlib import Path

import pytest

from verity.cli import _cmd_test, build_parser
from verity.mcp_library import SqlSecurityError, SqlSecurityGuard
from verity.mcp_server.handlers.database_guard import DatabaseGuardHandlerMixin

ALL_DIALECTS = (
    "postgres",
    "mysql",
    "sqlite",
    "duckdb",
    "tsql",
    "bigquery",
    "snowflake",
)

MYSQL_BACKTICKS = "SELECT `id`, `email` FROM `users` WHERE `tenant` = ?"


class TestBackwardCompatibility:
    def test_default_accepts_select(self) -> None:
        SqlSecurityGuard.validate_single_select_statement("SELECT 1")

    def test_default_blocks_drop(self) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_single_select_statement("DROP TABLE users")

    def test_default_blocks_stacked(self) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_single_select_statement(
                "SELECT 1; DROP TABLE users"
            )


class TestMysqlDialect:
    def test_backtick_identifiers_accepted(self) -> None:
        SqlSecurityGuard.validate_single_select_statement(
            MYSQL_BACKTICKS, dialect="mysql"
        )

    def test_backticks_under_postgres_do_not_crash(self) -> None:
        with contextlib.suppress(SqlSecurityError):
            SqlSecurityGuard.validate_single_select_statement(MYSQL_BACKTICKS)


class TestSqliteDialect:
    def test_limit_offset_accepted(self) -> None:
        SqlSecurityGuard.validate_single_select_statement(
            "SELECT * FROM users LIMIT 10 OFFSET 5", dialect="sqlite"
        )


@pytest.mark.parametrize("dialect", ALL_DIALECTS)
def test_stacked_query_blocked_every_dialect(dialect: str) -> None:
    with pytest.raises(SqlSecurityError):
        SqlSecurityGuard.validate_single_select_statement(
            "SELECT 1; DROP TABLE users", dialect=dialect
        )


class TestTsqlDialect:
    def test_top_and_bracket_identifiers_accepted(self) -> None:
        SqlSecurityGuard.validate_single_select_statement(
            "SELECT TOP 5 [id] FROM [dbo].[users]", dialect="tsql"
        )


class TestQualifyDialect:
    @pytest.mark.parametrize("dialect", ["snowflake", "duckdb"])
    def test_qualify_accepted(self, dialect: str) -> None:
        SqlSecurityGuard.validate_single_select_statement(
            "SELECT id, ROW_NUMBER() OVER (PARTITION BY tenant) AS rn "
            "FROM users QUALIFY rn = 1",
            dialect=dialect,
        )


class TestBigQueryDialect:
    def test_select_star_except_accepted(self) -> None:
        SqlSecurityGuard.validate_single_select_statement(
            "SELECT * EXCEPT(col) FROM users", dialect="bigquery"
        )


class TestUnknownDialect:
    def test_unknown_dialect_mentions_name(self) -> None:
        with pytest.raises(SqlSecurityError, match="oracle"):
            SqlSecurityGuard.validate_single_select_statement(
                "SELECT 1", dialect="oracle"
            )

    @pytest.mark.parametrize("dialect", ["oracle", "db2", "", "   "])
    def test_invalid_string_dialect_raises(self, dialect: str) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_single_select_statement(
                "SELECT 1", dialect=dialect
            )

    def test_non_string_dialect_raises(self) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_single_select_statement(
                "SELECT 1", dialect=None  # type: ignore[arg-type]
            )


PROHIBITED_QUERIES = (
    "SELECT 1; DROP TABLE x",
    "DELETE FROM users",
    "GRANT ALL ON users TO public",
    "SELECT * FROM pg_catalog.pg_class",
    "SELECT * FROM information_schema.tables",
)


@pytest.mark.parametrize("dialect", ALL_DIALECTS)
@pytest.mark.parametrize("query", PROHIBITED_QUERIES)
def test_universal_prohibitions(dialect: str, query: str) -> None:
    with pytest.raises(SqlSecurityError):
        SqlSecurityGuard.validate_single_select_statement(query, dialect=dialect)


class _Handler(DatabaseGuardHandlerMixin):
    pass


class TestHandlerParity:
    def test_allowed_response_includes_dialect(self) -> None:
        handler = _Handler()
        result = handler._execute_database_guard(
            {
                "action": "validate_sql_query",
                "options": {"sql_query": MYSQL_BACKTICKS, "dialect": "mysql"},
            }
        )
        assert result["ok"] is True
        assert result["verdict"] == "ALLOWED"
        assert result["dialect"] == "mysql"

    def test_blocked_response_includes_dialect(self) -> None:
        handler = _Handler()
        result = handler._execute_database_guard(
            {
                "action": "validate_sql_query",
                "options": {
                    "sql_query": "SELECT 1; DROP TABLE users",
                    "dialect": "mysql",
                },
            }
        )
        assert result["ok"] is False
        assert result["verdict"] == "BLOCKED"
        assert result["dialect"] == "mysql"

    def test_default_dialect_reported(self) -> None:
        handler = _Handler()
        result = handler._execute_database_guard(
            {"action": "validate_sql_query", "options": {"sql_query": "SELECT 1"}}
        )
        assert result["dialect"] == "postgres"


class TestHandlerDialectEdgeCases:
    def test_unknown_dialect_blocked_with_echo(self) -> None:
        handler = _Handler()
        result = handler._execute_database_guard(
            {
                "action": "validate_sql_query",
                "options": {"sql_query": "SELECT 1", "dialect": "oracle"},
            }
        )
        assert result["ok"] is False
        assert result["verdict"] == "BLOCKED"
        assert result["dialect"] == "oracle"
        assert any("oracle" in v for v in result["violations"])

    def test_none_dialect_defaults_to_postgres(self) -> None:
        handler = _Handler()
        result = handler._execute_database_guard(
            {
                "action": "validate_sql_query",
                "options": {"sql_query": "SELECT 1", "dialect": None},
            }
        )
        assert result["ok"] is True
        assert result["dialect"] == "postgres"

    def test_uppercase_dialect_normalized(self) -> None:
        handler = _Handler()
        result = handler._execute_database_guard(
            {
                "action": "validate_sql_query",
                "options": {"sql_query": MYSQL_BACKTICKS, "dialect": "MYSQL"},
            }
        )
        assert result["ok"] is True
        assert result["dialect"] == "mysql"


def _build_namespace(sql: str, dialect: str, output: str) -> argparse.Namespace:
    return argparse.Namespace(
        demo=False,
        target=None,
        sql=sql,
        url=None,
        command=None,
        format="json",
        output=output,
        save_baseline=None,
        baseline=None,
        dialect=dialect,
    )


class TestCliParity:
    def test_parser_default_dialect(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["test", "--sql", "SELECT 1"])
        assert args.dialect == "postgres"

    def test_parser_explicit_dialect(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["test", "--sql", "SELECT 1", "--dialect", "mysql"]
        )
        assert args.dialect == "mysql"

    def test_cmd_test_pass_includes_dialect(self, tmp_path: Path) -> None:
        out = tmp_path / "out.json"
        rc = _cmd_test(_build_namespace(MYSQL_BACKTICKS, "mysql", str(out)))
        assert rc == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data[0]["status"] == "PASS"
        assert "#dialect=mysql" in str(data[0]["details"])

    def test_cmd_test_fail_includes_dialect(self, tmp_path: Path) -> None:
        out = tmp_path / "out.json"
        rc = _cmd_test(
            _build_namespace("SELECT 1; DROP TABLE users", "sqlite", str(out))
        )
        assert rc == 1
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data[0]["status"] == "FAIL"
        assert "#dialect=sqlite" in str(data[0]["details"])

    def test_cmd_test_without_dialect_attribute(self, tmp_path: Path) -> None:
        out = tmp_path / "out.json"
        ns = argparse.Namespace(
            demo=False,
            target=None,
            sql="SELECT 1",
            url=None,
            command=None,
            format="json",
            output=str(out),
            save_baseline=None,
            baseline=None,
        )
        rc = _cmd_test(ns)
        assert rc == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "#dialect=postgres" in str(data[0]["details"])
