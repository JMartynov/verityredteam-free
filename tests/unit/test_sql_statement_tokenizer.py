"""Unit tests for SQL statement boundary detection in SqlSecurityGuard."""

from __future__ import annotations

from typing import Any

import pytest
import sqlglot

from verity.mcp_library import SqlSecurityError, SqlSecurityGuard


class TestStringLiteralImmunity:
    @pytest.mark.parametrize(
        "query",
        [
            "SELECT 'User auth error; -- retry' AS msg",
            "SELECT * FROM users WHERE note = 'a; DROP TABLE users'",
            "SELECT * FROM users WHERE note = 'DELETE FROM users; --'",
            "SELECT 'semi;colon' FROM users",
        ],
    )
    def test_string_literals_are_not_treated_as_statements(self, query: str) -> None:
        SqlSecurityGuard.validate_parameterized_query(query)


class TestStackedQueryDetection:
    @pytest.mark.parametrize(
        "query",
        [
            "SELECT 1; DROP TABLE users",
            "SELECT 1; DELETE FROM users",
            "SELECT 1; SELECT 2",
            "SELECT * FROM users; -- rest",
        ],
    )
    def test_stacked_queries_raise_with_rule_id(self, query: str) -> None:
        with pytest.raises(SqlSecurityError) as excinfo:
            SqlSecurityGuard.validate_parameterized_query(query)
        assert excinfo.value.rule_id == "DISALLOW_STACKED_QUERIES"


class TestTrailingSemicolon:
    def test_benign_trailing_semicolon_allowed(self) -> None:
        SqlSecurityGuard.validate_parameterized_query("SELECT 1;")


class TestDialectForwarding:
    @pytest.mark.parametrize(
        ("query", "dialect"),
        [
            ("SELECT `col;name` FROM `tbl`", "mysql"),
            ("SELECT `col` FROM `tbl` -- note; retry", "mysql"),
            ("SELECT [col;name] FROM [tbl]", "tsql"),
            ("SELECT $$User auth error; -- retry$$ AS msg", "postgres"),
        ],
    )
    def test_dialect_specific_quoting_and_literals(
        self, query: str, dialect: str
    ) -> None:
        SqlSecurityGuard.validate_parameterized_query(query, dialect=dialect)

    def test_forwards_dialect_to_sqlglot(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, Any] = {}
        real_tokenize = sqlglot.tokenize
        real_parse = sqlglot.parse

        def fake_tokenize(sql: str, **kwargs: Any) -> Any:
            seen["tokenize"] = kwargs.get("read")
            return real_tokenize(sql, **kwargs)

        def fake_parse(sql: str, **kwargs: Any) -> Any:
            seen["parse"] = kwargs.get("read")
            return real_parse(sql, **kwargs)

        monkeypatch.setattr(sqlglot, "tokenize", fake_tokenize)
        monkeypatch.setattr(sqlglot, "parse", fake_parse)

        SqlSecurityGuard.validate_parameterized_query("SELECT 1", dialect="snowflake")

        assert seen["tokenize"] == "snowflake"
        assert seen["parse"] == "snowflake"


class TestDynamicFormattingBlocked:
    @pytest.mark.parametrize(
        "query",
        [
            "SELECT * FROM users WHERE id = %(id)s",
            "SELECT * FROM users WHERE id = {}",
            "SELECT * FROM users WHERE name = ' + name + '",
            "SELECT * FROM users WHERE name = 'a' + 'b'",
        ],
    )
    def test_dynamic_patterns_still_blocked(self, query: str) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_parameterized_query(query)


class TestDialectValidation:
    @pytest.mark.parametrize("dialect", ["", "   "])
    def test_rejects_empty_dialect(self, dialect: str) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_parameterized_query("SELECT 1", dialect=dialect)

    @pytest.mark.parametrize("query", ["", "   ", None])
    def test_empty_query_checked_before_dialect(self, query: str | None) -> None:
        with pytest.raises(SqlSecurityError) as excinfo:
            SqlSecurityGuard.validate_parameterized_query(query, dialect="")
        assert str(excinfo.value) == "SQL query must be a non-empty string."
