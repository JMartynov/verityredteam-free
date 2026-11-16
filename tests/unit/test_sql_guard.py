"""Unit tests for verity.mcp_library.sql_guard."""

from __future__ import annotations

import pytest

from verity.mcp_library import SqlSecurityError, SqlSecurityGuard


class TestValidateParameterizedQuery:
    @pytest.mark.parametrize(
        "query",
        [
            "SELECT * FROM users WHERE id = %(id)s",
            "SELECT * FROM users WHERE id = {}",
            "SELECT * FROM users WHERE name = ' + name + '",
            "SELECT * FROM users WHERE name = 'a' + 'b'",
            "SELECT * FROM users; DROP TABLE users",
            "SELECT * FROM users; DELETE FROM users",
            "SELECT * FROM users; -- rest",
        ],
    )
    def test_blocks_unsafe_patterns(self, query: str) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_parameterized_query(query)

    @pytest.mark.parametrize(
        "query",
        [
            "SELECT id, name FROM users WHERE id = $1",
            "SELECT id FROM users WHERE id = :id",
            "SELECT id FROM users WHERE id = ?",
        ],
    )
    def test_allows_parameterized_queries(self, query: str) -> None:
        SqlSecurityGuard.validate_parameterized_query(query, (1,))

    @pytest.mark.parametrize("query", ["", "   ", None])
    def test_rejects_empty_or_non_string(self, query: str | None) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_parameterized_query(query)


class TestValidateSingleSelectStatement:
    @pytest.mark.parametrize(
        "query",
        [
            "SELECT id, name FROM users WHERE id = $1",
            "SELECT id FROM users",
            "WITH cte AS (SELECT 1 AS x) SELECT x FROM cte",
            "SELECT 1 UNION SELECT 2",
        ],
    )
    def test_allows_select_and_with(self, query: str) -> None:
        SqlSecurityGuard.validate_single_select_statement(query)

    @pytest.mark.parametrize("query", ["SEL/**/ECT * FROM users"])
    def test_blocks_comment_splitting(self, query: str) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_single_select_statement(query)

    @pytest.mark.parametrize(
        "query",
        [
            "SELECT 1; SELECT 2",
            "SELECT 1; DROP TABLE users",
            "SELECT 1; DELETE FROM users",
        ],
    )
    def test_blocks_stacked_queries(self, query: str) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_single_select_statement(query)

    @pytest.mark.parametrize(
        "query",
        [
            "DROP TABLE users",
            "DELETE FROM users",
            "UPDATE users SET name = 'x'",
            "INSERT INTO users (id) VALUES (1)",
            "CREATE TABLE users (id INT)",
            "ALTER TABLE users ADD COLUMN name TEXT",
        ],
    )
    def test_blocks_ddl_and_dml(self, query: str) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_single_select_statement(query)

    @pytest.mark.parametrize(
        "query",
        [
            "SELECT * FROM pg_catalog.pg_class",
            "SELECT * FROM information_schema.tables",
            "SELECT * FROM mysql.user",
        ],
    )
    def test_blocks_system_catalogs(self, query: str) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_single_select_statement(query)

    @pytest.mark.parametrize("query", ["", "   ", None])
    def test_rejects_empty_or_non_string(self, query: str | None) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_single_select_statement(query)


class TestApplyProjection:
    def test_filters_to_allowlist(self) -> None:
        row = {"id": 1, "name": "alice", "secret": "hunter2"}
        assert SqlSecurityGuard.apply_projection(row, {"id", "name"}) == {
            "id": 1,
            "name": "alice",
        }

    def test_accepts_list_allowlist(self) -> None:
        row = {"id": 1, "name": "alice"}
        assert SqlSecurityGuard.apply_projection(row, ["name"]) == {"name": "alice"}

    def test_returns_none_for_none_row(self) -> None:
        assert SqlSecurityGuard.apply_projection(None, {"id"}) is None

    def test_empty_allowlist_returns_empty_dict(self) -> None:
        assert SqlSecurityGuard.apply_projection({"id": 1}, set()) == {}


class TestEnforceTenantFilter:
    def test_binds_session_tenant(self) -> None:
        params = {"status": "active"}
        out = SqlSecurityGuard.enforce_tenant_filter(params, "tenant-a")
        assert out == {"status": "active", "tenant_id": "tenant-a"}

    def test_does_not_mutate_input(self) -> None:
        params = {"status": "active"}
        SqlSecurityGuard.enforce_tenant_filter(params, "tenant-a")
        assert params == {"status": "active"}

    @pytest.mark.parametrize("tenant", ["", None])
    def test_rejects_missing_tenant(self, tenant: str | None) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.enforce_tenant_filter({}, tenant)


class TestValidateIdentifierAllowlist:
    def test_returns_normalized_valid_identifier(self) -> None:
        allowed = {"id", "name"}
        result = SqlSecurityGuard.validate_identifier_allowlist("  Name ", allowed)
        assert result == "name"

    def test_rejects_disallowed_identifier(self) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_identifier_allowlist("secret", {"id", "name"})

    @pytest.mark.parametrize("identifier", ["na-me", "na me", "name;drop", "na'me"])
    def test_rejects_invalid_characters(self, identifier: str) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_identifier_allowlist(identifier, {identifier})

    @pytest.mark.parametrize("identifier", ["", "   ", None])
    def test_rejects_empty_or_non_string(self, identifier: str | None) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_identifier_allowlist(identifier, {"id"})


class TestValidateStatementTimeout:
    def test_defaults_when_none(self) -> None:
        assert SqlSecurityGuard.validate_statement_timeout(None) == 1000

    def test_returns_valid_value(self) -> None:
        assert SqlSecurityGuard.validate_statement_timeout(2500) == 2500

    def test_clamps_to_max_allowed(self) -> None:
        assert (
            SqlSecurityGuard.validate_statement_timeout(10_000, max_allowed_ms=5000)
            == 5000
        )

    @pytest.mark.parametrize("timeout", [0, -1, -500])
    def test_rejects_non_positive(self, timeout: int) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_statement_timeout(timeout)

    @pytest.mark.parametrize("timeout", ["abc", object()])
    def test_rejects_invalid_values(self, timeout: str | object) -> None:
        with pytest.raises(SqlSecurityError):
            SqlSecurityGuard.validate_statement_timeout(timeout)


class TestSanitizeLikePattern:
    def test_escapes_backslash_percent_and_underscore(self) -> None:
        result = SqlSecurityGuard.sanitize_like_pattern("50%_off\\x")
        assert result == "50\\%\\_off\\\\x"

    def test_plain_pattern_unchanged(self) -> None:
        assert SqlSecurityGuard.sanitize_like_pattern("alice") == "alice"

    def test_returns_empty_string_for_non_string(self) -> None:
        assert SqlSecurityGuard.sanitize_like_pattern(None) == ""
        result = SqlSecurityGuard.sanitize_like_pattern(123)  # type: ignore[arg-type]
        assert result == ""
