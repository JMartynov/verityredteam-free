"""SQL query safety, parameterization enforcement, and projection guards."""

from __future__ import annotations

import re
from typing import Any

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError
from sqlglot.tokens import TokenType

SUPPORTED_DIALECTS: tuple[str, ...] = (
    "postgres",
    "mysql",
    "sqlite",
    "duckdb",
    "tsql",
    "bigquery",
    "snowflake",
)


class SqlSecurityError(Exception):
    """Raised when an unsafe or unparameterized SQL operation is detected."""

    def __init__(self, message: str = "", *, rule_id: str | None = None) -> None:
        super().__init__(message)
        self.rule_id: str | None = rule_id


class SqlSecurityGuard:
    """Security guard providing parameterization checks, tenant scoping, and column projections."""

    # Disallowed patterns indicating dynamic string concatenation or raw formatting into SQL
    DANGEROUS_SQL_PATTERNS = (
        re.compile(r"%\s*\(", re.IGNORECASE),  # Python old-style % formatting in queries
        re.compile(r"\{\s*\}", re.IGNORECASE),  # Python str.format() placeholders in queries
        re.compile(r"'\s*\+\s*", re.IGNORECASE),  # String concatenation with quotes
        re.compile(r"\+\s*'", re.IGNORECASE),
    )

    @classmethod
    def validate_parameterized_query(
        cls,
        query: str,
        params: tuple[Any, ...] | list[Any] | dict[str, Any] | None = None,
        dialect: str = "postgres",
    ) -> None:
        """Verify that a SQL query uses parameter placeholders rather than raw concatenation."""
        if not isinstance(query, str) or not query.strip():
            raise SqlSecurityError("SQL query must be a non-empty string.")

        if not isinstance(dialect, str) or not dialect.strip():
            raise SqlSecurityError("SQL dialect must be a non-empty string.")
        normalized_dialect = dialect.strip().lower()

        for pattern in cls.DANGEROUS_SQL_PATTERNS:
            if pattern.search(query):
                msg = (
                    "Unsafe SQL pattern detected: dynamic concatenation or "
                    f"stacked queries prohibited: {query[:50]}"
                )
                raise SqlSecurityError(msg)

        # Token-aware statement boundary detection using the requested dialect
        try:
            tokens = sqlglot.tokenize(query, read=normalized_dialect)
        except (ValueError, TokenError) as exc:
            raise SqlSecurityError(
                "Unable to tokenize SQL query for dialect "
                f"'{normalized_dialect}': {exc}"
            ) from exc

        for idx, token in enumerate(tokens):
            if token.token_type == TokenType.SEMICOLON and (
                idx < len(tokens) - 1 or bool(token.comments)
            ):
                raise SqlSecurityError(
                    "Stacked queries with semicolons are strictly prohibited.",
                    rule_id="DISALLOW_STACKED_QUERIES",
                )

        try:
            stmts = [
                stmt
                for stmt in sqlglot.parse(query, read=normalized_dialect)
                if stmt is not None
            ]
        except (ParseError, TokenError):
            stmts = []

        if len(stmts) > 1:
            raise SqlSecurityError(
                "Stacked queries with semicolons are strictly prohibited.",
                rule_id="DISALLOW_STACKED_QUERIES",
            )

    @classmethod
    def apply_projection(
        cls,
        row: dict[str, Any] | None,
        allowlist: set[str] | list[str] | tuple[str, ...],
    ) -> dict[str, Any] | None:
        """Filter a relational database row dictionary to strictly allowlisted column names."""
        if row is None:
            return None
        allowed_set = set(allowlist)
        return {k: v for k, v in row.items() if k in allowed_set}

    @classmethod
    def enforce_tenant_filter(
        cls,
        params: dict[str, Any],
        session_tenant: str,
    ) -> dict[str, Any]:
        """Bind session_tenant to execution parameters."""
        if not session_tenant:
            raise SqlSecurityError(
                "session_tenant is required for tenant-scoped relational queries."
            )
        out = dict(params)
        out["tenant_id"] = session_tenant
        return out

    @classmethod
    def validate_single_select_statement(
        cls, query: str, dialect: str = "postgres"
    ) -> None:
        """Verify that a raw SQL query is strictly a single, read-only SELECT statement."""
        if not isinstance(query, str) or not query.strip():
            raise SqlSecurityError("SQL query must be a non-empty string.")

        if not isinstance(dialect, str) or dialect.strip().lower() not in SUPPORTED_DIALECTS:
            raise SqlSecurityError(
                f"Unknown or unsupported SQL dialect: '{dialect}'. "
                f"Supported dialects: {', '.join(SUPPORTED_DIALECTS)}."
            )
        dialect = dialect.strip().lower()

        clean_query = query.strip()

        # 1. Neutralize comment-splitting evasion (e.g. SEL/**/ECT or DR/**/OP)
        decommented_spaced = re.sub(r"/\*.*?\*/", " ", clean_query, flags=re.DOTALL)
        decommented_compact = re.sub(r"/\*.*?\*/", "", clean_query, flags=re.DOTALL)

        # 2. Check for semicolons / stacked queries outside string literals
        try:
            tokens = sqlglot.tokenize(clean_query, read=dialect)
            semicolon_indices = [
                i for i, t in enumerate(tokens) if t.token_type == TokenType.SEMICOLON
            ]
            if semicolon_indices and any(idx < len(tokens) - 1 for idx in semicolon_indices):
                raise SqlSecurityError("Stacked queries with semicolons are strictly prohibited.")
        except SqlSecurityError:
            raise
        except Exception:
            pass

        # 3. Check for prohibited keywords outside string literals using SQL tokenization
        prohibited_token_types = {
            TokenType.DROP: "DROP",
            TokenType.DELETE: "DELETE",
            TokenType.UPDATE: "UPDATE",
            TokenType.INSERT: "INSERT",
            TokenType.ALTER: "ALTER",
            TokenType.TRUNCATE: "TRUNCATE",
            TokenType.COMMIT: "COMMIT",
            TokenType.ROLLBACK: "ROLLBACK",
            TokenType.GRANT: "GRANT",
            TokenType.REVOKE: "REVOKE",
            TokenType.CREATE: "CREATE",
            TokenType.EXECUTE: "EXECUTE",
        }

        for check_text in (decommented_compact, decommented_spaced, clean_query):
            try:
                toks = sqlglot.tokenize(check_text, read=dialect)
                for t in toks:
                    if t.token_type in prohibited_token_types:
                        kw = prohibited_token_types[t.token_type]
                        raise SqlSecurityError(
                            f"Prohibited SQL keyword detected in read query: '{kw}'."
                        )
            except SqlSecurityError:
                raise
            except Exception:
                pass

        # 4. Parse AST with sqlglot to enforce single statement and strictly SELECT / WITH
        try:
            stmts = [s for s in sqlglot.parse(clean_query, read=dialect) if s is not None]
        except Exception as e:
            try:
                stmts = [
                    s for s in sqlglot.parse(decommented_spaced, read=dialect) if s is not None
                ]
            except Exception:
                raise SqlSecurityError(f"Malformed or unparseable SQL statement: {e}") from e

        if not stmts:
            raise SqlSecurityError("SQL query must contain at least one valid statement.")

        if len(stmts) > 1:
            raise SqlSecurityError("Stacked queries with semicolons are strictly prohibited.")

        stmt = stmts[0]
        if not isinstance(stmt, (exp.Select, exp.Union)):
            first_raw = clean_query.split()[0].upper() if clean_query.split() else ""
            raise SqlSecurityError(f"Query must begin with SELECT or WITH, found '{first_raw}'.")

        # 5. Prohibit DDL/DML and transaction AST nodes
        prohibited_ast_nodes = (
            exp.Drop,
            exp.Delete,
            exp.Update,
            exp.Insert,
            exp.Create,
            exp.Alter,
            exp.TruncateTable,
            exp.Command,
            exp.Commit,
            exp.Rollback,
            exp.Grant,
            exp.Revoke,
        )
        for node in stmt.find_all(prohibited_ast_nodes):
            raise SqlSecurityError(
                f"Prohibited SQL keyword detected in read query: '{type(node).__name__.upper()}'."
            )

        # 6. Prohibit access to internal system catalog tables (PostgreSQL & MySQL)
        system_catalogs = {
            "PG_CATALOG",
            "PG_SHADOW",
            "PG_AUTHID",
            "PG_ROLES",
            "INFORMATION_SCHEMA",
            "MYSQL.USER",
            "MYSQL.DB",
            "PERFORMANCE_SCHEMA",
            "SYS.SCHEMA",
        }
        for table in stmt.find_all(exp.Table):
            candidates = [
                table.name.upper() if table.name else "",
                table.db.upper() if table.db else "",
                table.catalog.upper() if table.catalog else "",
                f"{table.db.upper()}.{table.name.upper()}" if table.db and table.name else "",
            ]
            for c in candidates:
                if c in system_catalogs or (c and any(sc in c for sc in system_catalogs)):
                    raise SqlSecurityError(
                        f"Access to internal database catalog '{c}' is prohibited."
                    )

    @classmethod
    def validate_identifier_allowlist(
        cls,
        identifier: str,
        allowed: set[str] | list[str] | tuple[str, ...],
    ) -> str:
        """Validate a dynamic column or table identifier against an explicit safe allowlist."""
        if not isinstance(identifier, str) or not identifier.strip():
            raise SqlSecurityError("SQL identifier must be a non-empty string.")

        clean_id = identifier.strip().lower()
        if not re.match(r"^[a-z0-9_]+$", clean_id):
            raise SqlSecurityError(f"Invalid characters in SQL identifier: '{clean_id}'.")

        allowed_set = {a.lower() for a in allowed}
        if clean_id not in allowed_set:
            msg = (
                f"Identifier '{clean_id}' is not in the approved column "
                f"allowlist: {sorted(allowed_set)}."
            )
            raise SqlSecurityError(msg)
        return clean_id

    @classmethod
    def validate_statement_timeout(
        cls,
        timeout_ms: int | float | None,
        max_allowed_ms: int = 5000,
    ) -> int:
        """Validate and clamp statement execution timeout within safe bounds."""
        if timeout_ms is None:
            return 1000
        try:
            val = int(timeout_ms)
        except (ValueError, TypeError) as e:
            raise SqlSecurityError(f"Invalid statement timeout value: '{timeout_ms}'.") from e

        if val < 1:
            raise SqlSecurityError("Statement timeout must be greater than 0 ms.")
        return min(val, max_allowed_ms)

    @classmethod
    def sanitize_like_pattern(cls, pattern: str) -> str:
        """Escape SQL LIKE wildcards (%, _) and backslashes to prevent wildcard injection."""
        if not isinstance(pattern, str):
            return ""
        # Escape backslash first, then % and _
        escaped = pattern.replace("\\", "\\\\")
        escaped = escaped.replace("%", "\\%")
        return escaped.replace("_", "\\_")
