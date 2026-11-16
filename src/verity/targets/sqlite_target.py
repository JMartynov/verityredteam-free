"""In-memory SQLite synthetic target demonstrating SQL injection (CWE-89)."""

from __future__ import annotations

import sqlite3
from typing import Any

from verity.mcp_library.sql_guard import SqlSecurityError, SqlSecurityGuard


class SqliteSyntheticTarget:
    """Dual-profile SQLite target: string-concatenated SQL vs parameterized query."""

    target_id: str = "sqlite-basic"
    name: str = "SQLite Basic Target"
    cwe_id: str = "CWE-89"

    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")
        self._seed()

    def _seed(self) -> None:
        self._conn.execute(
            "CREATE TABLE users ("
            "id INTEGER PRIMARY KEY, "
            "username TEXT NOT NULL, "
            "role TEXT NOT NULL, "
            "secret TEXT NOT NULL)"
        )
        self._conn.executemany(
            "INSERT INTO users (username, role, secret) VALUES (?, ?, ?)",
            [
                ("alice", "user", "alice-low-secret"),
                ("bob", "user", "bob-low-secret"),
                ("admin", "admin", "FLAG{admin_sqlite_secret}"),
            ],
        )
        self._conn.commit()

    def close(self) -> None:
        """Close the underlying in-memory SQLite connection."""
        self._conn.close()

    def get_tools(self, profile: str = "vulnerable") -> list[dict[str, Any]]:
        """Return the tool schema for the requested profile."""
        if profile == "secure":
            description = "Look up a user by username using a parameterized query."
        else:
            description = (
                "Look up a user by username. The SQL string is built by "
                "concatenating the supplied username directly into the query."
            )
        return [
            {
                "name": "lookup_user",
                "description": description,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "username": {
                            "type": "string",
                            "description": "Username to look up.",
                        }
                    },
                    "required": ["username"],
                },
            }
        ]

    def _build_query(
        self, username: str, profile: str
    ) -> tuple[str, tuple[Any, ...]]:
        if profile == "secure":
            query = "SELECT id, username, role FROM users WHERE username = ?"
            SqlSecurityGuard.validate_single_select_statement(query)
            return query, (username,)
        query = (
            "SELECT id, username, role, secret FROM users "
            f"WHERE username = '{username}'"
        )
        return query, ()

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        profile: str = "vulnerable",
    ) -> dict[str, Any]:
        """Invoke the lookup_user tool under the requested profile."""
        if name != "lookup_user":
            return {"error": f"Unknown tool: {name}", "rows": [], "count": 0}
        username = str(arguments.get("username", ""))
        query, params = self._build_query(username, profile)
        try:
            cursor = self._conn.execute(query, params)
            rows = [
                {"id": row[0], "username": row[1], "role": row[2]}
                for row in cursor.fetchall()
            ]
        except (sqlite3.Error, SqlSecurityError) as exc:
            return {"error": str(exc), "rows": [], "count": 0}
        return {"rows": rows, "count": len(rows)}

    def run_demo_probe(self) -> dict[str, Any]:
        """Run the SQL-injection demo probe for both profiles."""
        payload = "' OR '1'='1"
        vulnerable = self.call_tool(
            "lookup_user", {"username": payload}, profile="vulnerable"
        )
        secure = self.call_tool(
            "lookup_user", {"username": payload}, profile="secure"
        )
        vulnerable_breached = vulnerable.get("count", 0) > 1
        secure_defended = secure.get("count", 0) == 0
        return {
            "target_id": self.target_id,
            "name": self.name,
            "cwe_id": self.cwe_id,
            "vulnerable_breached": vulnerable_breached,
            "secure_defended": secure_defended,
            "evidence": {
                "payload": payload,
                "vulnerable_result": vulnerable,
                "secure_result": secure,
            },
        }
