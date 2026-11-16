"""In-memory NoSQL document store demonstrating operator injection (CWE-943)."""

from __future__ import annotations

import re
from typing import Any

_ALLOWED_PROJECTION: tuple[str, ...] = ("username", "role", "email")


class MongoSyntheticTarget:
    """Dual-profile Mongo-style target: operator injection vs scalar equality."""

    target_id: str = "mongo-basic"
    name: str = "MongoDB NoSQL Target"
    cwe_id: str = "CWE-943"

    def __init__(self) -> None:
        self._customers: list[dict[str, Any]] = [
            {
                "username": "alice",
                "role": "user",
                "email": "alice@example.com",
                "secret": "alice-secret",
            },
            {
                "username": "bob",
                "role": "user",
                "email": "bob@example.com",
                "secret": "bob-secret",
            },
            {
                "username": "admin",
                "role": "admin",
                "email": "admin@example.com",
                "secret": "FLAG{mongo_admin_secret}",
            },
        ]

    def get_tools(self, profile: str = "vulnerable") -> list[dict[str, Any]]:
        """Return the find_customer tool schema for the requested profile."""
        if profile == "secure":
            description = (
                "Find customers using strictly scalar string equality on "
                "allowlisted fields."
            )
        else:
            description = (
                "Find customers by passing a query document directly to the "
                "in-memory store without operator sanitisation."
            )
        return [
            {
                "name": "find_customer",
                "description": description,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "object",
                            "description": "Query document to match customers.",
                        }
                    },
                    "required": ["query"],
                },
            }
        ]

    @staticmethod
    def _eval_operator(value: Any, operator: str, operand: Any) -> bool:
        if operator == "$ne":
            return value != operand
        if operator == "$gt":
            try:
                return value > operand  # type: ignore[operator]
            except TypeError:
                return False
        if operator == "$gte":
            try:
                return value >= operand  # type: ignore[operator]
            except TypeError:
                return False
        if operator == "$regex":
            return re.search(str(operand), str(value)) is not None
        return False

    def _match_vulnerable(
        self, document: dict[str, Any], query: dict[str, Any]
    ) -> bool:
        for key, value in query.items():
            if key == "$where":
                match = re.search(r"/([^/]+)/", str(value))
                if match and not re.search(
                    match.group(1), str(document.get("username", ""))
                ):
                    return False
                continue
            if isinstance(value, dict):
                for operator, operand in value.items():
                    if not self._eval_operator(
                        document.get(key), operator, operand
                    ):
                        return False
            else:
                if document.get(key) != value:
                    return False
        return True

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        profile: str = "vulnerable",
    ) -> dict[str, Any]:
        """Invoke the find_customer tool under the requested profile."""
        if name != "find_customer":
            return {"error": f"Unknown tool: {name}", "matches": []}

        query = arguments.get("query")
        if not isinstance(query, dict):
            return {"error": "query must be an object", "matches": []}

        if profile == "secure":
            if not query:
                return {"error": "query must be non-empty", "matches": []}
            for key, value in query.items():
                if (
                    not isinstance(key, str)
                    or key.startswith("$")
                    or re.match(r"^[A-Za-z0-9_]+$", key) is None
                ):
                    return {
                        "error": f"invalid query key: {key!r}",
                        "matches": [],
                    }
                if not isinstance(value, str):
                    return {
                        "error": "operator payloads are not permitted",
                        "matches": [],
                    }
            matches = [
                {
                    k: document[k]
                    for k in _ALLOWED_PROJECTION
                    if k in document
                }
                for document in self._customers
                if all(
                    document.get(key) == value
                    for key, value in query.items()
                )
            ]
            return {"matches": matches}

        matches = [
            dict(document)
            for document in self._customers
            if self._match_vulnerable(document, query)
        ]
        return {"matches": matches}

    def run_demo_probe(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"username": {"$ne": None}}
        vulnerable = self.call_tool(
            "find_customer", {"query": payload}, profile="vulnerable"
        )
        secure = self.call_tool(
            "find_customer", {"query": payload}, profile="secure"
        )
        vulnerable_breached = len(vulnerable.get("matches", [])) > 1
        secure_defended = len(secure.get("matches", [])) == 0
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
