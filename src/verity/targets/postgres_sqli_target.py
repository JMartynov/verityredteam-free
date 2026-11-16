"""In-memory multi-tenant invoice store demonstrating BOLA (CWE-639)."""

from __future__ import annotations

from typing import Any

from verity.mcp_library.sql_guard import SqlSecurityGuard

_SAFE_COLUMNS: tuple[str, ...] = ("invoice_id", "tenant_id", "amount", "status")


class PostgresSqliSyntheticTarget:
    """Dual-profile multi-tenant target: cross-tenant BOLA vs scoped projection."""

    target_id: str = "postgres-basic"
    name: str = "PostgreSQL Multi-Tenant Target"
    cwe_id: str = "CWE-639"

    def __init__(self) -> None:
        self._session_tenant = "tenant-a"
        self._invoices: dict[str, dict[str, Any]] = {
            "inv_a_100": {
                "invoice_id": "inv_a_100",
                "tenant_id": "tenant-a",
                "amount": 100.0,
                "status": "paid",
                "password_hash": "hash_a_100",
            },
            "inv_a_200": {
                "invoice_id": "inv_a_200",
                "tenant_id": "tenant-a",
                "amount": 250.0,
                "status": "open",
                "password_hash": "hash_a_200",
            },
            "inv_b_cyber": {
                "invoice_id": "inv_b_cyber",
                "tenant_id": "tenant-b",
                "amount": 1337.0,
                "status": "overdue",
                "password_hash": "FAKE-PW-HASH-B-CYBER",
            },
        }

    def get_tools(self, profile: str = "vulnerable") -> list[dict[str, Any]]:
        """Return the get_invoice tool schema for the requested profile."""
        if profile == "secure":
            description = (
                "Fetch an invoice scoped to the active session tenant, "
                "returning only non-sensitive columns."
            )
        else:
            description = (
                "Fetch an invoice by identifier. Tenant scoping and column "
                "masking are not enforced."
            )
        return [
            {
                "name": "get_invoice",
                "description": description,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "invoice_id": {
                            "type": "string",
                            "description": "Invoice identifier.",
                        }
                    },
                    "required": ["invoice_id"],
                },
            }
        ]

    def _lookup(
        self, invoice_id: str, tenant_id: str
    ) -> dict[str, Any] | None:
        invoice = self._invoices.get(invoice_id)
        if invoice is None or invoice["tenant_id"] != tenant_id:
            return None
        return invoice

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        profile: str = "vulnerable",
    ) -> dict[str, Any]:
        """Invoke the get_invoice tool under the requested profile."""
        if name != "get_invoice":
            return {"error": f"Unknown tool: {name}", "invoice": None}
        invoice_id = str(arguments.get("invoice_id", ""))

        if profile == "secure":
            params = SqlSecurityGuard.enforce_tenant_filter(
                {"invoice_id": invoice_id}, self._session_tenant
            )
            invoice = self._lookup(params["invoice_id"], params["tenant_id"])
            projected = SqlSecurityGuard.apply_projection(invoice, _SAFE_COLUMNS)
            return {"invoice": projected}

        invoice = self._invoices.get(invoice_id)
        return {"invoice": invoice}

    def run_demo_probe(self) -> dict[str, Any]:
        """Run the code-execution demo probe for both profiles."""
        """Run the NoSQL operator-injection demo probe for both profiles."""
        """Run the cross-tenant BOLA demo probe for both profiles."""
        target_invoice = "inv_b_cyber"
        vulnerable = self.call_tool(
            "get_invoice", {"invoice_id": target_invoice}, profile="vulnerable"
        )
        secure = self.call_tool(
            "get_invoice", {"invoice_id": target_invoice}, profile="secure"
        )
        vulnerable_invoice = vulnerable.get("invoice") or {}
        vulnerable_breached = (
            vulnerable_invoice.get("tenant_id") == "tenant-b"
            and "password_hash" in vulnerable_invoice
        )
        secure_defended = secure.get("invoice") is None
        return {
            "target_id": self.target_id,
            "name": self.name,
            "cwe_id": self.cwe_id,
            "vulnerable_breached": vulnerable_breached,
            "secure_defended": secure_defended,
            "evidence": {
                "session_tenant": self._session_tenant,
                "requested_invoice": target_invoice,
                "vulnerable_result": vulnerable,
                "secure_result": secure,
            },
        }
