"""FastMCP-compatible MCP Security Auditor Server for Verity Red Team."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable
    from http.server import ThreadingHTTPServer

from verity.discovery.auditor import ConsolidatedSecurityAuditor
from verity.discovery.models import ClientType, DiscoveredServerConfig, TransportType
from verity.discovery.transports.stdio import StdioDiscoveryTransport
from verity.lookup.engine import VulnerabilityLookupEngine
from verity.mcp_server.bootstrap import ServerContext
from verity.mcp_server.stream_logger import append_tool_call_log as _append_tool_call_log
from verity.mcp_server.tools import TOOL_DEFINITIONS, VerityToolDispatcher

logger = logging.getLogger("verity.mcp_server")


class VerityDiscoveryMcpServer:
    """JSON-RPC MCP Server instance handling requests via tool dispatcher."""

    def __init__(self, context: ServerContext) -> None:
        self.context = context
        self.dispatcher = VerityToolDispatcher(context)

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Dispatch JSON-RPC request to tools."""
        req_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params", {})

        # Ignore JSON-RPC notifications (no id or notification method - do not reply)
        if method.startswith("notifications/") or method == "initialized" or "id" not in request:
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": "verity-discovery-security-mcp-server",
                        "version": "1.0.0",
                    },
                },
            }

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": TOOL_DEFINITIONS},
            }

        if method == "tools/call":
            tool_name = params.get("name", "")
            args = params.get("arguments", {})
            res = self.dispatcher.execute_tool(tool_name, args)
            if (
                isinstance(res, dict)
                and res.get("ok") is False
                and f"Unknown tool: '{tool_name}'" == res.get("error")
            ):
                # Check legacy handle_jsonrpc_request fallback
                legacy = handle_jsonrpc_request(request)
                if "result" in legacy:
                    return legacy
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Tool '{tool_name}' not found"},
                }
            is_error = isinstance(res, dict) and (res.get("ok") is False or "error" in res)
            _append_tool_call_log(tool_name, args, res)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(res, indent=2)}],
                    "isError": is_error,
                },
            }

        return handle_jsonrpc_request(request)


def audit_target_mcp(
    target: str,
    transport_type: str = "stdio",
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    live_probe: bool = True,
    fingerprint_dir: str = "data/fingerprints",
    vuln_dir: str = "data/vulnerabilities",
) -> dict[str, Any]:
    """Audit a target MCP server by URL, package name, or command.

    Args:
        target: Target URL ('http://localhost:3000/sse') or command ('mcp-remote@0.0.8').
        transport_type: Transport type ('stdio', 'sse', 'http').
        args: Optional list of CLI arguments for stdio command.
        env: Optional environment variables dictionary.
        live_probe: Whether to dynamically probe live MCP capabilities.
        fingerprint_dir: Local or snapshot directory for passports.
        vuln_dir: Local or snapshot directory for OSV vulnerabilities.

    Returns:
        Structured audit report with matched package, confidence, CVE findings, and advice.
    """
    is_sse = "http" in target or transport_type.lower() == "sse"
    t_type = TransportType.SSE if is_sse else TransportType.STDIO
    url = target if t_type == TransportType.SSE else None
    cmd = None if t_type == TransportType.SSE else target

    final_args = list(args or [])
    if cmd and " " in cmd and not final_args:
        parts = cmd.split()
        cmd = parts[0]
        final_args = parts[1:]
    elif cmd and not final_args:
        final_args = [cmd]

    if not (" " in target or "/" in target):
        server_name = target
    elif "/" in target:
        server_name = Path(target).stem
    else:
        server_name = target.split()[0]

    config = DiscoveredServerConfig(
        client_type=ClientType.CUSTOM,
        server_name=server_name,
        command=cmd,
        args=tuple(final_args),
        env=env or {},
        transport_type=t_type,
        url=url,
    )

    from verity.discovery.transports.sse import HttpSseDiscoveryTransport

    transport = (
        HttpSseDiscoveryTransport(timeout_seconds=8.0)
        if t_type == TransportType.SSE
        else StdioDiscoveryTransport(timeout_seconds=8.0)
    )


    auditor = ConsolidatedSecurityAuditor(
        fingerprint_dir=fingerprint_dir,
        vuln_dir=vuln_dir,
        transport=transport,
    )
    record = auditor.audit_server(
        config,
        live_probe=live_probe and (url is not None or cmd is not None),
    )
    return record.to_dict()




def lookup_vulnerabilities(
    package_name: str,
    version: str | None = None,
    vuln_dir: str = "data/vulnerabilities",
) -> dict[str, Any]:
    """Query known OSV security advisories for an MCP package name and version."""
    engine = VulnerabilityLookupEngine.from_auto(vuln_dir)
    res = engine.query(identifier=package_name, version=version)
    return res.to_dict()


def fingerprint_target(
    tools: list[dict[str, Any]],
    prompts: list[dict[str, Any]] | None = None,
    resources: list[dict[str, Any]] | None = None,
    name_hint: str | None = None,
    fingerprint_dir: str = "data/fingerprints",
) -> dict[str, Any]:
    """Match exposed MCP tools, prompts, and resources against 3,903+ passports."""
    from verity.discovery.matcher import HybridDiscoveryMatcher
    from verity.discovery.models import ClientType, DiscoveredServerConfig, LiveServerCapability

    matcher = HybridDiscoveryMatcher(fingerprint_dir)
    live_cap = LiveServerCapability(
        server_name=name_hint or "target-mcp",
        tools=tuple(tools or []),
        prompts=tuple(prompts or []),
        resources=tuple(resources or []),
        is_responsive=True,
    )
    config = DiscoveredServerConfig(
        client_type=ClientType.CUSTOM,
        server_name=name_hint or "target-mcp",
    )
    match_res = matcher.match_live_capability(live_cap, config)
    return match_res.to_dict()


def scan_environment(
    custom_schemas: dict[str, list[dict[str, Any]]] | None = None,
    scan_dirs: list[str] | None = None,
    fingerprint_dir: str = "data/fingerprints",
    vuln_dir: str = "data/vulnerabilities",
) -> dict[str, Any]:
    """Scan all configured MCP servers across client directories and/or custom schemas.

    Audits all discovered tool contracts, matches tri-layer passports, and correlates OSV CVEs.
    """
    from verity.fingerprint.matcher import FingerprintMatcher
    from verity.lookup.engine import VulnerabilityLookupEngine

    matcher = FingerprintMatcher()
    matcher.load_auto(Path(fingerprint_dir))
    vuln_engine = VulnerabilityLookupEngine.from_auto(Path(vuln_dir))

    # Candidate directories to scan
    default_dirs = [
        Path("/root/.gemini/antigravity/mcp"),
        Path.home() / ".gemini" / "antigravity" / "mcp",
    ]
    if scan_dirs is not None:
        candidate_paths = [Path(p) for p in scan_dirs]
    else:
        candidate_paths = [p for p in default_dirs if p.is_dir()]

    discovered_servers: dict[str, list[dict[str, Any]]] = {}

    # 1. Gather schemas from directories
    for base_dir in candidate_paths:
        if not base_dir.is_dir():
            continue
        for server_dir in base_dir.iterdir():
            if server_dir.is_dir() and not server_dir.name.startswith("."):
                server_name = server_dir.name
                tools: list[dict[str, Any]] = []
                for json_file in server_dir.glob("*.json"):
                    try:
                        data = json.loads(json_file.read_text(encoding="utf-8"))
                        if isinstance(data, dict):
                            tools.append(data)
                    except Exception:
                        pass
                if tools:
                    discovered_servers[server_name] = tools

    # 2. Add any custom schemas provided directly
    if custom_schemas:
        for s_name, s_tools in custom_schemas.items():
            discovered_servers[s_name] = s_tools

    results: list[dict[str, Any]] = []
    has_critical = False
    has_high = False

    for server_name, tools in discovered_servers.items():
        fp_res = matcher.match(tools=tools, server_name_hint=server_name)
        pkg_to_query = (
            fp_res.package_name
            if fp_res.matched and fp_res.package_name
            else server_name
        )
        ver_to_query = fp_res.matched_version if fp_res.matched else None

        vuln_res = vuln_engine.query(identifier=pkg_to_query, version=ver_to_query)

        findings: list[dict[str, Any]] = []
        highest_severity = "CLEAN"

        if vuln_res.is_vulnerable:
            highest_severity = vuln_res.max_severity
            if highest_severity == "CRITICAL":
                has_critical = True
            elif highest_severity == "HIGH":
                has_high = True

            for v in vuln_res.vulnerabilities:
                findings.append({
                    "advisory_id": v.vulnerability_id,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "cwe_ids": list(v.cwe_ids),
                    "vulnerable_tools": list(v.vulnerable_tools),
                    "summary": v.summary,
                    "details": v.details,
                    "remediation": v.remediation_guidance,
                })

        upgrade_advice = None
        if vuln_res.upgrade_advice:
            upgrade_advice = vuln_res.upgrade_advice.to_dict()

        results.append({
            "server_name": server_name,
            "tool_count": len(tools),
            "matched_passport": fp_res.package_name,
            "matched_version": fp_res.matched_version,
            "confidence_score": round(fp_res.confidence_score * 100, 1),
            "match_layer": fp_res.match_layer,
            "highest_severity": highest_severity,
            "is_vulnerable": vuln_res.is_vulnerable,
            "findings_count": len(findings),
            "findings": findings,
            "upgrade_advice": upgrade_advice,
        })

    if has_critical:
        overall_risk = "CRITICAL"
    elif has_high:
        overall_risk = "HIGH"
    elif results:
        overall_risk = "CLEAN"
    else:
        overall_risk = "UNKNOWN"

    return {

        "status": "ok",
        "total_servers": len(results),
        "overall_risk": overall_risk,
        "servers": results,
    }


def health_check() -> dict[str, Any]:
    """Verify health and readiness of the Verity MCP Auditor server."""
    return {
        "status": "healthy",
        "service": "verity-mcp-auditor",
        "version": "1.0.0",
        "capabilities": [
            "verity_scan_environment",
            "verity_audit_target",
            "verity_fingerprint_target",
            "verity_lookup_vulnerabilities",
            "verity_health_check",
        ],
    }


def handle_jsonrpc_request(request: dict[str, Any]) -> dict[str, Any] | None:
    """Process a standard MCP JSON-RPC protocol message."""
    req_id = request.get("id")
    method = request.get("method", "")
    params = request.get("params", {})

    # Ignore JSON-RPC notifications (no id or notification method - do not reply)
    if method.startswith("notifications/") or method == "initialized" or "id" not in request:
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "verity-mcp-auditor",
                    "version": "1.0.0",
                },
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "verity_scan_environment",
                        "description": (
                            "Scan and audit all configured MCP servers across client "
                            "environment directories or custom schemas."
                        ),
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "custom_schemas": {
                                    "type": "object",
                                    "description": (
                                        "Optional mapping of server names to lists of tool schemas."
                                    ),
                                },
                                "scan_dirs": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": (
                                        "Optional list of directories to scan for MCP servers."
                                    ),
                                },
                            },
                        },
                    },
                    {
                        "name": "verity_audit_target",
                        "description": (
                            "Audit an MCP server (by URL, command, or package) to fingerprint "
                            "its contract and detect known CVEs."
                        ),
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": (
                                        "Target MCP URL ('http://localhost:3000/sse') "
                                        "or package ('mcp-remote@0.0.8')."
                                    ),
                                },
                                "transport_type": {
                                    "type": "string",
                                    "description": "Transport type: 'stdio', 'sse', or 'http'.",
                                    "default": "stdio",
                                },
                                "live_probe": {
                                    "type": "boolean",
                                    "description": (
                                        "Whether to dynamically query live tools and capabilities."
                                    ),
                                    "default": True,
                                },
                            },
                            "required": ["target"],
                        },
                    },
                    {
                        "name": "verity_fingerprint_target",
                        "description": (
                            "Match exposed MCP tools and schemas against 3,903+ "
                            "passport signatures."
                        ),


                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "tools": {
                                    "type": "array",
                                    "items": {"type": "object"},
                                    "description": "List of discovered MCP tool schemas.",
                                },
                                "prompts": {
                                    "type": "array",
                                    "items": {"type": "object"},
                                    "description": "Optional list of prompt templates.",
                                },
                                "resources": {
                                    "type": "array",
                                    "items": {"type": "object"},
                                    "description": "Optional list of resource templates.",
                                },
                                "name_hint": {
                                    "type": "string",
                                    "description": "Optional name hint for target server.",
                                },
                            },
                            "required": ["tools"],
                        },
                    },
                    {
                        "name": "verity_lookup_vulnerabilities",
                        "description": (
                            "Lookup known OSV security advisories for an MCP package."
                        ),
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "package_name": {
                                    "type": "string",
                                    "description": (
                                        "MCP package name ('mcp-remote' or 'server-postgres')."
                                    ),
                                },
                                "version": {
                                    "type": "string",
                                    "description": "Optional package version.",
                                },
                            },
                            "required": ["package_name"],
                        },
                    },
                    {
                        "name": "verity_health_check",
                        "description": "Check the health and readiness of the Verity MCP Auditor.",
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                ]

            },
        }

    if method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments", {})

        try:
            if tool_name == "verity_scan_environment":
                res = scan_environment(
                    custom_schemas=args.get("custom_schemas"),
                    scan_dirs=args.get("scan_dirs"),
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(res, indent=2)}]
                    },
                }

            if tool_name == "verity_audit_target":
                res = audit_target_mcp(
                    target=args.get("target", ""),
                    transport_type=args.get("transport_type", "stdio"),
                    live_probe=args.get("live_probe", True),
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(res, indent=2)}]
                    },
                }

            if tool_name == "verity_fingerprint_target":
                res = fingerprint_target(
                    tools=args.get("tools", []),
                    prompts=args.get("prompts"),
                    resources=args.get("resources"),
                    name_hint=args.get("name_hint"),
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(res, indent=2)}]
                    },
                }

            if tool_name == "verity_lookup_vulnerabilities":
                res = lookup_vulnerabilities(
                    package_name=args.get("package_name", ""),
                    version=args.get("version"),
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(res, indent=2)}]
                    },
                }

            if tool_name == "verity_health_check":
                res = health_check()
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(res, indent=2)}]
                    },
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Tool '{tool_name}' not found"},
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32000, "message": str(exc)},
            }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method '{method}' not supported"},
    }


def run_stdio_server(server: VerityDiscoveryMcpServer | None = None) -> None:
    """Run MCP server in standard I/O (stdio) JSON-RPC mode."""
    import sys

    from verity.mcp_server.bootstrap import initialize_server_context

    if server is None:
        context = initialize_server_context()
        server = VerityDiscoveryMcpServer(context)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = server.handle_request(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except Exception as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()


def create_http_sse_server(
    host: str = "0.0.0.0",
    port: int = 8765,
    server: VerityDiscoveryMcpServer | None = None,
) -> ThreadingHTTPServer:
    """Factory creating configured ThreadingHTTPServer for MCP SSE/HTTP JSON-RPC."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from verity.mcp_server.bootstrap import initialize_server_context

    if server is None:
        context = initialize_server_context()
        server = VerityDiscoveryMcpServer(context)

    class McpHttpHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass  # Suppress default noisy stderr logging

        def do_GET(self) -> None:
            if self.path in ("/health", "/healthz"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(
                    json.dumps({
                        "ok": True,
                        "status": "healthy",
                        "server": "verity-mcp-auditor",
                        "tools": len(TOOL_DEFINITIONS),
                    }).encode("utf-8")
                )
            elif self.path in ("/sse", "/events"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                client_host = self.headers.get("Host") or (
                    f"127.0.0.1:{port}" if host == "0.0.0.0" else f"{host}:{port}"
                )
                endpoint_event = f"event: endpoint\ndata: http://{client_host}/messages\n\n"
                self.wfile.write(endpoint_event.encode("utf-8"))
                self.wfile.flush()
                try:
                    import time

                    while True:
                        time.sleep(15)
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, Exception):
                    pass
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(
                    json.dumps({
                        "ok": True,
                        "server": "verity-mcp-auditor",
                        "tools": len(TOOL_DEFINITIONS),
                    }).encode("utf-8")
                )

        def do_POST(self) -> None:
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len) if content_len > 0 else b"{}"
            try:
                req = json.loads(post_body.decode("utf-8"))
                resp = server.handle_request(req)
            except Exception as exc:
                resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }

            if resp is None:
                self.send_response(204)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                return

            resp_bytes = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.end_headers()
            self.wfile.write(resp_bytes)

        def do_OPTIONS(self) -> None:
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, *")
            self.end_headers()

    httpd = ThreadingHTTPServer((host, port), McpHttpHandler)
    httpd.daemon_threads = True
    return httpd


def run_http_sse_server(
    host: str = "0.0.0.0",
    port: int = 8765,
    server: VerityDiscoveryMcpServer | None = None,
) -> None:
    """Run lightweight HTTP/SSE JSON-RPC 2.0 server using Python standard library."""
    httpd = create_http_sse_server(host=host, port=port, server=server)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def run_server(
    host: str = "0.0.0.0",
    port: int = 8765,
    transport: str = "stdio",
    server: VerityDiscoveryMcpServer | None = None,
) -> None:
    """Entrypoint to run the server in stdio or SSE/HTTP mode."""
    if transport == "stdio":
        run_stdio_server(server=server)
    else:
        run_http_sse_server(host=host, port=port, server=server)


def create_mcp_server() -> Callable[..., None]:
    """Return the MCP server runner entrypoint."""
    return run_server


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verity MCP Security Auditor Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host address")
    parser.add_argument("--port", type=int, default=8765, help="Port number")
    parser.add_argument("--transport", default="stdio", choices=["stdio", "sse", "http"])
    args = parser.parse_args()

    run_server(host=args.host, port=args.port, transport=args.transport)
