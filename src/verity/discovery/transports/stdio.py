"""Sandboxed Stdio Transport for dynamic MCP server capability discovery."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import subprocess
import time
from typing import Any

from verity.discovery.models import DiscoveredServerConfig, LiveServerCapability
from verity.discovery.transports.base import BaseDiscoveryTransport

logger = logging.getLogger("verity.discovery.transports.stdio")


class StdioDiscoveryTransport(BaseDiscoveryTransport):
    """Safely spawns child process with sanitized environment to inspect JSON-RPC capabilities."""

    def __init__(self, timeout_seconds: float = 5.0, strip_secrets: bool = True) -> None:
        super().__init__(timeout_seconds=timeout_seconds)
        self.strip_secrets = strip_secrets

    def _sanitize_env(self, custom_env: dict[str, str]) -> dict[str, str]:
        """Create minimal, safe environment for child process without leaking parent credentials."""
        safe_keys = {
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "SHELL",
            "TMPDIR",
            "TMP",
            "TEMP",
            "NODE_PATH",
            "PYTHONPATH",
            "VIRTUAL_ENV",
            "LANG",
            "LC_ALL",
        }
        sanitized = {k: v for k, v in os.environ.items() if k in safe_keys}
        if not self.strip_secrets:
            sanitized.update(custom_env)
        else:
            # Only include explicit server env vars that don't match sensitive API key patterns
            for k, v in custom_env.items():
                if not any(sub in k.lower() for sub in ("api_key", "secret", "password", "token")):
                    sanitized[k] = v
        return sanitized

    def inspect(self, config: DiscoveredServerConfig) -> LiveServerCapability:
        """Execute JSON-RPC 2.0 handshake over non-interactive stdin/stdout."""
        if not config.command:
            return LiveServerCapability(
                server_name=config.server_name,
                is_responsive=False,
                error_message="Missing execution command in configuration",
            )

        cmd = [config.command, *config.args]
        env = self._sanitize_env(config.env)
        start_time = time.perf_counter()

        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                bufsize=0,
            )

            # 1. Send 'initialize' request
            init_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "verity-discovery", "version": "1.0.0"},
                },
            }
            if proc.stdin:
                proc.stdin.write(json.dumps(init_req) + "\n")
                proc.stdin.flush()

            # Read initialize response
            init_resp = self._read_jsonrpc_response(proc, timeout=self.timeout_seconds / 2)
            if init_resp is None and proc.poll() is not None:
                elapsed = (time.perf_counter() - start_time) * 1000.0
                return LiveServerCapability(
                    server_name=config.server_name,
                    is_responsive=False,
                    error_message=(
                        f"Server process exited with code {proc.returncode}"
                    ),
                    response_time_ms=elapsed,
                )
            protocol_v = "2024-11-05"
            if init_resp and "result" in init_resp:
                protocol_v = init_resp["result"].get("protocolVersion", protocol_v)

            # Send initialized notification
            if proc.stdin:
                proc.stdin.write(
                    json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
                )
                proc.stdin.flush()

            # 2. Query 'tools/list'
            tools: list[dict[str, Any]] = []
            if proc.stdin:
                proc.stdin.write(
                    json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
                    + "\n"
                )
                proc.stdin.flush()
            tools_resp = self._read_jsonrpc_response(proc, timeout=self.timeout_seconds / 2)
            if tools_resp and "result" in tools_resp:
                tools = tools_resp["result"].get("tools", [])

            # 3. Query 'prompts/list'
            prompts: list[dict[str, Any]] = []
            if proc.stdin:
                proc.stdin.write(
                    json.dumps({"jsonrpc": "2.0", "id": 3, "method": "prompts/list", "params": {}})
                    + "\n"
                )
                proc.stdin.flush()
            prompts_resp = self._read_jsonrpc_response(proc, timeout=self.timeout_seconds / 4)
            if prompts_resp and "result" in prompts_resp:
                prompts = prompts_resp["result"].get("prompts", [])

            # 4. Query 'resources/list'
            resources: list[dict[str, Any]] = []
            if proc.stdin:
                proc.stdin.write(
                    json.dumps(
                        {"jsonrpc": "2.0", "id": 4, "method": "resources/list", "params": {}}
                    )
                    + "\n"
                )
                proc.stdin.flush()
            resources_resp = self._read_jsonrpc_response(proc, timeout=self.timeout_seconds / 4)
            if resources_resp and "result" in resources_resp:
                resources = resources_resp["result"].get("resources", [])

            elapsed = (time.perf_counter() - start_time) * 1000.0
            return LiveServerCapability(
                server_name=config.server_name,
                protocol_version=protocol_v,
                tools=tuple(tools),
                prompts=tuple(prompts),
                resources=tuple(resources),
                is_responsive=True,
                response_time_ms=elapsed,
            )

        except Exception as exc:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            logger.debug("Dynamic inspection failed for %s: %s", config.server_name, exc)
            return LiveServerCapability(
                server_name=config.server_name,
                is_responsive=False,
                error_message=str(exc),
                response_time_ms=elapsed,
            )
        finally:
            if proc:
                with contextlib.suppress(Exception):
                    proc.terminate()
                    proc.wait(timeout=0.5)
                with contextlib.suppress(Exception):
                    proc.kill()

    def _read_jsonrpc_response(
        self, proc: subprocess.Popen, timeout: float
    ) -> dict[str, Any] | None:
        """Read single JSON-RPC message from process stdout."""
        if not proc.stdout:
            return None
        start = time.time()
        while time.time() - start < timeout:
            line = proc.stdout.readline()
            if line:
                line_str = line.strip()
                if line_str.startswith("{") and line_str.endswith("}"):
                    try:
                        return json.loads(line_str)
                    except Exception:
                        pass
            elif proc.poll() is not None:
                break
            time.sleep(0.05)
        return None
