"""Read-only Http / SSE transport for remote MCP server discovery."""

from __future__ import annotations

import contextlib
import json
import logging
import ssl
import time
import urllib.request

from verity.discovery.models import DiscoveredServerConfig, LiveServerCapability
from verity.discovery.transports.base import BaseDiscoveryTransport

logger = logging.getLogger("verity.discovery.transports.sse")


class HttpSseDiscoveryTransport(BaseDiscoveryTransport):
    """Inspects remote SSE / streamable-HTTP MCP servers using lightweight read-only HTTP probes."""

    def __init__(self, timeout_seconds: float = 5.0) -> None:
        super().__init__(timeout_seconds=timeout_seconds)

    def _get_candidate_urls(self, original_url: str) -> list[str]:
        """Generate candidate URLs to resolve container-to-host or container-to-container loopback."""
        candidates = [original_url]
        if "localhost" in original_url or "127.0.0.1" in original_url:
            # Sibling container name on compose bridge network
            c_mock = original_url.replace("localhost", "mock-mcp-targets").replace(
                "127.0.0.1", "mock-mcp-targets"
            )
            if c_mock not in candidates:
                candidates.append(c_mock)
            # Docker host gateway resolution
            c_host = original_url.replace("localhost", "host.docker.internal").replace(
                "127.0.0.1", "host.docker.internal"
            )
            if c_host not in candidates:
                candidates.append(c_host)
        return candidates

    def _probe_single_url(
        self,
        url: str,
        ctx: ssl.SSLContext,
        timeout: float,
    ) -> tuple[bool, str | None, list[dict], list[dict], list[dict], float]:
        start_time = time.perf_counter()
        tools_list: list[dict] = []
        prompts_list: list[dict] = []
        resources_list: list[dict] = []

        # 1. Try JSON-RPC POST for tools/list first
        post_data = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        ).encode("utf-8")
        req_post = urllib.request.Request(
            url,
            data=post_data,
            headers={
                "User-Agent": "VerityDiscovery/1.0",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )

        try:
            with urllib.request.urlopen(req_post, context=ctx, timeout=timeout) as resp:
                elapsed = (time.perf_counter() - start_time) * 1000.0
                body = resp.read().decode("utf-8", errors="replace")
                try:
                    data = json.loads(body)
                    if isinstance(data, dict):
                        res_obj = data.get("result", data)
                        if isinstance(res_obj, dict):
                            tools_list = res_obj.get("tools", [])
                            prompts_list = res_obj.get("prompts", [])
                            resources_list = res_obj.get("resources", [])
                except Exception:
                    pass

        except Exception:
            pass

        # 2. Fallback to GET probe
        req_get = urllib.request.Request(
            url,
            headers={
                "User-Agent": "VerityDiscovery/1.0",
                "Accept": "application/json, text/event-stream",
            },
        )
        try:
            with urllib.request.urlopen(req_get, context=ctx, timeout=timeout) as resp:
                elapsed = (time.perf_counter() - start_time) * 1000.0
                body = resp.read().decode("utf-8", errors="replace")
                try:
                    data = json.loads(body)
                    if isinstance(data, dict):
                        res_obj = data.get("result", data)
                        if isinstance(res_obj, dict):
                            tools_list = res_obj.get("tools", [])
                            prompts_list = res_obj.get("prompts", [])
                            resources_list = res_obj.get("resources", [])
                except Exception:
                    pass

                return (resp.status == 200), None, tools_list, prompts_list, resources_list, elapsed
        except Exception as get_exc:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return False, str(get_exc), [], [], [], elapsed

    def inspect(self, config: DiscoveredServerConfig) -> LiveServerCapability:
        """Probe remote endpoint for standard MCP capability declarations with loopback fallback."""
        if not config.url:
            return LiveServerCapability(
                server_name=config.server_name,
                is_responsive=False,
                error_message="Missing endpoint URL in configuration",
            )

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        protocol_version = "2024-11-05"

        candidate_urls = self._get_candidate_urls(config.url)
        last_error = "Unknown error"
        total_elapsed = 0.0

        for probe_url in candidate_urls:
            is_ok, err_msg, tools, prompts, resources, elapsed = self._probe_single_url(
                probe_url, ctx, self.timeout_seconds
            )
            total_elapsed += elapsed
            if is_ok:
                with contextlib.suppress(Exception):
                    object.__setattr__(config, "url", probe_url)
                return LiveServerCapability(
                    server_name=config.server_name,
                    protocol_version=protocol_version,
                    tools=tuple(tools),
                    prompts=tuple(prompts),
                    resources=tuple(resources),
                    is_responsive=True,
                    response_time_ms=elapsed,
                )
            last_error = err_msg or last_error
            # Only try next candidate URL if connection was refused or cannot connect
            err_lower = last_error.lower()
            if not any(k in err_lower for k in ("111", "refused", "nodename", "cannot connect")):
                break

        return LiveServerCapability(
            server_name=config.server_name,
            is_responsive=False,
            error_message=last_error,
            response_time_ms=total_elapsed,
        )

