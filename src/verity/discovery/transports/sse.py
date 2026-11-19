"""Read-only Http / SSE transport for remote MCP server discovery."""

from __future__ import annotations

import contextlib
import http.client
import json
import logging
import ssl
import time
import urllib.parse
from collections.abc import Iterator

from verity.discovery.models import DiscoveredServerConfig, LiveServerCapability
from verity.discovery.transports.base import BaseDiscoveryTransport

logger = logging.getLogger("verity.discovery.transports.sse")

_DEFAULT_PROTOCOL_VERSION = "2024-11-05"
_MAX_BODY_BYTES = 4 * 1024 * 1024
_MAX_LINE_BUFFER_BYTES = 1024 * 1024


class _DeadlineLineReader:
    """Incremental line reader for a streaming HTTP response, bounded by a wall-clock deadline."""

    def __init__(
        self,
        resp: http.client.HTTPResponse,
        conn: http.client.HTTPConnection,
        deadline: float,
    ) -> None:
        self._resp = resp
        self._conn = conn
        self._deadline = deadline
        self._buf = b""
        self._eof = False

    def readline(self) -> bytes | None:
        while True:
            idx = self._buf.find(b"\n")
            if idx >= 0:
                line = self._buf[: idx + 1]
                self._buf = self._buf[idx + 1 :]
                return line
            if self._eof:
                if self._buf:
                    line = self._buf
                    self._buf = b""
                    return line
                return None
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock = getattr(self._conn, "sock", None)
            if sock is not None:
                with contextlib.suppress(OSError):
                    sock.settimeout(max(0.05, remaining))
            try:
                chunk = self._resp.read1(4096)
            except Exception:
                return None
            if not chunk:
                self._eof = True
                continue
            self._buf += chunk
            if len(self._buf) > _MAX_LINE_BUFFER_BYTES:
                return None


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

    @staticmethod
    def _remaining_timeout(timeout: float, deadline: float) -> float | None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        return max(0.1, min(timeout, remaining))

    @staticmethod
    def _connect(url: str, ctx: ssl.SSLContext, timeout: float) -> http.client.HTTPConnection:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname or "127.0.0.1"
        if parts.scheme == "https":
            return http.client.HTTPSConnection(
                host, parts.port or 443, timeout=timeout, context=ctx
            )
        return http.client.HTTPConnection(host, parts.port or 80, timeout=timeout)

    @staticmethod
    def _request_path(url: str) -> str:
        parts = urllib.parse.urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        return path

    @staticmethod
    def _content_type(resp: http.client.HTTPResponse) -> str:
        raw = resp.getheader("Content-Type") or ""
        return raw.split(";", 1)[0].strip().lower()

    def _read_body(
        self,
        resp: http.client.HTTPResponse,
        conn: http.client.HTTPConnection,
        deadline: float,
    ) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while total < _MAX_BODY_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock = getattr(conn, "sock", None)
            if sock is not None:
                with contextlib.suppress(OSError):
                    sock.settimeout(max(0.05, remaining))
            try:
                chunk = resp.read(8192)
            except Exception:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    def _iter_sse_frames(
        self,
        resp: http.client.HTTPResponse,
        conn: http.client.HTTPConnection,
        deadline: float,
        reader: _DeadlineLineReader | None = None,
    ) -> Iterator[tuple[str, str]]:
        reader = reader or _DeadlineLineReader(resp, conn, deadline)
        event_name: str | None = None
        data_lines: list[str] = []
        while True:
            raw = reader.readline()
            if raw is None:
                if data_lines:
                    yield event_name or "message", "\n".join(data_lines)
                return
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if line == "":
                if data_lines:
                    yield event_name or "message", "\n".join(data_lines)
                event_name = None
                data_lines = []
                continue
            if line.startswith(":"):
                continue
            if line.startswith("event:"):
                event_name = line[len("event:") :].strip()
            elif line.startswith("data:"):
                value = line[len("data:") :]
                if value.startswith(" "):
                    value = value[1:]
                data_lines.append(value)
            # Ignore id:, retry: and other SSE fields.

    @staticmethod
    def _extract_capabilities(
        data: object,
    ) -> tuple[list[dict], list[dict], list[dict]]:
        if not isinstance(data, dict):
            return [], [], []
        if isinstance(data.get("result"), dict):
            obj: object = data["result"]
        elif "error" in data and not any(k in data for k in ("tools", "prompts", "resources")):
            return [], [], []
        else:
            obj = data
        if not isinstance(obj, dict):
            return [], [], []
        tools = list(obj.get("tools") or [])
        prompts = list(obj.get("prompts") or [])
        resources = list(obj.get("resources") or [])
        return tools, prompts, resources

    def _streamable_initialize(
        self,
        url: str,
        ctx: ssl.SSLContext,
        timeout: float,
        deadline: float,
    ) -> tuple[object, str | None, str | None]:
        conn_timeout = self._remaining_timeout(timeout, deadline)
        if conn_timeout is None:
            return None, None, "deadline exceeded"
        conn = self._connect(url, ctx, conn_timeout)
        try:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": _DEFAULT_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "VerityDiscovery", "version": "1.0"},
                },
            }
            headers = {
                "User-Agent": "VerityDiscovery/1.0",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            }
            try:
                conn.request(
                    "POST",
                    self._request_path(url),
                    body=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                )
                resp = conn.getresponse()
            except Exception as exc:
                return None, None, str(exc)
            if resp.status >= 400:
                return None, resp.getheader("Mcp-Session-Id"), f"HTTP {resp.status}"
            session_id = resp.getheader("Mcp-Session-Id")
            ctype = self._content_type(resp)
            if ctype == "text/event-stream":
                for event, data in self._iter_sse_frames(resp, conn, deadline):
                    if event == "endpoint":
                        return None, session_id, "endpoint event on POST"
                    try:
                        parsed = json.loads(data)
                    except Exception:
                        continue
                    if isinstance(parsed, dict) and parsed.get("id") == 1:
                        return parsed, session_id, None
                return None, session_id, "no initialize response"
            if "json" in ctype or ctype == "":
                raw = self._read_body(resp, conn, deadline)
                try:
                    parsed = json.loads(raw.decode("utf-8", errors="replace"))
                except Exception:
                    return None, session_id, "invalid json response"
                return parsed, session_id, None
            return None, session_id, f"unexpected content-type {ctype!r}"
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    def _post_jsonrpc(
        self,
        url: str,
        ctx: ssl.SSLContext,
        timeout: float,
        deadline: float,
        session_id: str | None,
        payload: dict,
    ) -> dict | None:
        conn_timeout = self._remaining_timeout(timeout, deadline)
        if conn_timeout is None:
            return None
        conn = self._connect(url, ctx, conn_timeout)
        try:
            headers = {
                "User-Agent": "VerityDiscovery/1.0",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            }
            if session_id:
                headers["Mcp-Session-Id"] = session_id
            try:
                conn.request(
                    "POST",
                    self._request_path(url),
                    body=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                )
                resp = conn.getresponse()
            except Exception:
                return None
            if resp.status >= 400:
                return None
            ctype = self._content_type(resp)
            target_id = payload.get("id")
            if ctype == "text/event-stream":
                if target_id is None:
                    return None
                for _event, data in self._iter_sse_frames(resp, conn, deadline):
                    try:
                        parsed = json.loads(data)
                    except Exception:
                        continue
                    if isinstance(parsed, dict) and parsed.get("id") == target_id:
                        if isinstance(parsed.get("result"), dict):
                            return parsed["result"]
                        return parsed
                return None
            if "json" in ctype or ctype == "":
                raw = self._read_body(resp, conn, deadline)
                if not raw:
                    return None
                try:
                    parsed = json.loads(raw.decode("utf-8", errors="replace"))
                except Exception:
                    return None
                if not isinstance(parsed, dict):
                    return None
                if "error" in parsed:
                    return None
                if isinstance(parsed.get("result"), dict):
                    return parsed["result"]
                if any(k in parsed for k in ("tools", "prompts", "resources")):
                    return parsed
                return None
            return None
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    @staticmethod
    def _advertised_capabilities(init_data: object) -> dict | None:
        if not isinstance(init_data, dict):
            return None
        obj = init_data.get("result") if isinstance(init_data.get("result"), dict) else init_data
        caps = obj.get("capabilities") if isinstance(obj, dict) else None
        return caps if isinstance(caps, dict) else None

    def _try_streamable_http(
        self,
        url: str,
        ctx: ssl.SSLContext,
        timeout: float,
        deadline: float,
    ) -> tuple[list[dict], list[dict], list[dict], bool, str | None]:
        init_data, session_id, err = self._streamable_initialize(url, ctx, timeout, deadline)
        if err is not None:
            return [], [], [], False, err
        tools, prompts, resources = self._extract_capabilities(init_data)
        if isinstance(init_data, dict) and "error" in init_data and not (
            tools or prompts or resources
        ):
            return [], [], [], False, f"initialize error: {init_data.get('error')}"
        if tools or prompts or resources:
            return tools, prompts, resources, True, None

        self._post_jsonrpc(
            url,
            ctx,
            timeout,
            deadline,
            session_id,
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )
        tools_result = self._post_jsonrpc(
            url,
            ctx,
            timeout,
            deadline,
            session_id,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        if isinstance(tools_result, dict):
            tools = list(tools_result.get("tools") or [])
            prompts = list(tools_result.get("prompts") or prompts)
            resources = list(tools_result.get("resources") or resources)
        caps = self._advertised_capabilities(init_data)
        probe_prompts = not caps or "prompts" in caps
        probe_resources = not caps or "resources" in caps
        if not prompts and probe_prompts:
            result = self._post_jsonrpc(
                url,
                ctx,
                timeout,
                deadline,
                session_id,
                {"jsonrpc": "2.0", "id": 3, "method": "prompts/list", "params": {}},
            )
            if isinstance(result, dict):
                prompts = list(result.get("prompts") or [])
        if not resources and probe_resources:
            result = self._post_jsonrpc(
                url,
                ctx,
                timeout,
                deadline,
                session_id,
                {"jsonrpc": "2.0", "id": 4, "method": "resources/list", "params": {}},
            )
            if isinstance(result, dict):
                resources = list(result.get("resources") or [])
        return tools, prompts, resources, True, None

    def _finite_probe(
        self,
        url: str,
        ctx: ssl.SSLContext,
        timeout: float,
        deadline: float,
        method: str,
    ) -> tuple[list[dict], list[dict], list[dict], bool]:
        conn_timeout = self._remaining_timeout(timeout, deadline)
        if conn_timeout is None:
            return [], [], [], False
        conn = self._connect(url, ctx, conn_timeout)
        try:
            headers = {
                "User-Agent": "VerityDiscovery/1.0",
                "Accept": "application/json, text/event-stream",
            }
            body: bytes | None = None
            if method == "POST":
                headers["Content-Type"] = "application/json"
                body = json.dumps(
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
                ).encode("utf-8")
            try:
                conn.request(method, self._request_path(url), body=body, headers=headers)
                resp = conn.getresponse()
            except Exception:
                return [], [], [], False
            if resp.status >= 400:
                return [], [], [], False
            ctype = self._content_type(resp)
            if ctype == "text/event-stream":
                # A streaming server; leave it to the dedicated streaming paths.
                return [], [], [], False
            if "json" not in ctype and ctype != "":
                return [], [], [], False
            raw = self._read_body(resp, conn, deadline)
            try:
                parsed = json.loads(raw.decode("utf-8", errors="replace"))
            except Exception:
                return [], [], [], False
            tools, prompts, resources = self._extract_capabilities(parsed)
            if tools or prompts or resources:
                return tools, prompts, resources, True
            if isinstance(parsed, dict) and "error" not in parsed:
                return [], [], [], True
            return [], [], [], False
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    def _try_finite_json(
        self,
        url: str,
        ctx: ssl.SSLContext,
        timeout: float,
        deadline: float,
    ) -> tuple[list[dict], list[dict], list[dict], bool, str | None]:
        tools, prompts, resources, ok = self._finite_probe(url, ctx, timeout, deadline, "POST")
        if ok and (tools or prompts or resources):
            return tools, prompts, resources, True, None
        tools, prompts, resources, ok = self._finite_probe(url, ctx, timeout, deadline, "GET")
        if ok and (tools or prompts or resources):
            return tools, prompts, resources, True, None
        return [], [], [], False, "no finite JSON capabilities"

    def _wait_for_rpc_id(
        self,
        frames: Iterator[tuple[str, str]],
        target_id: int,
    ) -> dict | None:
        for _event, data in frames:
            try:
                parsed = json.loads(data)
            except Exception:
                continue
            if isinstance(parsed, dict) and parsed.get("id") == target_id:
                if isinstance(parsed.get("result"), dict):
                    return parsed["result"]
                return parsed
        return None

    def _post_to_endpoint(
        self,
        endpoint_url: str,
        ctx: ssl.SSLContext,
        timeout: float,
        deadline: float,
        payload: dict,
    ) -> dict | None:
        conn_timeout = self._remaining_timeout(timeout, deadline)
        if conn_timeout is None:
            return None
        conn = self._connect(endpoint_url, ctx, conn_timeout)
        try:
            headers = {
                "User-Agent": "VerityDiscovery/1.0",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            }
            try:
                conn.request(
                    "POST",
                    self._request_path(endpoint_url),
                    body=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                )
                resp = conn.getresponse()
            except Exception:
                return None
            if resp.status >= 400:
                return None
            ctype = self._content_type(resp)
            target_id = payload.get("id")
            if ctype == "text/event-stream":
                if target_id is None:
                    return None
                for _event, data in self._iter_sse_frames(resp, conn, deadline):
                    try:
                        parsed = json.loads(data)
                    except Exception:
                        continue
                    if isinstance(parsed, dict) and parsed.get("id") == target_id:
                        if isinstance(parsed.get("result"), dict):
                            return parsed["result"]
                        return parsed
                return None
            if "json" in ctype or ctype == "":
                raw = self._read_body(resp, conn, deadline)
                if not raw:
                    return None
                try:
                    parsed = json.loads(raw.decode("utf-8", errors="replace"))
                except Exception:
                    return None
                if not isinstance(parsed, dict):
                    return None
                if "error" in parsed:
                    return None
                if isinstance(parsed.get("result"), dict):
                    return parsed["result"]
                if any(k in parsed for k in ("tools", "prompts", "resources")):
                    return parsed
                return None
            return None
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    def _try_legacy_sse(
        self,
        url: str,
        ctx: ssl.SSLContext,
        timeout: float,
        deadline: float,
    ) -> tuple[list[dict], list[dict], list[dict], bool, str | None]:
        conn_timeout = self._remaining_timeout(timeout, deadline)
        if conn_timeout is None:
            return [], [], [], False, "deadline exceeded"
        conn = self._connect(url, ctx, conn_timeout)
        try:
            headers = {
                "User-Agent": "VerityDiscovery/1.0",
                "Accept": "text/event-stream, application/json",
            }
            try:
                conn.request("GET", self._request_path(url), headers=headers)
                resp = conn.getresponse()
            except Exception as exc:
                return [], [], [], False, str(exc)
            if resp.status >= 400:
                return [], [], [], False, f"HTTP {resp.status}"
            ctype = self._content_type(resp)
            if ctype != "text/event-stream":
                if "json" in ctype or ctype == "":
                    raw = self._read_body(resp, conn, deadline)
                    try:
                        parsed = json.loads(raw.decode("utf-8", errors="replace"))
                    except Exception:
                        return [], [], [], False, "invalid json"
                    tools, prompts, resources = self._extract_capabilities(parsed)
                    return tools, prompts, resources, True, None
                return [], [], [], False, f"unexpected content-type {ctype!r}"

            reader = _DeadlineLineReader(resp, conn, deadline)
            frames = self._iter_sse_frames(resp, conn, deadline, reader=reader)
            endpoint_url: str | None = None
            for event, data in frames:
                if event == "endpoint":
                    endpoint_url = urllib.parse.urljoin(url, data.strip())
                    break
                try:
                    parsed = json.loads(data)
                except Exception:
                    continue
                if isinstance(parsed, dict):
                    tools, prompts, resources = self._extract_capabilities(parsed)
                    if (
                        tools
                        or prompts
                        or resources
                        or parsed.get("result")
                        or parsed.get("error")
                    ):
                        return tools, prompts, resources, True, None
            if endpoint_url is None:
                return [], [], [], False, "no endpoint event"

            init_result = self._post_to_endpoint(
                endpoint_url,
                ctx,
                timeout,
                deadline,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": _DEFAULT_PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "VerityDiscovery", "version": "1.0"},
                    },
                },
            )
            if init_result is None:
                init_result = self._wait_for_rpc_id(frames, 1)
            init_tools, init_prompts, init_resources = self._extract_capabilities(init_result)
            if init_tools or init_prompts or init_resources:
                return init_tools, init_prompts, init_resources, True, None

            self._post_to_endpoint(
                endpoint_url,
                ctx,
                timeout,
                deadline,
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            )

            tools: list[dict] = []
            prompts: list[dict] = []
            resources: list[dict] = []
            tools_result = self._post_to_endpoint(
                endpoint_url,
                ctx,
                timeout,
                deadline,
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )
            if tools_result is None:
                tools_result = self._wait_for_rpc_id(frames, 2)
            if isinstance(tools_result, dict):
                tools = list(tools_result.get("tools") or [])
                prompts = list(tools_result.get("prompts") or prompts)
                resources = list(tools_result.get("resources") or resources)

            caps = self._advertised_capabilities(init_result)
            probe_prompts = not caps or "prompts" in caps
            probe_resources = not caps or "resources" in caps
            if not prompts and probe_prompts:
                result = self._post_to_endpoint(
                    endpoint_url,
                    ctx,
                    timeout,
                    deadline,
                    {"jsonrpc": "2.0", "id": 3, "method": "prompts/list", "params": {}},
                )
                if result is None:
                    reader._deadline = min(deadline, time.monotonic() + 0.25)
                    result = self._wait_for_rpc_id(frames, 3)
                    reader._deadline = deadline
                if isinstance(result, dict):
                    prompts = list(result.get("prompts") or [])
            if not resources and probe_resources:
                result = self._post_to_endpoint(
                    endpoint_url,
                    ctx,
                    timeout,
                    deadline,
                    {"jsonrpc": "2.0", "id": 4, "method": "resources/list", "params": {}},
                )
                if result is None:
                    reader._deadline = min(deadline, time.monotonic() + 0.25)
                    result = self._wait_for_rpc_id(frames, 4)
                    reader._deadline = deadline
                if isinstance(result, dict):
                    resources = list(result.get("resources") or [])

            if tools or prompts or resources:
                return tools, prompts, resources, True, None
            return [], [], [], True, None
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    def _probe_single_url(
        self,
        url: str,
        ctx: ssl.SSLContext,
        timeout: float,
    ) -> tuple[bool, str | None, list[dict], list[dict], list[dict], float]:
        start_time = time.monotonic()
        deadline = start_time + timeout

        tools, prompts, resources, ok, err = self._try_streamable_http(
            url, ctx, timeout, deadline
        )
        if ok and (tools or prompts or resources):
            elapsed = (time.monotonic() - start_time) * 1000.0
            return True, None, tools, prompts, resources, elapsed

        tools2, prompts2, resources2, ok2, err2 = self._try_finite_json(
            url, ctx, timeout, deadline
        )
        if ok2 and (tools2 or prompts2 or resources2):
            elapsed = (time.monotonic() - start_time) * 1000.0
            return True, None, tools2, prompts2, resources2, elapsed

        tools3, prompts3, resources3, ok3, err3 = self._try_legacy_sse(
            url, ctx, timeout, deadline
        )
        if ok3 and (tools3 or prompts3 or resources3):
            elapsed = (time.monotonic() - start_time) * 1000.0
            return True, None, tools3, prompts3, resources3, elapsed

        if ok and err is None:
            elapsed = (time.monotonic() - start_time) * 1000.0
            return True, None, tools, prompts, resources, elapsed
        if ok2 and err2 is None:
            elapsed = (time.monotonic() - start_time) * 1000.0
            return True, None, tools2, prompts2, resources2, elapsed
        if ok3 and err3 is None:
            elapsed = (time.monotonic() - start_time) * 1000.0
            return True, None, tools3, prompts3, resources3, elapsed

        elapsed = (time.monotonic() - start_time) * 1000.0
        return (
            False,
            err3 or err2 or err or "No MCP capabilities discovered",
            [],
            [],
            [],
            elapsed,
        )

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

