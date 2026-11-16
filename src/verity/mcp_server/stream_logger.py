"""Shared stream and demo logging utilities for the Verity MCP server."""

from __future__ import annotations

import datetime
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("verity.mcp_server.stream_logger")

_REPO_ROOT = (
    Path.cwd()
    if (Path.cwd() / "artifacts").exists()
    else Path(__file__).resolve().parent.parent.parent.parent
)


def _truncate_json(payload: Any, max_len: int) -> str:
    """Serialize payload to compact JSON and truncate to max_len characters."""
    text = json.dumps(payload, separators=(",", ": "), default=str)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def _format_tool_summary(tool_name: str, args: dict[str, Any], res: dict[str, Any]) -> str:
    """Format a concise one-line status summary for an MCP tool invocation."""
    if tool_name == "verity_database_guard":
        default_verdict = "BLOCKED" if "verdict" in res else "ALLOWED"
        return f"Verdict={res.get('verdict', default_verdict)}"
    if tool_name == "verity_database_oracle":
        return f"Proof={res.get('status', 'SUCCESS')}"
    if res.get("ok") is False:
        err = res.get("error") or res.get("verdict") or "Failed"
        return f"ERROR: {err}"
    if tool_name == "verity_security_scan":
        action = args.get("action")
        if action == "full_audit":
            target = res.get("target", "unknown")
            is_vuln = "VULNERABLE" if res.get("is_vulnerable") else "CLEAN"
            cnt = res.get("findings_count", 0)
            return f"Target={target} Status={is_vuln} ({cnt} findings)"
        if action == "fingerprint_server":
            return f"Matched {res.get('package_name')}@{res.get('version')}"
        return "Success"
    return "OK"


def log_tool_event(tool_name: str, args: dict[str, Any], res: dict[str, Any]) -> None:
    """Write human-readable tool invocation event lines to demo.log and mcp_stream.log."""
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        action = args.get("action")
        action_str = f"({action})" if action else ""
        summary = _format_tool_summary(tool_name, args, res)

        lines = [
            f"[{ts}] ⚡ Tool: {tool_name}{action_str} -> {summary}\n",
            f"[{ts}]   📥 Request:  {_truncate_json(args, 140)}\n",
            f"[{ts}]   📤 Response: {_truncate_json(res, 180)}\n",
        ]

        env_stream = os.environ.get("VERITY_STREAM_LOG_PATH")
        dest_paths = [
            _REPO_ROOT / "artifacts" / "demo.log",
            Path(env_stream) if env_stream else _REPO_ROOT / "artifacts" / "mcp_stream.log",
        ]
        for log_file in dest_paths:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            with open(log_file, "a", encoding="utf-8") as fh:
                fh.writelines(lines)
    except Exception as exc:
        logger.debug("Failed to write tool event log: %s", exc)


def append_tool_call_log(tool_name: str, args: dict[str, Any], result: dict[str, Any] | None) -> None:
    """Append one structured JSON-line record of a tool/call invocation to VERITY_STREAM_LOG_PATH if set."""
    log_path = os.environ.get("VERITY_STREAM_LOG_PATH", "")
    if not log_path:
        return
    try:
        record: dict[str, Any] = {
            "ts": datetime.datetime.now(datetime.UTC).isoformat(),
            "tool": tool_name,
            "args_keys": sorted(args.keys()) if isinstance(args, dict) else [],
            "ok": not (isinstance(result, dict) and (result.get("ok") is False or "error" in result)),
        }
        if isinstance(args, dict):
            if "action" in args:
                record["action"] = args["action"]
            if "options" in args and isinstance(args["options"], dict):
                record["options"] = args["options"]
        if isinstance(result, dict):
            for key in ("verdict", "violations", "status", "affected_rows"):
                if key in result:
                    record[key] = result[key]

        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception as exc:
        logger.debug("Failed to append structured tool call log: %s", exc)
