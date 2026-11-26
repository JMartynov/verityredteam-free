"""Multi-client static configuration parser and secret detector for MCP clients."""

from __future__ import annotations

import json
import logging
import os
import platform
import re
from pathlib import Path
from typing import Any

import yaml

from verity.discovery.models import ClientType, DiscoveredServerConfig, TransportType
from verity.scanner.credential_patterns import (
    CREDENTIAL_VALUE_PATTERNS,
    is_placeholder_value,
)

logger = logging.getLogger("verity.discovery.config_scanner")


def strip_jsonc_comments(text: str) -> str:
    """Strip ``//`` line comments, ``/* */`` block comments, and trailing commas.

    String state is tracked so URLs containing ``//`` and block-comment tokens
    inside string literals are preserved verbatim. Trailing commas are removed
    only when they precede a ``}`` or ``]`` outside a string.
    """
    if not text:
        return text

    result: list[str] = []
    n = len(text)
    i = 0
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            result.append(ch)
            if ch == "\\" and i + 1 < n:
                result.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            result.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                while i < n and text[i] != "\n":
                    i += 1
                continue
            if nxt == "*":
                i += 2
                while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                i = min(i + 2, n)
                continue
        result.append(ch)
        i += 1

    cleaned = "".join(result)

    # Second pass: strip trailing commas only outside strings.
    out: list[str] = []
    i = 0
    m = len(cleaned)
    in_string = False
    while i < m:
        ch = cleaned[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < m:
                out.append(cleaned[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == ",":
            j = i + 1
            while j < m and cleaned[j] in " \t\r\n":
                j += 1
            if j < m and cleaned[j] in "}]":
                i += 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


class MultiClientConfigScanner:
    """Discovers, parses, and normalizes MCP client configurations across all supported tools."""

    SECRET_KEY_PATTERNS = re.compile(
        r"(api[_-]?key|secret|token|password|bearer|auth|jwt|private[_-]?key"
        r"|access[_-]?key|aws_secret|credentials?|client[_-]?secret)",
        re.IGNORECASE,
    )
    SECRET_VALUE_PATTERNS = re.compile(
        "|".join(pattern.pattern for pattern in CREDENTIAL_VALUE_PATTERNS)
    )
    DSN_CREDENTIAL_PATTERN = re.compile(
        r"(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqps?|mssql|"
        r"snowflake|https?)://[^/\s:@]+:([^/\s@]+)@",
        re.IGNORECASE,
    )

    @classmethod
    def is_secret_env_entry(cls, key: str, raw_value: Any) -> bool:
        """Return True when an env entry holds a plaintext secret or credential DSN."""
        text = str(raw_value).strip() if raw_value is not None else ""
        if not text or text.startswith("${") or text.startswith("$"):
            return False
        if is_placeholder_value(text):
            return False
        if cls.SECRET_KEY_PATTERNS.search(str(key)):
            return True
        if any(pattern.search(text) for pattern in CREDENTIAL_VALUE_PATTERNS):
            return True
        dsn_match = cls.DSN_CREDENTIAL_PATTERN.search(text)
        if dsn_match:
            pwd = dsn_match.group(1)
            if pwd and not pwd.startswith("${") and not pwd.startswith("$"):
                return True
        return False

    @classmethod
    def get_standard_client_paths(
        cls,
        base_home: str | Path | None = None,
        sandbox_root: str | Path | None = None,
    ) -> dict[ClientType, list[Path]]:
        """Resolve standard configuration paths, isolated to sandbox_root if specified."""
        if sandbox_root:
            root = Path(sandbox_root)
            home = root / "home"
            cwd = root / "workspace"
        else:
            home = Path(base_home) if base_home else Path.home()
            cwd = Path.cwd()

        system = "Linux" if sandbox_root else platform.system()

        paths: dict[ClientType, list[Path]] = {
            ClientType.CLAUDE_DESKTOP: [],
            ClientType.CLAUDE_CODE: [],
            ClientType.CURSOR: [],
            ClientType.VSCODE_CLINE: [],
            ClientType.VSCODE_ROO: [],
            ClientType.GOOSE: [],
            ClientType.CONTINUE: [],
            ClientType.WINDSURF: [],
            ClientType.ZED: [],
            ClientType.VSCODE: [],
            ClientType.JUNIE: [],
            ClientType.ANTIGRAVITY: [],
            ClientType.OPENHANDS: [],
            ClientType.TRAE: [],
            ClientType.LMSTUDIO: [],
            ClientType.LIBRECHAT: [],
            ClientType.WORKSPACE: [],
        }

        # 1. Claude Desktop
        if system == "Darwin":
            paths[ClientType.CLAUDE_DESKTOP].append(
                home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
            )
        elif system == "Windows":
            appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
            paths[ClientType.CLAUDE_DESKTOP].append(
                appdata / "Claude" / "claude_desktop_config.json"
            )
        else:
            paths[ClientType.CLAUDE_DESKTOP].append(
                home / ".config" / "Claude" / "claude_desktop_config.json"
            )

        # 2. Cursor
        paths[ClientType.CURSOR].append(home / ".cursor" / "mcp.json")
        if system == "Darwin":
            paths[ClientType.CURSOR].append(
                home
                / "Library"
                / "Application Support"
                / "Cursor"
                / "User"
                / "globalStorage"
                / "mcp.json"
            )

        # 3. VS Code (Cline & Roo Code)
        if system == "Darwin":
            paths[ClientType.VSCODE_CLINE].append(
                home
                / "Library"
                / "Application Support"
                / "Code"
                / "User"
                / "globalStorage"
                / "saoudrizwan.claude-dev"
                / "settings"
                / "cline_mcp_settings.json"
            )
            paths[ClientType.VSCODE_ROO].append(
                home
                / "Library"
                / "Application Support"
                / "Code"
                / "User"
                / "globalStorage"
                / "rooveterinaryinc.roo-cline"
                / "settings"
                / "cline_mcp_settings.json"
            )
        elif system == "Windows":
            appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
            paths[ClientType.VSCODE_CLINE].append(
                appdata
                / "Code"
                / "User"
                / "globalStorage"
                / "saoudrizwan.claude-dev"
                / "settings"
                / "cline_mcp_settings.json"
            )
            paths[ClientType.VSCODE_ROO].append(
                appdata
                / "Code"
                / "User"
                / "globalStorage"
                / "rooveterinaryinc.roo-cline"
                / "settings"
                / "cline_mcp_settings.json"
            )
        else:
            paths[ClientType.VSCODE_CLINE].append(
                home
                / ".config"
                / "Code"
                / "User"
                / "globalStorage"
                / "saoudrizwan.claude-dev"
                / "settings"
                / "cline_mcp_settings.json"
            )
            paths[ClientType.VSCODE_ROO].append(
                home
                / ".config"
                / "Code"
                / "User"
                / "globalStorage"
                / "rooveterinaryinc.roo-cline"
                / "settings"
                / "cline_mcp_settings.json"
            )

        # 4. Continue.dev
        paths[ClientType.CONTINUE].append(home / ".continue" / "config.json")
        paths[ClientType.CONTINUE].append(home / ".continue" / "config.yaml")

        # 5. Windsurf
        paths[ClientType.WINDSURF].append(home / ".codeium" / "windsurf" / "mcp_config.json")

        # 6. Zed
        paths[ClientType.ZED].append(home / ".config" / "zed" / "settings.json")

        # 7. LibreChat
        paths[ClientType.LIBRECHAT].append(home / ".librechat" / "librechat.yaml")
        paths[ClientType.LIBRECHAT].append(cwd / "librechat.yaml")

        # 8. Workspace auto-detection
        paths[ClientType.WORKSPACE].extend(
            [
                cwd / ".cursor" / "mcp.json",
                cwd / ".vscode" / "mcp.json",
                cwd / "claude.json",
                cwd / "mcp.json",
            ]
        )

        # 9. Claude Code (per-user + project-local)
        paths[ClientType.CLAUDE_CODE].append(home / ".claude.json")
        paths[ClientType.CLAUDE_CODE].append(cwd / ".mcp.json")

        # 10. Goose (block-style YAML with `extensions`)
        paths[ClientType.GOOSE].append(home / ".config" / "goose" / "config.yaml")
        paths[ClientType.GOOSE].append(home / ".config" / "goose" / "config.yml")

        # 11. Junie (JetBrains project-level)
        paths[ClientType.JUNIE].append(cwd / ".idea" / "mcp.json")

        # 12. GitHub Copilot (VS Code globalStorage)
        if system == "Darwin":
            paths[ClientType.VSCODE].append(
                home
                / "Library"
                / "Application Support"
                / "Code"
                / "User"
                / "globalStorage"
                / "github.copilot"
                / "mcp.json"
            )
        elif system == "Windows":
            appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
            paths[ClientType.VSCODE].append(
                appdata / "Code" / "User" / "globalStorage" / "github.copilot" / "mcp.json"
            )
        else:
            paths[ClientType.VSCODE].append(
                home
                / ".config"
                / "Code"
                / "User"
                / "globalStorage"
                / "github.copilot"
                / "mcp.json"
            )

        # 13. Antigravity (Gemini)
        paths[ClientType.ANTIGRAVITY].append(home / ".gemini" / "config" / "mcp_config.json")

        # 14. OpenHands
        paths[ClientType.OPENHANDS].append(home / ".openhands" / "mcp.json")

        # 15. Trae
        paths[ClientType.TRAE].append(home / ".trae" / "mcp.json")

        # 16. LM Studio
        paths[ClientType.LMSTUDIO].append(home / ".lmstudio" / "mcp.json")

        return paths

    @classmethod
    def expand_env_vars(cls, val: str, env_override: dict[str, str] | None = None) -> str:
        """Safely expand environment variables ${VAR} or $VAR."""
        env_map = {**os.environ, **(env_override or {})}

        def replace_match(match: re.Match[str]) -> str:
            var_name = match.group(1) or match.group(2)
            return env_map.get(var_name, f"${{{var_name}}}")

        return re.sub(r"\$\{([a-zA-Z0-9_]+)\}|\$([a-zA-Z0-9_]+)", replace_match, val)

    @classmethod
    def _parse_file_data(cls, file_path: Path) -> object:
        """Parse JSON/JSONC/YAML config file contents with JSONC normalization."""
        content = file_path.read_text(encoding="utf-8")
        if file_path.suffix.lower() in (".yaml", ".yml"):
            return yaml.safe_load(content)
        cleaned = strip_jsonc_comments(content)
        return json.loads(cleaned)

    @classmethod
    def _collect_specs(cls, value: object, pairs: list[tuple[str, dict]]) -> None:
        if isinstance(value, dict):
            for name, spec in value.items():
                if isinstance(spec, dict):
                    pairs.append((str(name), spec))
        elif isinstance(value, list):
            for idx, spec in enumerate(value):
                if isinstance(spec, dict):
                    name = str(spec.get("name") or f"server-{idx}")
                    pairs.append((name, spec))

    @classmethod
    def _extract_server_specs(cls, data: object) -> list[tuple[str, dict]]:
        """Extract (server_name, spec) pairs from a parsed MCP config document."""
        if not isinstance(data, dict):
            return []

        pairs: list[tuple[str, dict]] = []
        for key in ("mcpServers", "mcp_servers", "servers", "context_servers", "extensions"):
            cls._collect_specs(data.get(key), pairs)

        experimental = data.get("experimental")
        if isinstance(experimental, dict):
            cls._collect_specs(experimental.get("modelContextProtocolServers"), pairs)

        projects = data.get("projects")
        if isinstance(projects, dict):
            for project_value in projects.values():
                if isinstance(project_value, dict):
                    cls._collect_specs(project_value.get("mcpServers"), pairs)

        if not pairs and "command" not in data:
            for name, spec in data.items():
                if isinstance(spec, dict) and any(
                    k in spec for k in ("command", "cmd", "url", "uri")
                ):
                    pairs.append((str(name), spec))

        return pairs

    @classmethod
    def parse_config_file(
        cls,
        path: str | Path,
        client_type: ClientType = ClientType.CUSTOM,
    ) -> list[DiscoveredServerConfig]:
        """Parse an MCP configuration file and extract all declared server configurations."""
        file_path = Path(path)
        if not file_path.is_file():
            return []

        try:
            data = cls._parse_file_data(file_path)
        except Exception as exc:
            logger.debug("Failed parsing config %s: %s", file_path, exc)
            return []

        discovered: list[DiscoveredServerConfig] = []

        for name, spec in cls._extract_server_specs(data):
            command = spec.get("command") or spec.get("cmd")
            raw_args = spec.get("args", [])
            args = tuple(raw_args) if isinstance(raw_args, (list, tuple)) else ()
            raw_env = spec.get("env") or spec.get("envs") or {}
            url = spec.get("url") or spec.get("uri")
            disabled = bool(spec.get("disabled", False) or spec.get("is_disabled", False))

            # Determine transport type
            if isinstance(url, str) and url:
                transport = TransportType.SSE if "sse" in url.lower() else TransportType.HTTP
            elif command:
                transport = TransportType.STDIO
            else:
                transport = TransportType.UNKNOWN

            # Clean & sanitize environment variable definitions
            env_cleaned: dict[str, str] = {}
            if isinstance(raw_env, dict):
                for k, v in raw_env.items():
                    env_cleaned[str(k)] = cls.expand_env_vars(str(v))

            env_keys = tuple(sorted(env_cleaned.keys()))

            raw_config = dict(spec)
            if "command" not in raw_config and "cmd" in raw_config:
                raw_config["command"] = raw_config["cmd"]
            if "url" not in raw_config and "uri" in raw_config:
                raw_config["url"] = raw_config["uri"]
            raw_config["env"] = (
                dict(spec.get("env") or spec.get("envs") or {})
                if isinstance(spec.get("env") or spec.get("envs"), dict)
                else {}
            )

            discovered.append(
                DiscoveredServerConfig(
                    client_type=client_type,
                    server_name=name,
                    command=command,
                    args=args,
                    env=env_cleaned,
                    env_keys=env_keys,
                    transport_type=transport,
                    url=url if isinstance(url, str) else None,
                    config_path=str(file_path.resolve()),
                    is_disabled=disabled,
                    raw_config=raw_config,
                )
            )

        return discovered

    @classmethod
    def discover_workspace_configs(
        cls,
        root_path: str | Path,
        ignore_matcher: Any | None = None,
    ) -> list[Path]:
        """Recursively discover workspace-local MCP configuration files."""
        from verity.baseline.ignore import DEFAULT_IGNORE_DIRS

        root = Path(root_path).resolve()
        candidate_names = {".mcp.json", "mcp.json", "claude_desktop_config.json"}
        discovered: list[Path] = []

        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.name not in candidate_names:
                continue
            if ignore_matcher is not None:
                if ignore_matcher.is_ignored(path, is_dir=False):
                    continue
            elif any(part in DEFAULT_IGNORE_DIRS for part in path.parts[:-1]):
                continue
            discovered.append(path)

        return discovered

    @classmethod
    def scan_all(
        cls,
        target_clients: list[ClientType] | None = None,
        base_home: str | Path | None = None,
        custom_paths: list[str | Path] | None = None,
        sandbox_root: str | Path | None = None,
    ) -> tuple[list[DiscoveredServerConfig], list[str]]:
        """Scan all known clients and custom paths, strictly isolated to sandbox_root if set."""
        standard_map = cls.get_standard_client_paths(base_home=base_home, sandbox_root=sandbox_root)
        scanned_files: set[str] = set()
        all_discovered: list[DiscoveredServerConfig] = []

        if target_clients is not None or custom_paths is None:
            clients_to_scan = target_clients or list(ClientType)
            for client_type in clients_to_scan:
                for p in standard_map.get(client_type, []):
                    if p.is_file():
                        scanned_files.add(str(p.resolve()))
                        servers = cls.parse_config_file(p, client_type=client_type)
                        all_discovered.extend(servers)

        if custom_paths:
            for cp in custom_paths:
                p = Path(cp)
                if p.is_file():
                    scanned_files.add(str(p.resolve()))
                    servers = cls.parse_config_file(p, client_type=ClientType.CUSTOM)
                    all_discovered.extend(servers)

        return all_discovered, sorted(scanned_files)

    @classmethod
    def scan_global_npm(cls) -> list[dict[str, Any]]:
        """Enumerate globally installed npm MCP servers (opt-in, may exec ``npm``)."""
        try:
            from mcp_fingerprints.config_scanner import NpmGlobalScanner

            result = NpmGlobalScanner().scan_all()
            return result if isinstance(result, list) else []
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Global npm MCP scan failed: %s", exc)
            return []
