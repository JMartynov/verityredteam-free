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

logger = logging.getLogger("verity.discovery.config_scanner")


class MultiClientConfigScanner:
    """Discovers, parses, and normalizes MCP client configurations across all supported tools."""

    SECRET_KEY_PATTERNS = re.compile(
        r"(api[_-]?key|secret|token|password|bearer|auth|jwt|private[_-]?key)",
        re.IGNORECASE,
    )
    SECRET_VALUE_PATTERNS = re.compile(
        r"(sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{30,}|eyJ[a-zA-Z0-9_-]{20,})",
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
        if cls.SECRET_KEY_PATTERNS.search(str(key)):
            return True
        if cls.SECRET_VALUE_PATTERNS.search(text):
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
            ClientType.CURSOR: [],
            ClientType.VSCODE_CLINE: [],
            ClientType.VSCODE_ROO: [],
            ClientType.CONTINUE: [],
            ClientType.WINDSURF: [],
            ClientType.ZED: [],
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
        """Parse JSON or YAML config file contents."""
        content = file_path.read_text(encoding="utf-8")
        if file_path.suffix.lower() in (".yaml", ".yml"):
            return yaml.safe_load(content)
        return json.loads(content)

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
        for key in ("mcpServers", "mcp_servers", "servers", "context_servers"):
            cls._collect_specs(data.get(key), pairs)

        experimental = data.get("experimental")
        if isinstance(experimental, dict):
            cls._collect_specs(experimental.get("modelContextProtocolServers"), pairs)

        if not pairs and "command" not in data:
            for name, spec in data.items():
                if isinstance(spec, dict) and any(
                    k in spec
                    for k in ("command", "url", "args", "env", "transport", "type", "disabled")
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
            command = spec.get("command")
            raw_args = spec.get("args", [])
            args = tuple(raw_args) if isinstance(raw_args, (list, tuple)) else ()
            raw_env = spec.get("env", {})
            url = spec.get("url")
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
            raw_config["env"] = dict(raw_env) if isinstance(raw_env, dict) else {}

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
