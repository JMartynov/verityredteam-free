"""Static analyzer for IDE and client MCP configuration files."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, ClassVar

from verity.onboarding.models import ConfigAssessmentReport, ConfigSecurityFinding


class StaticConfigScanner:
    """Scans local MCP client configuration files (Claude Desktop, Cursor, VSCode)."""

    SECRET_KEY_PATTERNS = re.compile(
        r"(api[_-]?key|secret|token|password|bearer|auth|jwt|private[_-]?key)",
        re.IGNORECASE,
    )
    SECRET_VALUE_PATTERNS = re.compile(
        r"(sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{30,}|eyJ[a-zA-Z0-9_-]{20,})",
    )
    UNSAFE_SHELL_COMMANDS: ClassVar[set[str]] = {
        "sh",
        "bash",
        "zsh",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
    }
    SHELL_METACHAR_PATTERN = re.compile(r"[;&|><`$]")

    @classmethod
    def scan_file(cls, config_path: str | Path) -> ConfigAssessmentReport:
        """Parse and analyze a single MCP configuration file."""
        path = Path(config_path)
        if not path.is_file():
            return ConfigAssessmentReport(
                scanned_file=str(path),
                discovered_servers=(),
                findings=(
                    ConfigSecurityFinding(
                        issue_id="STATIC-FILE-NOT-FOUND-001",
                        severity="LOW",
                        server_name="",
                        config_path=str(path),
                        description="Target MCP configuration file does not exist.",
                        redacted_evidence=str(path),
                    ),
                ),
                is_safe=False,
            )

        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as err:
            return ConfigAssessmentReport(
                scanned_file=str(path),
                discovered_servers=(),
                findings=(
                    ConfigSecurityFinding(
                        issue_id="STATIC-CONFIG-MALFORMED-001",
                        severity="MEDIUM",
                        server_name="",
                        config_path=str(path),
                        description=f"Configuration file contains invalid JSON: {err}",
                        redacted_evidence=str(err),
                    ),
                ),
                is_safe=False,
            )

        return cls.scan_dict(data, str(path))

    @classmethod
    def scan_dict(
        cls,
        data: dict[str, Any],
        config_path: str = "memory",
    ) -> ConfigAssessmentReport:
        """Analyze in-memory MCP configuration dictionary."""
        findings: list[ConfigSecurityFinding] = []
        servers = data.get("mcpServers", {})
        if not isinstance(servers, dict):
            servers = data.get("servers", {})
        if not isinstance(servers, dict):
            servers = {}

        discovered_servers = tuple(servers.keys())

        for server_name, server_cfg in servers.items():
            if not isinstance(server_cfg, dict):
                continue

            # 1. Check for unsafe stdio command execution
            command = str(server_cfg.get("command", ""))
            args = server_cfg.get("args", [])
            args_str = " ".join(str(a) for a in args) if isinstance(args, list) else str(args)

            cmd_base = Path(command).name.lower()
            if cmd_base in cls.UNSAFE_SHELL_COMMANDS or "-c" in args or "/c" in args:
                findings.append(
                    ConfigSecurityFinding(
                        issue_id="STATIC-UNSAFE-STDIO-001",
                        severity="HIGH",
                        server_name=server_name,
                        config_path=config_path,
                        description=(
                            f"Server '{server_name}' uses unsafe shell wrapper "
                            f"command: '{command}'."
                        ),
                        redacted_evidence=f"command: {command}, args: {args_str[:50]}",
                    )
                )
            elif cls.SHELL_METACHAR_PATTERN.search(command) or cls.SHELL_METACHAR_PATTERN.search(
                args_str
            ):
                findings.append(
                    ConfigSecurityFinding(
                        issue_id="STATIC-UNSAFE-STDIO-001",
                        severity="HIGH",
                        server_name=server_name,
                        config_path=config_path,
                        description=(
                            f"Server '{server_name}' contains unescaped shell metacharacters "
                            "in command or args."
                        ),
                        redacted_evidence=f"command: {command[:30]}...",
                    )
                )

            # 2. Check for inline raw credentials and secrets
            env = server_cfg.get("env", {})
            if isinstance(env, dict):
                for env_k, env_v in env.items():
                    val_str = str(env_v)
                    if (
                        cls.SECRET_KEY_PATTERNS.search(env_k)
                        and not val_str.startswith("${")
                        and len(val_str) > 6
                    ):
                        findings.append(
                            ConfigSecurityFinding(
                                issue_id="STATIC-SECRET-INLINE-001",
                                severity="CRITICAL",
                                server_name=server_name,
                                config_path=config_path,
                                description=(
                                    f"Server '{server_name}' exposes inline raw secret "
                                    f"in environment key '{env_k}'."
                                ),
                                redacted_evidence=f"{env_k}=***REDACTED_SECRET***",
                            )
                        )
                    elif cls.SECRET_VALUE_PATTERNS.search(val_str):
                        findings.append(
                            ConfigSecurityFinding(
                                issue_id="STATIC-SECRET-INLINE-001",
                                severity="CRITICAL",
                                server_name=server_name,
                                config_path=config_path,
                                description=(
                                    f"Server '{server_name}' contains raw token pattern "
                                    f"in environment key '{env_k}'."
                                ),
                                redacted_evidence=f"{env_k}=***REDACTED_API_TOKEN***",
                            )
                        )

            # 3. Check for unapproved wildcard or insecure endpoints
            url = str(server_cfg.get("url", ""))
            if url.startswith("http://") and not (
                url.startswith("http://localhost") or url.startswith("http://127.0.0.1")
            ):
                findings.append(
                    ConfigSecurityFinding(
                        issue_id="STATIC-INSECURE-HTTP-001",
                        severity="MEDIUM",
                        server_name=server_name,
                        config_path=config_path,
                        description=(
                            f"Server '{server_name}' uses unencrypted HTTP remote transport."
                        ),
                        redacted_evidence=f"url: {url}",
                    )
                )

        return ConfigAssessmentReport(
            scanned_file=config_path,
            discovered_servers=discovered_servers,
            findings=tuple(findings),
            is_safe=len(findings) == 0,
        )
