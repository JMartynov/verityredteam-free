"""Locked ATDD tests for M46 Phase A: 15+ client discovery, JSONC stripping, --client, and --scan-global."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from verity import cli
from verity.discovery.config_scanner import MultiClientConfigScanner, strip_jsonc_comments
from verity.discovery.models import ClientType


def test_client_type_supports_15_plus_clients_and_aliases() -> None:
    """AC-46.1 / AC-82.1: MultiClientConfigScanner resolves 15+ IDE/agent clients and aliases."""
    expected_clients = {
        "claude_desktop",
        "claude_code",
        "cursor",
        "windsurf",
        "zed",
        "vscode_cline",
        "vscode_roo",
        "goose",
        "continue",
        "junie",
        "vscode",
        "antigravity",
        "openhands",
        "trae",
        "lmstudio",
        "librechat",
        "workspace",
    }
    member_values = {c.value for c in ClientType}
    assert expected_clients <= member_values
    assert len(expected_clients) >= 15

    assert ClientType.from_str("claude-code") == ClientType.CLAUDE_CODE
    assert ClientType.from_str("CLAUDE_CODE") == ClientType.CLAUDE_CODE
    assert ClientType.from_str("cline") == ClientType.VSCODE_CLINE
    assert ClientType.from_str("vscode_cline") == ClientType.VSCODE_CLINE
    assert ClientType.from_str("roo-code") == ClientType.VSCODE_ROO
    assert ClientType.from_str("vscode_roo") == ClientType.VSCODE_ROO
    assert ClientType.from_str("claude-desktop") == ClientType.CLAUDE_DESKTOP

    with pytest.raises(ValueError):
        ClientType.from_str("nonexistent-ide-client")


def test_standard_client_paths_discover_new_clients(tmp_path: Path) -> None:
    """AC-46.1 / AC-82.1: Standard client paths resolve all 15+ clients inside sandbox_root."""
    sandbox = tmp_path / "sandbox"
    home = sandbox / "home"
    workspace = sandbox / "workspace"

    configs: dict[Path, tuple[ClientType, str, str]] = {
        home / ".claude.json": (ClientType.CLAUDE_CODE, "cc-srv", "uvx"),
        home / ".config" / "goose" / "config.yaml": (ClientType.GOOSE, "goose-srv", "npx"),
        workspace / ".idea" / "mcp.json": (ClientType.JUNIE, "junie-srv", "npx"),
        home / ".gemini" / "config" / "mcp_config.json": (ClientType.ANTIGRAVITY, "agy-srv", "uvx"),
        home / ".openhands" / "mcp.json": (ClientType.OPENHANDS, "oh-srv", "npx"),
        home / ".trae" / "mcp.json": (ClientType.TRAE, "trae-srv", "npx"),
        home / ".lmstudio" / "mcp.json": (ClientType.LMSTUDIO, "lms-srv", "npx"),
    }

    for path, (_ct, srv_name, cmd) in configs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix == ".yaml":
            path.write_text(
                f"extensions:\n  {srv_name}:\n    cmd: {cmd}\n    args:\n      - -y\n      - safe-pkg@1.0.0\n",
                encoding="utf-8",
            )
        else:
            path.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            srv_name: {
                                "command": cmd,
                                "args": ["-y", "safe-pkg@1.0.0"],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

    paths_map = MultiClientConfigScanner.get_standard_client_paths(sandbox_root=sandbox)
    for ct in (
        ClientType.CLAUDE_CODE,
        ClientType.GOOSE,
        ClientType.JUNIE,
        ClientType.VSCODE,
        ClientType.ANTIGRAVITY,
        ClientType.OPENHANDS,
        ClientType.TRAE,
        ClientType.LMSTUDIO,
    ):
        assert ct in paths_map and paths_map[ct]

    discovered, scanned_files = MultiClientConfigScanner.scan_all(sandbox_root=sandbox)
    discovered_map = {d.client_type: d for d in discovered}
    for _path, (ct, srv_name, _cmd) in configs.items():
        assert ct in discovered_map
        assert discovered_map[ct].server_name == srv_name
    assert len(scanned_files) == len(configs)


def test_jsonc_stripping_preserves_urls_and_parses_comments(tmp_path: Path) -> None:
    """AC-46.1 / AC-82.1: JSONC // comments, /* */ comments, and trailing commas parse cleanly without corrupting URLs."""
    jsonc_text = """{
  // Line comment at top
  "mcpServers": {
    "remote-http": {
      "url": "https://mcp.example.com/sse", // inline comment after URL
      "env": {
        "DOCS_URL": "http://internal.local/docs//v1",
      },
    },
    /* Multi-line
       block comment */
    "local-stdio": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    },
  },
}"""
    cleaned = strip_jsonc_comments(jsonc_text)
    parsed = json.loads(cleaned)
    assert parsed["mcpServers"]["remote-http"]["url"] == "https://mcp.example.com/sse"
    assert parsed["mcpServers"]["remote-http"]["env"]["DOCS_URL"] == "http://internal.local/docs//v1"

    cfg_path = tmp_path / "zed_settings.jsonc"
    cfg_path.write_text(jsonc_text, encoding="utf-8")
    servers = MultiClientConfigScanner.parse_config_file(cfg_path, ClientType.ZED)
    assert [s.server_name for s in servers] == ["remote-http", "local-stdio"]
    assert servers[0].url == "https://mcp.example.com/sse"


def test_non_mcp_json_skipped_cleanly(tmp_path: Path) -> None:
    """Paired benign: non-MCP JSON files produce 0 discovered servers and 0 findings."""
    non_mcp = tmp_path / "package.json"
    non_mcp.write_text(
        json.dumps(
            {
                "name": "ordinary-web-app",
                "version": "1.0.0",
                "scripts": {"test": "vitest"},
                "dependencies": {"express": "^4.18.0"},
            }
        ),
        encoding="utf-8",
    )
    servers = MultiClientConfigScanner.parse_config_file(non_mcp, ClientType.WORKSPACE)
    assert servers == []


def test_cli_client_filter_and_opt_in_scan_global(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-46.1 / AC-82.1: --client filters discovery and --scan-global is strictly opt-in."""
    home = tmp_path / "home"
    cursor_cfg = home / ".cursor" / "mcp.json"
    cursor_cfg.parent.mkdir(parents=True)
    cursor_cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "cursor-srv": {
                        "command": "bash",
                        "args": ["-c", "echo hi"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    cc_cfg = home / ".claude.json"
    cc_cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "cc-srv": {
                        "command": "npx",
                        "args": ["-y", "safe-pkg@1.0.0"],
                        "env": {"API_KEY": "sk-live-secret-token-1234567890"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    orig_scan_all = MultiClientConfigScanner.scan_all

    def fake_scan_all(
        target_clients: list[ClientType] | None = None,
        base_home: str | Path | None = None,
        custom_paths: list[str | Path] | None = None,
        sandbox_root: str | Path | None = None,
    ) -> tuple[list[object], list[str]]:
        return orig_scan_all(
            target_clients=target_clients,
            base_home=home,
            custom_paths=custom_paths,
            sandbox_root=sandbox_root,
        )

    monkeypatch.setattr(MultiClientConfigScanner, "scan_all", fake_scan_all)

    npm_mock = MagicMock(
        return_value=[
            {
                "client": "npm-global",
                "name": "@evil/mcp-global-test",
                "command": "mcp-global-test",
                "args": [],
                "source": str(tmp_path / "node_modules/@evil/mcp-global-test/package.json"),
                "version": "1.0.0",
            }
        ]
    )
    monkeypatch.setattr(MultiClientConfigScanner, "scan_global_npm", npm_mock)

    # 1. Without --scan-global, NpmGlobalScanner is NOT called; --client claude-code filters out cursor.
    rc = cli.main(
        ["scan", "--client", "claude-code", "--offline", "--format", "json"]
    )
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert npm_mock.call_count == 0
    server_names = {f.get("server_name") for f in out["findings"]}
    assert "cc-srv" in server_names
    assert "cursor-srv" not in server_names

    # 2. With --scan-global, scan_global_npm IS invoked.
    rc_global = cli.main(
        ["scan", "--client", "claude-code", "--scan-global", "--offline", "--format", "json"]
    )
    out_global = json.loads(capsys.readouterr().out)
    assert rc_global == 0
    assert npm_mock.call_count == 1
    assert out_global["summary"]["scanned_files_count"] >= 1
