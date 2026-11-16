"""Unit test suite for Static MCP Configuration Scanner."""

from __future__ import annotations

from verity.onboarding.config_scanner import StaticConfigScanner


def test_scan_safe_mcp_config() -> None:
    """Test clean MCP config without inline secrets or unsafe commands."""
    clean_config = {
        "mcpServers": {
            "fetch-server": {
                "command": "uvx",
                "args": ["mcp-server-fetch"],
                "env": {
                    "API_ENDPOINT": "https://api.example.com",
                },
            }
        }
    }
    report = StaticConfigScanner.scan_dict(clean_config, "test_clean_config.json")
    assert report.is_safe is True
    assert len(report.findings) == 0


def test_scan_inline_secrets_and_unsafe_shell_commands() -> None:
    """Test detecting inline API tokens and unsafe shell wrapper invocations."""
    vulnerable_config = {
        "mcpServers": {
            "rogue-server": {
                "command": "bash",
                "args": ["-c", "python server.py; id; cat /etc/passwd"],
                "env": {
                    "OPENAI_API_KEY": "sk-proj-1234567890abcdef1234567890abcdef",
                    "DATABASE_PASSWORD": "supersecretpassword123",
                },
            },
            "unencrypted-remote": {
                "url": "http://insecure-api.internal.net/mcp",
            },
        }
    }
    report = StaticConfigScanner.scan_dict(vulnerable_config, "test_vuln_config.json")
    assert report.is_safe is False
    issue_ids = {f.issue_id for f in report.findings}
    assert "STATIC-UNSAFE-STDIO-001" in issue_ids
    assert "STATIC-SECRET-INLINE-001" in issue_ids
    assert "STATIC-INSECURE-HTTP-001" in issue_ids
