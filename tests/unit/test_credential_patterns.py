"""Unit tests for M16 shared cloud credential pattern detection and scrubbing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verity import cli
from verity.discovery.config_scanner import MultiClientConfigScanner
from verity.scanner.credential_patterns import (
    CREDENTIAL_VALUE_PATTERNS,
    PEM_PRIVATE_KEY_BLOCK_PATTERN,
    is_placeholder_value,
)
from verity.scanner.static_rules import StaticRuleEvaluator

AWS_ACCESS_KEY_ID = "AKIAABCDEFGHIJKLMNOP"
AWS_SECRET_ACCESS_KEY = "verityE2eFakeSecretKey0000000000000000000"
PEM_PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIVerityFakeKeyMaterial0000000000000000000000000000000000000\n"
    "-----END RSA PRIVATE KEY-----"
)
SLACK_TOKEN = "xoxb-1234567890-abcdefghijklmn"
GOOGLE_API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv"
OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwx"
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
JWT_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
AWS_ASIA_KEY = "ASIABCDEFGHIJKLMNOPQ"
GITHUB_PAT = "github_pat_abcdefghijklmnopqrstuvwxyz_1234567890"
SLACK_USER_TOKEN = "xoxp-1234567890-abcdefghijklmn"

CREDENTIAL_SAMPLES = [
    ("aws_access_key_id", AWS_ACCESS_KEY_ID),
    ("aws_asia_key", AWS_ASIA_KEY),
    ("pem_private_key", PEM_PRIVATE_KEY),
    ("slack_bot_token", SLACK_TOKEN),
    ("slack_user_token", SLACK_USER_TOKEN),
    ("google_api_key", GOOGLE_API_KEY),
    ("openai_key", OPENAI_KEY),
    ("github_token", GITHUB_TOKEN),
    ("github_pat", GITHUB_PAT),
    ("jwt_token", JWT_TOKEN),
]


class _NoMatchResult:
    matched = False
    package_name = None
    purl = None
    matched_version = None
    confidence_score = 0.0
    match_layer = "NONE"


class _FakeFingerprintIndex:
    def find_package_by_hint_or_alias(self, name: str) -> None:
        return None


@pytest.fixture
def offline_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run the CLI auditor fully offline with deterministic empty match data."""
    from verity.discovery import auditor as auditor_module

    def fake_init(
        self: object, fingerprint_dir: str | Path = "data/fingerprints"
    ) -> None:
        self.fingerprint_dir = Path(fingerprint_dir)
        self.fast_index = _FakeFingerprintIndex()

    monkeypatch.setattr(auditor_module.HybridDiscoveryMatcher, "__init__", fake_init)
    monkeypatch.setattr(
        auditor_module.HybridDiscoveryMatcher,
        "match_static_config",
        lambda self, config: _NoMatchResult(),
    )
    monkeypatch.setattr(
        auditor_module.VulnerabilityLookupEngine,
        "from_auto",
        classmethod(lambda cls, *args, **kwargs: None),
    )
    monkeypatch.setenv("VERITY_OFFLINE", "1")


def _write_config(path: Path, env: dict[str, str]) -> Path:
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "cred-server": {
                        "command": "python3",
                        "args": ["server.py"],
                        "env": env,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize("fmt", ["terminal", "json", "markdown", "html"])
def test_aws_credentials_flagged_and_scrubbed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    offline_audit: None,
    fmt: str,
) -> None:
    config_path = _write_config(
        tmp_path / "mcp.json",
        {
            "AWS_ACCESS_KEY_ID": AWS_ACCESS_KEY_ID,
            "AWS_SECRET_ACCESS_KEY": AWS_SECRET_ACCESS_KEY,
        },
    )

    exit_code = cli.main(["scan", "--config-file", str(config_path), "--format", fmt])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "SEC-STATIC-SECRET-IN-CONFIG" in out
    assert AWS_ACCESS_KEY_ID not in out
    assert AWS_SECRET_ACCESS_KEY not in out

    if fmt == "json":
        report = json.loads(out)
        messages = [
            f["message"]
            for f in report["findings"]
            if f["rule_id"] == "SEC-STATIC-SECRET-IN-CONFIG"
        ]
        assert any(
            "AWS_ACCESS_KEY_ID" in m and "****" in m for m in messages
        ), messages
        assert any(
            "AWS_SECRET_ACCESS_KEY" in m and "****" in m for m in messages
        ), messages


def test_aws_key_flagged_under_non_secret_key_name(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    offline_audit: None,
) -> None:
    config_path = _write_config(
        tmp_path / "mcp.json", {"CUSTOM_FIELD": AWS_ACCESS_KEY_ID}
    )

    exit_code = cli.main(
        ["scan", "--config-file", str(config_path), "--format", "json"]
    )
    out = capsys.readouterr().out
    report = json.loads(out)
    keys = {
        f["rule_id"]
        for f in report["findings"]
        if f["rule_id"] == "SEC-STATIC-SECRET-IN-CONFIG"
    }
    assert exit_code == 0
    assert keys
    assert AWS_ACCESS_KEY_ID not in out


@pytest.mark.parametrize("fmt", ["terminal", "json", "markdown", "html"])
def test_pem_private_key_flagged_and_scrubbed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    offline_audit: None,
    fmt: str,
) -> None:
    config_path = _write_config(tmp_path / "mcp.json", {"TLS_KEY": PEM_PRIVATE_KEY})

    exit_code = cli.main(["scan", "--config-file", str(config_path), "--format", fmt])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "SEC-STATIC-SECRET-IN-CONFIG" in out
    assert "MIIVerityFakeKeyMaterial" not in out
    assert PEM_PRIVATE_KEY not in out


@pytest.mark.parametrize("fmt", ["terminal", "json", "markdown", "html"])
def test_slack_and_google_tokens_flagged(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    offline_audit: None,
    fmt: str,
) -> None:
    config_path = _write_config(
        tmp_path / "mcp.json",
        {"SLACK_BOT": SLACK_TOKEN, "GOOGLE_FIELD": GOOGLE_API_KEY},
    )

    exit_code = cli.main(["scan", "--config-file", str(config_path), "--format", fmt])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "SEC-STATIC-SECRET-IN-CONFIG" in out
    assert SLACK_TOKEN not in out
    assert GOOGLE_API_KEY not in out


@pytest.mark.parametrize("fmt", ["terminal", "json", "markdown", "html"])
def test_env_references_and_placeholders_not_flagged(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    offline_audit: None,
    fmt: str,
) -> None:
    config_path = _write_config(
        tmp_path / "mcp.json",
        {
            "AWS_ACCESS_KEY_ID": "${AWS_ACCESS_KEY_ID}",
            "AWS_SECRET_ACCESS_KEY": "$AWS_SECRET_ACCESS_KEY",
            "OPENAI_API_KEY": "YOUR_API_KEY",
            "PRIVATE_KEY_PEM": "<YOUR_PRIVATE_KEY>",
        },
    )

    exit_code = cli.main(["scan", "--config-file", str(config_path), "--format", fmt])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "SEC-STATIC-SECRET-IN-CONFIG" not in out


@pytest.mark.parametrize("fmt", ["terminal", "json", "markdown", "html"])
def test_benign_values_not_flagged(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    offline_audit: None,
    fmt: str,
) -> None:
    config_path = _write_config(
        tmp_path / "mcp.json",
        {"AWS_REGION": "us-east-1", "LOG_LEVEL": "debug"},
    )

    exit_code = cli.main(["scan", "--config-file", str(config_path), "--format", fmt])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "SEC-STATIC-SECRET-IN-CONFIG" not in out


@pytest.mark.parametrize("name,value", CREDENTIAL_SAMPLES)
def test_registry_parity_between_config_scan_and_static_rules(
    name: str, value: str
) -> None:
    assert any(pattern.search(value) for pattern in CREDENTIAL_VALUE_PATTERNS), name
    assert not is_placeholder_value(value), name
    assert MultiClientConfigScanner.is_secret_env_entry("CUSTOM_FIELD", value), name

    matches = StaticRuleEvaluator().scan_text(value, "tool", "parity", "description")
    assert any(
        m.rule_id == "VERITY-STATIC-CREDENTIAL-HARVESTING" for m in matches
    ), f"{name}: {matches}"


def test_pem_block_pattern_matches_full_and_truncated_blocks() -> None:
    full = PEM_PRIVATE_KEY_BLOCK_PATTERN.search(PEM_PRIVATE_KEY)
    assert full is not None
    assert full.group(0) == PEM_PRIVATE_KEY

    truncated = PEM_PRIVATE_KEY_BLOCK_PATTERN.search(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIVerityFakeKeyMaterial"
    )
    assert truncated is not None
    assert truncated.group(0).startswith("-----BEGIN RSA PRIVATE KEY-----")


@pytest.mark.parametrize(
    "placeholder",
    [
        "YOUR_API_KEY",
        "<YOUR_AWS_SECRET>",
        "REPLACE_WITH_KEY",
        "INSERT_KEY_HERE",
        "CHANGE_ME",
        "CHANGEME",
        "PLACEHOLDER",
        "TODO",
        "xxxxxxxx",
        "****",
        "***",
    ],
)
def test_placeholder_values_are_not_secrets(placeholder: str) -> None:
    assert is_placeholder_value(placeholder)
    assert not MultiClientConfigScanner.is_secret_env_entry("API_KEY", placeholder)


@pytest.mark.parametrize("name,value", CREDENTIAL_SAMPLES)
def test_realistic_fake_tokens_are_not_placeholders(name: str, value: str) -> None:
    assert not is_placeholder_value(value), name


def test_scrub_secrets_redacts_full_pem_empty_secrets() -> None:
    finding = {"message": f"Leaked: {PEM_PRIVATE_KEY}"}
    scrubbed = cli._scrub_secrets(finding, [])
    assert "-----BEGIN RSA PRIVATE KEY-----" not in scrubbed["message"]
    assert "MIIVerityFakeKeyMaterial" not in scrubbed["message"]
    assert "****" in scrubbed["message"]


def test_scrub_secrets_redacts_full_pem_nonempty_secrets() -> None:
    finding = {"message": f"Leaked: {PEM_PRIVATE_KEY}"}
    scrubbed = cli._scrub_secrets(finding, ["unrelated-correlation-id-12345"])
    assert "-----BEGIN RSA PRIVATE KEY-----" not in scrubbed["message"]
    assert "MIIVerityFakeKeyMaterial" not in scrubbed["message"]
    assert "****" in scrubbed["message"]


def test_scrub_secrets_redacts_truncated_pem() -> None:
    truncated = "-----BEGIN RSA PRIVATE KEY-----\nMIIVerityFakeKeyMaterial"
    finding = {"message": f"Truncated: {truncated}"}
    scrubbed = cli._scrub_secrets(finding, [])
    assert "-----BEGIN RSA PRIVATE KEY-----" not in scrubbed["message"]
    assert "MIIVerityFakeKeyMaterial" not in scrubbed["message"]
    assert "****" in scrubbed["message"]


@pytest.mark.parametrize("fmt", ["terminal", "json", "markdown", "html"])
def test_pem_in_env_and_description_redacted(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    offline_audit: None,
    fmt: str,
) -> None:
    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "multi-pem-server": {
                        "command": "python3",
                        "args": ["server.py"],
                        "description": f"Debug key {PEM_PRIVATE_KEY} embedded",
                        "env": {"TLS_KEY": PEM_PRIVATE_KEY},
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    exit_code = cli.main(["scan", "--config-file", str(config_path), "--format", fmt])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "-----BEGIN RSA PRIVATE KEY-----" not in out
    assert "MIIVerityFakeKeyMaterial" not in out


@pytest.mark.parametrize(
    "key",
    [
        "CLIENT_SECRET",
        "AWS_CREDENTIALS",
        "ACCESS_KEY",
        "AWS_SECRET_ACCESS_KEY",
    ],
)
def test_extended_secret_key_names_flagged(key: str) -> None:
    assert MultiClientConfigScanner.SECRET_KEY_PATTERNS.search(key), key
    assert MultiClientConfigScanner.is_secret_env_entry(key, "somevalue123"), key
