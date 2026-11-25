"""ATDD tests for M40: Free CLI --format sarif Pro-only gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verity import cli


def _write_minimal_config(tmp_path: Path) -> Path:
    config_path = tmp_path / "mcp.json"
    config_path.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    return config_path


def test_sarif_requires_pro_plugin(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """AC-40.1: Free emits PRO_FEATURE_REQUIRED, exit code 2, writes no artifact; Pro control exports SARIF."""
    config_path = _write_minimal_config(tmp_path)
    missing_out = tmp_path / "should_not_exist.sarif"
    existing_out = tmp_path / "existing.sarif"
    existing_out.write_text("KEEP_EXISTING_CONTENT", encoding="utf-8")

    # Free mode (Pro plugin absent)
    monkeypatch.setattr(cli, "_pro_plugin_available", lambda: False)

    # 1. With --output pointing to a non-existent file: gate fires, no file created.
    rc = cli.main(
        [
            "scan",
            "--config-file",
            str(config_path),
            "--format",
            "sarif",
            "--output",
            str(missing_out),
        ]
    )
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.err == ""
    assert not missing_out.exists()
    payload = json.loads(captured.out)
    assert payload["ok"] is False
    assert payload["error"] == "PRO_FEATURE_REQUIRED"
    assert "verity-pro" in payload["message"]

    # 2. With --output pointing to an existing file: file must NOT be truncated or overwritten.
    rc_existing = cli.main(
        [
            "scan",
            "--config-file",
            str(config_path),
            "--format",
            "sarif",
            "--output",
            str(existing_out),
        ]
    )
    captured_existing = capsys.readouterr()
    assert rc_existing == 2
    assert captured_existing.err == ""
    assert existing_out.read_text(encoding="utf-8") == "KEEP_EXISTING_CONTENT"
    payload_existing = json.loads(captured_existing.out)
    assert payload_existing["error"] == "PRO_FEATURE_REQUIRED"

    # 3. Paired Pro-present control exports valid SARIF v2.1.0.
    monkeypatch.setattr(cli, "_pro_plugin_available", lambda: True)
    monkeypatch.setattr(cli, "_iter_plugin_entry_points", lambda: [])
    pro_out = tmp_path / "pro_export.sarif"
    rc_pro = cli.main(
        [
            "scan",
            "--config-file",
            str(config_path),
            "--format",
            "sarif",
            "--output",
            str(pro_out),
        ]
    )
    captured_pro = capsys.readouterr()
    assert rc_pro == 0
    assert captured_pro.err == ""
    assert pro_out.exists()
    sarif = json.loads(pro_out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert isinstance(sarif.get("runs"), list) and len(sarif["runs"]) == 1


def test_export_sarif_missing_exporter_emits_structured_error_without_writing_file(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Verify _export_sarif also refuses safely when no exporter is resolved."""
    monkeypatch.setattr(cli, "_load_sarif_exporter", lambda: None)
    out_file = tmp_path / "no_exporter.sarif"

    rc = cli._export_sarif({"findings": []}, str(out_file))
    captured = capsys.readouterr()
    assert rc == 2
    assert not out_file.exists()
    payload = json.loads(captured.out)
    assert payload["ok"] is False
    assert payload["error"] == "PRO_FEATURE_REQUIRED"
    assert "verity-pro" in payload["message"]
