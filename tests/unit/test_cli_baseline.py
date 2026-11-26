"""Locked ATDD tests for M31 / TASK-80 CLI --save-baseline, --baseline, --fail-on-new, and schema guard."""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

import pytest
from verity.baseline.store import BaselineSchemaError, load_baseline

from verity import cli


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "src").mkdir()
    return repo


def test_baseline_store_is_atomic_and_deterministic(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-31.3 / AC-80.9: --save-baseline emits schema_version 1.0, sorted keys/entries, zero secrets/paths."""
    repo = _make_repo(tmp_path)
    srv = repo / "src" / "server.py"
    srv.write_text("def run(expr: str):\n    return eval(expr)\n", encoding="utf-8")

    cfg = repo / "mcp.json"
    secret = "sk-live-baseline-secret-9999999999"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "leaky": {
                        "command": "python3",
                        "args": ["safe.py"],
                        "env": {"OPENAI_API_KEY": secret},
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    b1 = repo / ".verity-baseline.json"
    b2 = repo / ".verity-baseline-2.json"

    rc1 = cli.main(
        [
            "scan",
            "--root",
            str(repo),
            "--path",
            str(srv),
            str(cfg),
            "--offline",
            "--save-baseline",
            str(b1),
            "--format",
            "json",
        ]
    )
    capsys.readouterr()
    assert rc1 == 0
    assert b1.is_file()

    rc2 = cli.main(
        [
            "scan",
            "--root",
            str(repo),
            "--path",
            str(srv),
            str(cfg),
            "--offline",
            "--save-baseline",
            str(b2),
            "--format",
            "json",
        ]
    )
    capsys.readouterr()
    assert rc2 == 0

    raw1 = b1.read_text(encoding="utf-8")
    raw2 = b2.read_text(encoding="utf-8")
    assert raw1 == raw2, "Consecutive baseline saves must be byte-identical"
    assert secret not in raw1
    assert str(repo) not in raw1
    assert "scan_duration_ms" not in raw1
    assert "generated_at" not in raw1

    data = load_baseline(b1)
    assert data["schema_version"] == "1.0"
    entries = data["entries"]
    assert len(entries) >= 2
    sort_keys = [(e["file_path"], e["rule_id"], e["fingerprint"]) for e in entries]
    assert sort_keys == sorted(sort_keys)


def test_scan_baseline_fail_on_new_exit_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-31.3 / AC-80.10: --baseline --fail-on-new exits 0 (no new), 1 (new), 2 (op error)."""
    repo = _make_repo(tmp_path)
    srv = repo / "src" / "server.py"
    srv.write_text("def run(expr: str):\n    return eval(expr)\n", encoding="utf-8")
    baseline = repo / ".verity-baseline.json"

    # Save baseline
    assert (
        cli.main(
            [
                "scan",
                "--root",
                str(repo),
                "--path",
                str(srv),
                "--offline",
                "--save-baseline",
                str(baseline),
            ]
        )
        == 0
    )
    capsys.readouterr()

    # Unchanged repo -> exit 0, 0 new findings
    rc_clean = cli.main(
        [
            "scan",
            "--root",
            str(repo),
            "--path",
            str(srv),
            "--offline",
            "--baseline",
            str(baseline),
            "--fail-on-new",
            "--format",
            "json",
        ]
    )
    out_clean = json.loads(capsys.readouterr().out)
    assert rc_clean == 0
    assert out_clean["summary"]["new_findings"] == 0
    assert out_clean["summary"]["baseline_findings"] == 1
    assert out_clean["summary"]["resolved_since_baseline"] == 0

    # Add a new finding -> exit 1, new_findings == 1
    srv2 = repo / "src" / "new_tool.py"
    srv2.write_text(
        "import os\ndef bad():\n    os.system('id')\n", encoding="utf-8"
    )
    rc_new = cli.main(
        [
            "scan",
            "--root",
            str(repo),
            "--path",
            str(repo),
            "--offline",
            "--baseline",
            str(baseline),
            "--fail-on-new",
            "--format",
            "json",
        ]
    )
    out_new = json.loads(capsys.readouterr().out)
    assert rc_new == 1
    assert out_new["summary"]["new_findings"] == 1
    assert out_new["summary"]["baseline_findings"] == 1

    # Resolve original finding -> resolved_since_baseline == 1
    srv.write_text("def run(x: int) -> int:\n    return x + 1\n", encoding="utf-8")
    srv2.unlink()
    rc_resolved = cli.main(
        [
            "scan",
            "--root",
            str(repo),
            "--path",
            str(repo),
            "--offline",
            "--baseline",
            str(baseline),
            "--fail-on-new",
            "--format",
            "json",
        ]
    )
    out_res = json.loads(capsys.readouterr().out)
    assert rc_resolved == 0
    assert out_res["summary"]["new_findings"] == 0
    assert out_res["summary"]["resolved_since_baseline"] == 1

    # Missing baseline -> exit 2
    rc_missing = cli.main(
        [
            "scan",
            "--root",
            str(repo),
            "--path",
            str(srv),
            "--offline",
            "--baseline",
            str(repo / "missing-baseline.json"),
            "--fail-on-new",
        ]
    )
    capsys.readouterr()
    assert rc_missing == 2


def test_baseline_schema_mismatch_with_verity_test_baseline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-31.3 / AC-80.11: verity test rug-pull dict vs verity scan baseline cross-use exits 2."""
    repo = _make_repo(tmp_path)
    srv = repo / "src" / "server.py"
    srv.write_text("x = 1\n", encoding="utf-8")

    rug_pull_baseline = repo / "rug_pull_baseline.json"
    rug_pull_baseline.write_text(
        json.dumps({"query_docs": "a" * 64}), encoding="utf-8"
    )
    with pytest.raises(BaselineSchemaError):
        load_baseline(rug_pull_baseline)

    # Passing rug-pull dict to `verity scan --baseline` -> exit 2
    rc_scan = cli.main(
        [
            "scan",
            "--root",
            str(repo),
            "--path",
            str(srv),
            "--offline",
            "--baseline",
            str(rug_pull_baseline),
        ]
    )
    capsys.readouterr()
    assert rc_scan == 2

    # Passing `verity scan` baseline to `verity test --baseline` -> exit 2
    scan_baseline = repo / ".verity-baseline.json"
    scan_baseline.write_text(
        json.dumps({"schema_version": "1.0", "entries": []}), encoding="utf-8"
    )
    stdio_script = tmp_path / "dummy_mcp.py"
    stdio_script.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    req = json.loads(line)\n"
        "    if 'id' not in req: continue\n"
        "    m = req.get('method')\n"
        "    res = {'tools': []} if m == 'tools/list' else {'protocolVersion': '2024-11-05', 'capabilities': {'tools': {}}}\n"
        "    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'result': res}) + '\\n')\n"
        "    sys.stdout.flush()\n",
        encoding="utf-8",
    )
    cmd = f"{shlex.quote(sys.executable)} {shlex.quote(str(stdio_script))}"
    rc_test = cli.main(
        ["test", "--command", cmd, "--baseline", str(scan_baseline)]
    )
    capsys.readouterr()
    assert rc_test == 2
