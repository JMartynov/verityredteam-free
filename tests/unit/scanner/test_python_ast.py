"""Locked ATDD unit tests for M39: Python AST Real-World Rules & Import Aliases."""

from __future__ import annotations

from pathlib import Path

from verity.scanner import RuleCatalog, scan_python_file

_PYTHON_AST_PATH = (
    Path(__file__).resolve().parents[3] / "src" / "verity" / "scanner" / "python_ast.py"
)


def test_import_alias_resolution(tmp_path: Path) -> None:
    """AC-39.1: Aliased imports resolve to canonical dotted names before rule dispatch."""
    target = tmp_path / "aliased_server.py"
    target.write_text(
        """
import pickle as p
from subprocess import Popen as run_cmd

def tool_load_and_exec(buf: bytes, cmd: str):
    obj = p.loads(buf)
    run_cmd(cmd, shell=True)
    return obj
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_python_file(target)
    rule_ids = {f.rule_id for f in findings}
    assert "VERITY-AST-CWE-502-PICKLE" in rule_ids
    assert "VERITY-AST-CWE-78-SHELL" in rule_ids


def test_benign_os_path_join(tmp_path: Path) -> None:
    """AC-39.1: Benign constant-only os.path.join alias and unknown roots stay clean."""
    target = tmp_path / "benign_alias_server.py"
    target.write_text(
        """
import os.path as osp

BASE_DIR = "/srv/static"

def get_index_path(custom_client) -> str:
    custom_client.sub.call("ping")
    return osp.join(BASE_DIR, "index.html")
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_python_file(target)
    assert findings == []


def test_cwe22_traversal_flagged(tmp_path: Path) -> None:
    """AC-39.2: Real parameter-to-sink def-use traversal without containment is flagged."""
    source_text = _PYTHON_AST_PATH.read_text(encoding="utf-8")
    assert "is_traversal" not in source_text

    target = tmp_path / "traversal_vuln.py"
    target.write_text(
        """
import os

@mcp.tool()
def read_log(filename: str) -> str:
    target = os.path.join("/var/log/app", filename)
    with open(target, "r", encoding="utf-8") as fh:
        return fh.read()
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_python_file(target)
    cwe22 = [f for f in findings if f.rule_id == RuleCatalog.RULE_CWE_22_UNBOUNDED_READ.rule_id]
    assert len(cwe22) >= 1
    assert cwe22[0].rule_id == "VERITY-AST-CWE-22-TRAVERSAL"
    assert cwe22[0].cwe_id == "CWE-22"


def test_cwe22_traversal_defended(tmp_path: Path) -> None:
    """AC-39.2: Containment checks (resolve+is_relative_to, realpath, commonpath) and constants stay clean."""
    target = tmp_path / "traversal_safe.py"
    target.write_text(
        """
import os
from pathlib import Path

BASE_DIR = "/var/log/app"
DEFAULT_LOG = "/var/log/app/default.log"

@mcp.tool()
def read_log_pathlib(filename: str) -> str:
    candidate = Path(BASE_DIR, filename).resolve()
    if not candidate.is_relative_to(Path(BASE_DIR).resolve()):
        raise ValueError("Path escapes sandbox")
    with open(candidate, "r", encoding="utf-8") as fh:
        return fh.read()

@mcp.tool()
def read_log_realpath(filename: str) -> str:
    root = os.path.realpath(BASE_DIR)
    candidate = os.path.realpath(os.path.join(BASE_DIR, filename))
    if os.path.commonpath([root, candidate]) != root:
        raise ValueError("Path escapes sandbox")
    with open(candidate, "r", encoding="utf-8") as fh:
        return fh.read()

@mcp.tool()
def read_default_log() -> str:
    with open(DEFAULT_LOG, "r", encoding="utf-8") as fh:
        return fh.read()
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_python_file(target)
    cwe22 = [f for f in findings if f.rule_id == "VERITY-AST-CWE-22-TRAVERSAL"]
    assert cwe22 == []


def test_cwe89_sqli_fstring(tmp_path: Path) -> None:
    """AC-39.3: Dynamic SQL via f-string, .format(), and % interpolation is flagged."""
    target = tmp_path / "sqli_vuln.py"
    target.write_text(
        """
def query_users(cursor, connection, session, user: str, uid: int, role: str):
    cursor.execute(f"SELECT * FROM users WHERE name = '{user}'")
    connection.execute("SELECT * FROM users WHERE id = {}".format(uid))
    session.raw("SELECT * FROM users WHERE role = '%s'" % role)
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_python_file(target)
    sqli = [f for f in findings if f.rule_id == "VERITY-AST-CWE-89-SQLI"]
    assert len(sqli) == 3
    assert all(f.cwe_id == "CWE-89" for f in sqli)


def test_cwe89_sqli_parameterized(tmp_path: Path) -> None:
    """AC-39.3: Parameterized SQL with Constant strings and constant-only f-strings stays clean."""
    target = tmp_path / "sqli_safe.py"
    target.write_text(
        """
def query_users_safe(cursor, connection, session, uid: int):
    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))
    cursor.executemany("INSERT INTO logs (id) VALUES (?)", [(uid,)])
    connection.execute("SELECT 1")
    session.text("SELECT * FROM items WHERE id = :id")
    session.raw(f"SELECT {'1'}")
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_python_file(target)
    sqli = [f for f in findings if f.rule_id == "VERITY-AST-CWE-89-SQLI"]
    assert sqli == []


def test_cwe862_bola_flagged(tmp_path: Path) -> None:
    """AC-39.4: Tenant-less record ID lookup in MCP tool is flagged without synthetic markers."""
    source_text = _PYTHON_AST_PATH.read_text(encoding="utf-8")
    assert "bola_violation" not in source_text
    assert "is_cross_tenant" not in source_text

    target = tmp_path / "bola_vuln.py"
    target.write_text(
        """
@mcp.tool()
def get_invoice(invoice_id: str, repo) -> dict:
    return repo.get_record(invoice_id)
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_python_file(target)
    bola = [f for f in findings if f.rule_id == "VERITY-AST-CWE-862-BOLA"]
    assert len(bola) >= 1
    assert bola[0].cwe_id == "CWE-862"


def test_cwe862_bola_defended(tmp_path: Path) -> None:
    """AC-39.4: Record ID lookups with tenant/ownership checks or auth guards stay clean."""
    target = tmp_path / "bola_safe.py"
    target.write_text(
        """
@mcp.tool()
def get_invoice_checked(invoice_id: str, session_tenant: str, repo) -> dict:
    record = repo.get_record(invoice_id)
    if record.tenant_id != session_tenant:
        raise PermissionError("Forbidden")
    return record

@mcp.tool()
def fetch_order_guarded(order_id: str, current_user: str, session) -> dict:
    authorize(current_user, order_id)
    return session.fetch_order(order_id)
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_python_file(target)
    bola = [f for f in findings if f.rule_id == "VERITY-AST-CWE-862-BOLA"]
    assert bola == []
