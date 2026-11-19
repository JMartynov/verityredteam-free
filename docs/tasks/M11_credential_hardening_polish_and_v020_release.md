# M11: Credential Detection Hardening, Packaging/Display Polish & `v0.2.0` PyPI Release

- **Task ID**: `M11`
- **Priority**: `P0`
- **Status**: `In Progress`
- **Dependencies**: `M7`, `M8`, `M9`, `M10`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

Following Wave 2 completion (`M7`–`M10`), three follow-up items remain to finalize the `v0.2.0` PyPI release and close edge cases discovered during smoke testing:

1. **Credential Detection Hardening**:
   - `ConsolidatedSecurityAuditor.audit_server()` (`src/verity/discovery/auditor.py`) currently only checks `MultiClientConfigScanner.SECRET_KEY_PATTERNS` on env variable names.
   - As observed during `M7` smoke checks, embedded DSN credentials (e.g., `DATABASE_URL=postgres://admin:SuperSecretPass999@db.internal:5432/prod`) and secret-format tokens (`SECRET_VALUE_PATTERNS`, e.g., `sk-...`, `ghp_...`, `eyJ...`) under arbitrary env keys such as `CUSTOM_FIELD` are not flagged by `audit_server()` yet.
   - Safe placeholder references such as `postgres://admin:${DB_PASS}@db.internal:5432/prod` or `${OPENAI_API_KEY}` must remain exempt even when those variables are exported in `os.environ`.
2. **Packaging & Terminal Display Polish**:
   - `uv build` prints `SetuptoolsDeprecationWarning` because `pyproject.toml` still specifies `license = { text = "Apache-2.0" }` instead of SPDX `license = "Apache-2.0"` with `setuptools>=77.0.0`.
   - `src/verity/reporting/terminal.py` wraps/ellipsizes long rule IDs (`SEC-STATIC-UNSAFE-SHELL-WR…`) in `render_scan_terminal()` because the `Rule` column lacks `no_wrap=True`.
   - Bump package version from `0.1.0` to `0.2.0` in `pyproject.toml` and `src/verity/__init__.py`.
3. **PyPI `v0.2.0` Publish & Live Cold-Install E2E Verification**:
   - Push `main` (`M7`–`M11`) and tag `v0.2.0` to trigger `.github/workflows/workflow.yaml` (PyPI Trusted Publishing).
   - Run `INSTALL_SOURCE=pypi ./tests/e2e_containers/run_e2e.sh` across all 4 clean Docker containers to verify live PyPI `pip` and `uvx` installation from scratch.

---

## 2. Requirements & Target Files

- **`pyproject.toml` & `src/verity/__init__.py`**:
  - Update `[build-system].requires` to `["setuptools>=77.0.0"]`, `version = "0.2.0"`, and `license = "Apache-2.0"`.
  - Update `__version__ = "0.2.0"`.
- **`src/verity/discovery/config_scanner.py`**:
  - Add `DSN_CREDENTIAL_PATTERN` on `MultiClientConfigScanner` (`postgres`/`postgresql`/`mysql`/`mariadb`/`mongodb`/`mongodb+srv`/`redis`/`rediss`/`amqp`/`amqps`/`mssql`/`snowflake`/`http`/`https` with `user:pass@`).
  - Add `@classmethod def is_secret_env_entry(cls, key: str, raw_value: Any) -> bool` handling `SECRET_KEY_PATTERNS`, `SECRET_VALUE_PATTERNS`, and `DSN_CREDENTIAL_PATTERN` while exempting `${...}` / `$...` env references (including `${VAR}` in the DSN password segment).
- **`src/verity/discovery/auditor.py`**:
  - Use `MultiClientConfigScanner.is_secret_env_entry(k, raw_text)` in `audit_server()`.
- **`src/verity/cli.py`**:
  - Use `MultiClientConfigScanner.is_secret_env_entry()` and also extract DSN password group `dsn_match.group(1)` into the `secrets` scrub list in `_collect_config_findings()` so neither the full DSN nor embedded password leaks in any report format.
- **`src/verity/reporting/terminal.py`**:
  - Set `table.add_column("Rule", no_wrap=True)` in `render_scan_terminal()`.
- **`tests/unit/test_cli_auditor_parity.py` & `tests/unit/test_cli_and_reporting.py`**:
  - Assert full un-ellipsized `"SEC-STATIC-SECRET-IN-CONFIG"` in terminal mode (`no_wrap=True`).
  - Assert parametrized across `["terminal", "json", "markdown", "html"]` that `DATABASE_URL` DSN credentials and `CUSTOM_FIELD: sk-...` are caught and scrubbed with zero leaks, while `postgres://admin:${DB_PASS}@...` is not flagged.
  - Assert `verity.__version__ == "0.2.0"`.

---

## 3. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv sync --extra dev
uv run ruff check src tests
uv run pytest tests/ -q
uv build
git push origin main && git tag -a v0.2.0 -m "Release v0.2.0" && git push origin v0.2.0
INSTALL_SOURCE=pypi ./tests/e2e_containers/run_e2e.sh
```

---

## 4. Acceptance Criteria

- [ ] `MultiClientConfigScanner.is_secret_env_entry()` detects plaintext key patterns, `SECRET_VALUE_PATTERNS` under arbitrary keys, and DSN credential URLs while ignoring `${VAR}` references (including `${DB_PASS}` inside DSN URLs).
- [ ] Neither full DSN values nor embedded passwords leak in `terminal`, `json`, `markdown`, or `html` outputs.
- [ ] `terminal.py` renders full rule IDs (`no_wrap=True`), and `uv build` produces `0.2.0` wheel/sdist with zero `SetuptoolsDeprecationWarning`.
- [ ] Both `verityredteam-free` unit tests (`ruff` + `pytest`) and `verityredteam` Pro MCP agent tests (`17/17`) pass cleanly.
- [ ] Tag `v0.2.0` publishes `verity-redteam-core==0.2.0` to PyPI and `INSTALL_SOURCE=pypi ./tests/e2e_containers/run_e2e.sh` passes across all 4 clean containers.
