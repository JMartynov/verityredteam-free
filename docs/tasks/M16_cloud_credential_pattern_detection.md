# M16: Detect AWS `AKIA…` Keys, PEM Private Keys & Cloud Tokens in MCP Config Values

- **Task ID**: `M16`
- **Priority**: `P2` (Master Rank `#5`, Track A — Product & Customer Value)
- **Status**: `Todo`
- **Dependencies**: `M7`, `M11`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

`MultiClientConfigScanner` (`src/verity/discovery/config_scanner.py`) flags plaintext secrets in MCP `env` blocks via:
- `SECRET_KEY_PATTERNS` (`api_key|secret|token|password|bearer|auth|jwt|private_key`) — does **not** match `AWS_ACCESS_KEY_ID`.
- `SECRET_VALUE_PATTERNS` — only `sk-…`, `ghp_…`, `eyJ…`.

`StaticRuleEvaluator` (`src/verity/scanner/static_rules.py`, `VERITY-STATIC-CREDENTIAL-HARVESTING`) already detects `AKIA[0-9A-Z]{16}` and `-----BEGIN (RSA |OPENSSH |EC |DSA |…)PRIVATE KEY-----`, but those shapes are not shared with config scanning. Result: `"AWS_ACCESS_KEY_ID": "AKIA…"` or a PEM key under a generic env name is neither flagged as `SEC-STATIC-SECRET-IN-CONFIG` nor redacted by `_scrub_secrets()`.

---

## 2. Requirements & Target Files

1. **Shared Credential Shape Registry**: Define one shared tuple of credential value patterns (e.g. `src/verity/scanner/credential_patterns.py`) reused by `config_scanner.py` and (optionally) `static_rules.py`, covering at minimum:
   - AWS access key IDs `\b(AKIA|ASIA)[0-9A-Z]{16}\b`
   - PEM private key headers `-----BEGIN (RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----`
   - Slack tokens `xox[baprs]-[A-Za-z0-9-]{10,}`
   - Google API keys `AIza[0-9A-Za-z_-]{35}`
   - Existing `sk-`, `ghp_` / `github_pat_`, `eyJ` JWT shapes
2. **Key Name Coverage**: Extend `SECRET_KEY_PATTERNS` to include `access[_-]?key`, `aws_secret`, `credential(s)`, `client[_-]?secret`.
3. **Scrubbing**: Ensure `_collect_config_findings()` / `_scrub_secrets()` (`src/verity/cli.py`) redacts the full matched values (including multi-line PEM blocks) to `****` in all report formats.
4. **Exemptions**: `${AWS_ACCESS_KEY_ID}` / `$VAR` references and obvious placeholders remain unflagged.

---

## 3. Automated Tests to Verify (`tests/unit/test_credential_patterns.py`)

1. `AWS_ACCESS_KEY_ID: AKIA…` and `AWS_SECRET_ACCESS_KEY: <40 chars>` → flagged `SEC-STATIC-SECRET-IN-CONFIG`, raw values absent from `terminal`/`json`/`markdown`/`html` output (parametrized).
2. `CUSTOM_FIELD: AKIA…` (non-secret key name) → flagged via value pattern.
3. `TLS_KEY: "-----BEGIN RSA PRIVATE KEY-----\n…"` → flagged and fully scrubbed.
4. Slack `xoxb-…` and Google `AIza…` values → flagged.
5. `${AWS_ACCESS_KEY_ID}` and `$AWS_SECRET_ACCESS_KEY` → **not** flagged.
6. Benign values (`AWS_REGION: us-east-1`, `LOG_LEVEL: debug`) → **not** flagged (zero false positives).
7. Parity test: every value shape in the shared registry is detected by both `MultiClientConfigScanner.is_secret_env_entry()` and `StaticRuleEvaluator` (no drift).

---

## 4. Acceptance Scenario in Clean Container with Real MCP Server Config

Extend `tests/e2e_containers/verify_all_scenarios.sh` Scenario 1:
1. Add to the generated `~/.cursor/mcp.json` a real MCP server entry (official `@modelcontextprotocol/server-aws-kb-retrieval` or equivalent via `npx -y …`) with:
   - `AWS_ACCESS_KEY_ID: AKIAVERITYE2ETEST0001` (fake, format-valid)
   - `AWS_SECRET_ACCESS_KEY: verityE2eFakeSecretKey0000000000000000000`
   - `PRIVATE_KEY_PEM: "-----BEGIN RSA PRIVATE KEY-----\nMIIVerityFake…\n-----END RSA PRIVATE KEY-----"`
   - plus a safe twin server using `${AWS_ACCESS_KEY_ID}` references.
2. Add those raw values to the `SECRETS=( … )` leak-scan array.
3. Run:
   ```bash
   verity scan --config-file "$HOME/.cursor/mcp.json" --format json --output /tmp/out/aws_scan.json --fail-on-findings
   verity scan --format markdown --output /tmp/out/aws_scan.md
   ```
4. **Assertions**: exit `1`; `SEC-STATIC-SECRET-IN-CONFIG` reported for all three keys with `****` evidence; safe twin produces zero secret findings; `scan_for_leaks` finds no raw AWS/PEM values in any output or exported snapshot; full `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh` passes.

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/unit/test_credential_patterns.py -v
uv run pytest tests/
INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] AWS (`AKIA`/`ASIA` + secret key), PEM private keys, Slack and Google API tokens in MCP config values are flagged as `SEC-STATIC-SECRET-IN-CONFIG` regardless of env key name.
- [ ] All matched values are redacted to `****` in every report format; `${VAR}` references and benign values produce zero findings.
- [ ] A single shared credential pattern registry prevents drift between config scanning and static rules.
- [ ] `tests/unit/test_credential_patterns.py`, full `pytest tests/`, `ruff check src tests`, and the container E2E scenario pass cleanly.
