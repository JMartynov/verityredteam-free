# Auxiliary & Benchmark Appendix (Tier 3 & Tier 4)

!!! warning "Not part of the primary product core"
    The 23 capabilities catalogued on this page — **11 Tier 3 secondary
    utilities** and **12 Tier 4 internal QA / regression harnesses** — are
    **not** part of the primary Tier 1 / Tier 2 customer product core.
    They are documented here only so the inventory stays honest: they are
    optional utilities or internal QA / regression proof harnesses.

## Why this appendix exists

The customer-facing narrative lives in the [documentation home](../index.md)
(Tier 1 and Tier 2) and in the
[Verity Pro Enterprise Features](../pro/enterprise_features.md) page.
Everything a customer is expected to install, run, and depend on day to
day is described there.

This appendix covers the remaining surface area, split into two groups:

- **Tier 3 — optional utilities.** Secondary helpers that are useful in
  narrow situations (schema linting, SBOM export, community threat feeds)
  but must never be pitched as the core security engine.
- **Tier 4 — internal QA / regression harnesses.** Fixtures, mocks,
  synthetic oracles, and legacy interactive shells whose real job is to
  prove the engine works, not to serve customers directly.

!!! note "Scores are inventory ranks, not product promises"
    A high score means the capability is worth keeping somewhere. It does
    **not** mean the capability belongs in the primary product story.

## How to read the tables

Both tables below use the same six columns.

| Column | Meaning |
| --- | --- |
| Rank | Overall usefulness rank in the feature inventory |
| Tier | Tier 3 (optional utility) or Tier 4 (internal QA harness) |
| Feature Name | Capability name plus the CLI command or class |
| Repo | Repository that ships the capability |
| Score | Composite usefulness score from the inventory |
| Disposition / Action | The decision we record for the capability |

## Tier 3 — Optional Utilities (Ranks 26-36)

| Rank | Tier | Feature Name | Repo | Score | Disposition / Action |
| --- | --- | --- | --- | --- | --- |
| 26 | Tier 3 | MCP Readiness Linter & OWASP Scorer (lint) | mcp-vulnerabilities | 6.30 | Keep as optional schema linter; do not pitch as core security engine. |
| 27 | Tier 3 | Static Web Portals & Webhook Notifier (notifier.py) | mcp-vulnerabilities | 6.25 | Keep for community GitHub Pages threat feed only. |
| 28 | Tier 3 | Headless REST API & Loopback Browser Bridge (bridge) | mcp-vulnerabilities | 6.00 | Keep as optional helper for GitHub Pages portal. |
| 29 | Tier 3 | BK-Tree Typosquatted Package Detector (audit-typosquat) | mcp-vulnerabilities | 5.78 | Fold quietly into verity scan; de-emphasize standalone CLI command. |
| 30 | Tier 3 | CycloneDX v1.5 & SPDX v2.3 SBOM Exporters (export-sbom) | Fingerprints / Vulns | 5.75 | Keep as secondary compliance export. |
| 31 | Tier 3 | Semantic Embedding Search (search --semantic) | mcp-fingerprints | 5.45 | Keep in optional [semantic] extra only. |
| 32 | Tier 3 | Binary Malware SHA-256 & VirusTotal Scanner (scan-binaries) | mcp-vulnerabilities | 5.00 | De-emphasize (requires user VT API key or custom blocklist). |
| 33 | Tier 3 | Trivy Container Wrapper (TrivyScanner) | mcp-vulnerabilities | 4.53 | Internal helper only (requires external trivy binary). |
| 34 | Tier 3 | Background 5,800-Port Monitoring Daemon (monitor) | mcp-vulnerabilities | 4.33 | De-emphasize (Unix-only os.fork, noisy 5,801-port sweep). |
| 35 | Tier 3 | Ephemeral DuckDB / SQLite Engine (EphemeralDBEngine) | mcp-fingerprints | 4.33 | Internal SDK helper; keep out of primary user docs. |
| 36 | Tier 3 | Deep Zero-Tool Repo Auditor & Monorepo Prober | mcp-fingerprints | 4.13 | Internal catalog-harvesting script. |

## Tier 4 — Internal QA & Regression Harnesses (Ranks 37-48)

| Rank | Tier | Feature Name | Repo | Score | Disposition / Action |
| --- | --- | --- | --- | --- | --- |
| 37 | Tier 4 | VAIB Applicability Engine, Exploit Bridge & Onboarding FSM | Pro + Free | 4.48 | Internal state helpers; keep out of primary marketing. |
| 38 | Tier 4 | Interactive Hub, Curses TUI & Setup Wizard (`init`, `~/.mcp_fingerprints.toml`) | Fingerprints / Vulns | 3.85 | Internal/legacy interactive shell; keep out of core docs. |
| 39 | Tier 4 | Hardcoded F-String Guard Templates (generate_guard_patch) | Free + Pro | 3.80 | Position honestly as Guard Snippet Generator. |
| 40 | Tier 4 | Sandboxed Live Probers (`python:3.12-slim` / Incus) | mcp-vulnerabilities | 3.50 | Internal sandbox runner; requires local container runtime. |
| 41 | Tier 4 | Config Auto-Fixer & PR Bot (fix, remediate-pr) | mcp-vulnerabilities | 3.45 | Secondary experimental PR helper; keep out of primary core. |
| 42 | Tier 4 | Sigstore Keyless Feed Attestation (verify-feed) | mcp-vulnerabilities | 3.40 | Optional verification utility with deterministic `sha256-manifest` fallback when `sigstore` is absent. |
| 43 | Tier 4 | Hardcoded Socratic Payloads & Configurable `PolicyGatekeeper` | Pro (hacking/*) | 3.25 | Internal benchmark/red-team fixtures; `PolicyGatekeeper(allowed_tenants=())` defaults to opt-in tenancy, and `get_deterministic_plan()` synthesizes schema-driven plans for unregistered servers. |
| 44 | Tier 4 | Hardcoded 7-Branch AIVSS v1.0 CWE Lookup Table | Pro (reporting/) | 3.03 | Optional reporting metadata; not primary OSV severity. |
| 45 | Tier 4 | `ReadOnlySafetyGuard` & `DualPathRouter` Helpers | Free (scanner/) | 2.93 | Internal demo/probe helpers; `ReadOnlySafetyGuard` blocks `run_sql`/`execute_sql`/`upsert`/`post_`/`put_`/`patch_`/`chmod`/`kill`, and `DualPathRouter` uses schema-driven skeletons (`NEEDS_ARGS` when unsafe); prefer `SqlSecurityGuard` for SQL AST guarding. |
| 46 | Tier 4 | 51 Synthetic JSON-Flag Database Verification Oracles & `ControlledPenetrationEngine` | Pro (oracles/*, penetration/) | 2.18 | Reposition strictly as **Internal Benchmark & Regression Verification Infrastructure**; `ControlledPenetrationEngine` verifies rollback via `try/finally` and `DatabaseStateVerifier` fails closed (`allow_synthetic_fallback=False`). |
| 47 | Tier 4 | 32-Server VAIB Docker Lab & In-Memory Snowflake Cloud Mocks | Pro (fixtures/*) | 1.95 | Reposition strictly as **Internal Benchmark & Regression Verification Infrastructure** (not a customer-facing operating mode). |
| 48 | Tier 4 | Tool Collision Resolver (resolve-config --strategy prefix) | mcp-vulnerabilities | 1.70 | Legacy CLI flag (`MCP_PREFIX_<TOOL>` env namespacing); do not recommend in customer workflows. |

## Tier 3 optional-utilities guidance

Tier 3 helpers are shipped, supported, and documented, but they are not
the reason a customer adopts Verity. Use them when they fit:

- **Schema linting.** The readiness linter is a design-time aid. Run it on
  a new MCP server to catch weak tool schemas before release.
- **Compliance export.** The CycloneDX and SPDX exporters turn an existing
  scan result into a secondary SBOM artefact.
- **Community feeds.** The notifier and static portal exist to publish a
  public threat feed, not to scan customer environments.
- **Optional extras.** Semantic search stays behind the optional
  ``[semantic]`` install extra and never becomes a hard dependency.

Three Tier 3 entries are deliberately de-emphasised. The binary scanner
depends on an external VirusTotal key or custom blocklist, the container
scanner needs a local Trivy binary, and the port-monitoring daemon relies
on Unix-only ``os.fork`` while performing a noisy 5,801-port sweep. They
remain in the code base for internal and power-user use, but the primary
CLI surface never advertises them. The typosquat detector is folded
quietly into ``verity scan`` rather than shipped as a separate command.

The internal-only helpers — the Trivy wrapper, the ephemeral DuckDB /
SQLite engine, and the deep zero-tool repo auditor — stay outside the
primary user documentation because they either require external tooling
or exist solely to seed the fingerprint catalog.

## Tier 4 internal QA & regression harness boundaries

Tier 4 capabilities are proof infrastructure. They exist so the engine can
be regression-tested deterministically, and they deliberately carry
boundaries that make them unsuitable as customer features:

1. **Fixtures over inputs.** The synthetic oracles, Docker lab, and
   in-memory cloud mocks respond to fixed JSON flags. They validate the
   scanner; they do not scan anything real.
2. **Hardcoded payloads.** The Socratic payload bank and the AIVSS CWE
   lookup table are fixtures, not live intelligence.
3. **Legacy shells.** The interactive hub, the curses TUI, and the setup
   wizard predate the scriptable CLI and are kept for internal
   experimentation only.
4. **Environment coupling.** The sandbox probe runner needs a local
   container runtime, and the Sigstore attestation path needs the optional
   ``sigstore`` extra.

When a Tier 4 helper proves broadly useful, the correct move is to promote
a narrow, well-tested slice of it into Tier 1 or Tier 2 — never to
re-label the harness itself as a customer feature.

The two guard-related entries and Wave 4 benchmark decoupling deserve a specific note:

- **Internal Benchmark & Regression Verification Infrastructure (Pro).** The 32-server VAIB Docker lab, the 51 DB scenario oracles, and `ControlledPenetrationEngine` are **Internal Benchmark & Regression Verification Infrastructure** used for CI and engineering QA — not the primary customer operating mode.
- **Fail-closed Pro verification & rollback.** `DatabaseStateVerifier.verify_mongodb_cross_tenant_isolation(allow_synthetic_fallback=False)` fails closed when MongoDB is unreachable instead of reporting synthetic fixture passes (emitting a `[SYNTHETIC]`-prefixed reason only when `allow_synthetic_fallback=True`), and `ControlledPenetrationEngine` executes attack and rollback inside `try/finally` so `rollback_confirmed` is `True` only after rollback and post-rollback baseline verification succeed (`details["rollback_error"]` is recorded on failure).
- **Configurable tenancy & schema-driven plans (Pro).** `PolicyGatekeeper(allowed_tenants=())` defaults to an empty allowlist so production targets are not rejected for lacking synthetic lab tenant names, while `get_deterministic_plan()` synthesizes neutral schema-driven proposals from `McpServerSpec` tool schemas for unregistered servers instead of falling back to `CUSTOMER_CRUD_PLAN`.
- **Hardened `ReadOnlySafetyGuard` & decoupled `DualPathRouter` (Free).** `ReadOnlySafetyGuard` extends destructive-verb coverage to block `run_sql`, `execute_sql`, `upsert`, `post_`, `put_`, `patch_`, `chmod`, and `kill` (using boundary matching for `post_`, `put_`, and `patch_`), while `DualPathRouter` removes the hardcoded `"formula": "1 + 1"` payload in favor of a neutral schema-driven required-argument skeleton (surfacing `NEEDS_ARGS` when a required parameter cannot be synthesized safely and preserving caller-supplied arguments verbatim). Real SQL deployments should still use `SqlSecurityGuard`, and the hardcoded f-string guard templates are honest only when described as a **Guard Snippet Generator**.

## Disposition summary

| Disposition | Count | Meaning |
| --- | --- | --- |
| Keep as optional utility or repositioned helper | 8 | Ship and support, but outside the primary product story. |
| Internal helper or QA harness only | 10 | Stay in the QA tree; never documented as customer features. |
| De-emphasise | 5 | Still shipped, removed from the primary CLI narrative. |

## Scope discipline

Tier 3 and Tier 4 exist so the primary docs stay honest. When a new
capability is added to the code base, the first question is not "does it
work?" but "which tier does it belong to?". A capability that only proves
the engine works belongs in Tier 4. A capability that a customer uses
occasionally belongs in Tier 3. Only capabilities a customer depends on
day to day belong in Tier 1 or Tier 2.

This discipline keeps three promises:

1. **A small, honest primary story.** Customers see only what they need.
2. **A complete, auditable inventory.** Nothing disappears from the docs.
3. **A stable extension path.** Power users can still reach the extras.

## Relationship to the rest of the documentation

- [Documentation home](../index.md) — Tier 1 and Tier 2 capabilities, the
  two tiers customers are actually sold.
- [Verity Pro Enterprise Features](../pro/enterprise_features.md) — the
  commercial capability matrix and graceful degradation contract.
- [Rule catalog](../rules/catalog.md) — the 22 security rules the engine
  emits, generated from the live code.
- [Task changelog](../changelog/tasks.md) — the engineering ledger that
  records when a Tier 3 or Tier 4 capability was repositioned.

## Frequently asked questions

**Is a Tier 3 utility unsupported?** No. Tier 3 utilities are supported
and documented; they are simply not part of the primary product story.

**Can I depend on a Tier 4 harness in CI?** Only inside the Verity QA
pipeline. Tier 4 harnesses are pinned to internal fixtures and may change
without a customer-facing deprecation cycle.

**Why keep anything at score 1.70?** Because removing working code costs
more than documenting it honestly. The tool collision resolver stays for
reproducibility of historical scans.

**Where do new capabilities land?** New customer capabilities land in
Tier 1 or Tier 2. Anything that only proves the engine works lands in
Tier 4 and never appears on the homepage.

## Maintenance notes

- This page is hand-authored and **not** generated by
  ``scripts/build_docs_portal.py``.
- The inventory scores are copied from the internal feature audit and must
  be updated together with any disposition change.
- Adding a row requires updating the disposition summary counts above.
- Any new Tier 3 or Tier 4 capability must be listed here *before* it is
  mentioned in the primary documentation.

## Appendix: full rank index

| Rank | Tier | Short name |
| --- | --- | --- |
| 26 | Tier 3 | MCP Readiness Linter & OWASP Scorer |
| 27 | Tier 3 | Static Web Portals & Webhook Notifier |
| 28 | Tier 3 | Headless REST API & Loopback Browser Bridge |
| 29 | Tier 3 | BK-Tree Typosquatted Package Detector |
| 30 | Tier 3 | CycloneDX & SPDX SBOM Exporters |
| 31 | Tier 3 | Semantic Embedding Search |
| 32 | Tier 3 | Binary Malware & VirusTotal Scanner |
| 33 | Tier 3 | Trivy Container Wrapper |
| 34 | Tier 3 | Background Port Monitoring Daemon |
| 35 | Tier 3 | Ephemeral DuckDB / SQLite Engine |
| 36 | Tier 3 | Deep Zero-Tool Repo Auditor |
| 37 | Tier 4 | VAIB Applicability Engine & Onboarding FSM |
| 38 | Tier 4 | Interactive Hub, Curses TUI & Setup Wizard |
| 39 | Tier 4 | Hardcoded F-String Guard Templates |
| 40 | Tier 4 | Sandboxed Live Probers |
| 41 | Tier 4 | Config Auto-Fixer & PR Bot |
| 42 | Tier 4 | Sigstore Keyless Feed Attestation |
| 43 | Tier 4 | Hardcoded Socratic Payloads |
| 44 | Tier 4 | AIVSS v1.0 CWE Lookup Table |
| 45 | Tier 4 | ReadOnlySafetyGuard & DualPathRouter |
| 46 | Tier 4 | Synthetic JSON-Flag Database Oracles |
| 47 | Tier 4 | Docker Lab & Cloud Mocks |
| 48 | Tier 4 | Tool Collision Resolver |
