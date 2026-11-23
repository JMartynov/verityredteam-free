# Extensibility & Plugin Architecture

`verity-redteam-core` (Verity RedTeam Free) is the single source of the runtime
abstraction barrier. Optional enterprise capabilities ship in a separate `verity-pro`
distribution and are discovered dynamically through Python entry points — no core code is
patched or branched.

## Runtime abstraction barrier

The core enumerates plugins registered under the `verity.plugins` entry-point group:

```python
from importlib.metadata import entry_points

for ep in entry_points(group="verity.plugins"):
    ep.load()
```

## Registering a plugin package

A plugin package registers itself in its own `pyproject.toml`:

```toml
[project.entry-points."verity.plugins"]
enterprise = "verity_pro.plugin:register_pro_extensions"
```

## Graceful degradation contract

When no plugin is installed, Pro-only actions (for example SARIF export or Snowflake RBAC
guards) return a structured `PRO_FEATURE_REQUIRED` payload instead of raising
`ImportError`. This guarantees that `verity-redteam-core` always runs completely
standalone:

```json
{
  "status": "PRO_FEATURE_REQUIRED",
  "feature": "export_sarif",
  "message": "SARIF v2.1.0 compliance export requires the verity-pro plugin."
}
```

Install the core package and use it without any plugin:

```bash
pip install verity-redteam-core
verity scan
```

## Choosing an extension point

The core exposes three independent seams. Pick the one that matches the fidelity you
need — from cheapest (pure regex over metadata) to deepest (parsed Python control flow).

| Goal | Public seam | Primary object |
| --- | --- | --- |
| Flag hostile MCP metadata, prompts, or resources | `StaticRuleEvaluator(custom_rules=[...])` | `StaticRule` |
| Inspect MCP handler source code | subclass `McpAstVisitor` | `AstFinding` |
| Constrain SQL execution and row visibility | subclass `SqlSecurityGuard` | `SqlSecurityError` |

None of these seams requires patching `verity-redteam-core`. They are ordinary Python
classes in `verity.scanner.static_rules`, `verity.scanner.python_ast`, and
`verity.mcp_library.sql_guard`, and they are designed to be composed by the caller.

## Tutorial 1: Custom static configuration rules

`StaticRuleEvaluator` ships a curated set of `DEFAULT_RULES`. A custom rule is simply a
`StaticRule` instance appended through the `custom_rules` constructor argument; custom
rules evaluate alongside the defaults with the same precedence rules.

### 1.1 Define the rule

The following policy rejects package install instructions that point away from the
corporate registry:

```python
import re

from verity.scanner.models import ScannerSeverity
from verity.scanner.static_rules import StaticRule, StaticRuleEvaluator

CUSTOM_REGISTRY_RULE = StaticRule(
    rule_id="CUSTOM-STATIC-001",
    category="SUPPLY_CHAIN",
    cwe_id="CWE-829",
    severity=ScannerSeverity.HIGH,
    title="Non-approved internal package registry",
    description=(
        "MCP tool metadata directs package resolution at a registry that is "
        "not on the corporate allowlist."
    ),
    patterns=(
        re.compile(
            r"https?://(?!packages\.corp\.internal)[a-z0-9.\-]+/simple/?",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bpip\s+install\s+--index-url\s+"
            r"https?://(?!packages\.corp\.internal)\S+",
            re.IGNORECASE,
        ),
    ),
    remediation="Point installs at https://packages.corp.internal/simple.",
)

evaluator = StaticRuleEvaluator(custom_rules=[CUSTOM_REGISTRY_RULE])
```

Rules are safer as module-level constants: `patterns` is a tuple of pre-compiled
`re.Pattern` objects, so compilation happens once per process rather than per scan.

### 1.2 Evaluate a definition

`scan_all()` walks tools, prompts, and resources in one pass. Each field is scanned
independently, and at most one finding per rule per field is emitted:

```python
tool = {
    "name": "install_dependency",
    "description": (
        "Runs pip install --index-url https://pypi.org/simple for the caller."
    ),
    "inputSchema": {"properties": {"package": {"type": "string"}}},
}

result = evaluator.scan_all(tools=[tool])

print(result.has_findings)      # True
print(result.high_count)        # 1
print(result.critical_count)    # 0
```

### 1.3 Read the structured result

`StaticScanResult.to_dict()` is the wire format consumed by reporting layers:

```python
payload = result.to_dict()

payload["summary"]["total_findings"]        # 1
payload["findings"][0]["rule_id"]           # 'CUSTOM-STATIC-001'
payload["findings"][0]["target_type"]       # 'tool'
payload["findings"][0]["target_name"]       # 'install_dependency'
payload["findings"][0]["field_path"]        # 'description'
```

The `summary` block always carries `total_findings`, per-severity counts,
`scanned_tools`, `scanned_prompts`, `scanned_resources`, and `duration_ms`. The
`duration_ms` value is wall-clock timing and therefore differs on every run.

### 1.4 Fields that are scanned

For a tool, the evaluator inspects `name`, `description`, every
`inputSchema.properties.<name>.description`, and every
`inputSchema.properties.<name>.default`. Prompts are scanned on `name`, `description`,
each argument description, and each `messages[i].content`. Resources are scanned on
`uri` and `description`.

### 1.5 Authoring guidance

- Prefix custom ids (`CUSTOM-…`) so they are distinguishable from shipped rules.
- Keep `patterns` narrow; every pattern runs against every scanned field.
- Set `suppress_on_templates=True` when a rule should ignore documentation snippets
  containing `YOUR_API_KEY`, `REPLACE_WITH`, `.example`, `.sample`, or `.template`.
- Normalization and zero-width stripping are applied before matching, so patterns do
  not need to handle homoglyph or `\u200b` evasion themselves.
- The evaluator is stateless after construction; reuse one instance per process.

## Tutorial 2: Custom Python AST visitors

Static rules never see source code. When a policy depends on *how* a handler is
implemented — which sink is called, which arguments flow into it — extend
`McpAstVisitor`.

### 2.1 Subclass the visitor

The stock visitor matches `pickle.loads` by attribute chain. A handler that imports
`pickle as p` therefore escapes it. The subclass below resolves import aliases recorded
during traversal and reuses the shipped catalog rule so reports stay consistent:

```python
import ast

from verity.scanner.python_ast import McpAstVisitor
from verity.scanner.rules import RuleCatalog


class AliasedDeserializationVisitor(McpAstVisitor):
    """Catch insecure deserialization hidden behind an import alias."""

    SINKS = frozenset({"loads", "load"})
    MODULES = frozenset({"pickle", "_pickle", "marshal"})

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            root = func.value.id
            origin = self.imports.get(root, root)
            if origin in self.MODULES and func.attr in self.SINKS:
                self._add_finding(
                    RuleCatalog.RULE_CWE_502_PICKLE,
                    node,
                    "Aliased insecure deserialization via "
                    f"'{root}.{func.attr}' (imported as '{origin}').",
                )
        super().visit_Call(node)
```

`self.imports` maps local aliases to their origin module for both `import x as y` and
`from m import x as y`. `self._add_finding(rule, node, message)` is the protected helper
the base class uses internally; it records file, line, column, snippet, and the current
MCP tool context.

### 2.2 Invoke the visitor

`scan_python_file()` constructs the stock `McpAstVisitor` internally and offers no
substitution hook, so custom visitors are driven directly by the caller:

```python
source = """
import pickle as p

def tool_restore(payload):
    return p.loads(payload)
"""

visitor = AliasedDeserializationVisitor(
    file_path="custom_server.py",
    source_code=source,
)
visitor.visit(ast.parse(source))
```

### 2.3 Interpret findings

```python
for finding in visitor.findings:
    print(f"{finding.rule_id} line={finding.line_number}")
    print(finding.message)
    print(finding.snippet)
    print(finding.mcp_tool_context)
```

```text
VERITY-AST-CWE-502-PICKLE line=5
Aliased insecure deserialization via 'p.loads' (imported as 'pickle').
    return p.loads(payload)
tool_restore
```

The parent's `visit_FunctionDef` marks handlers named `tool_*`, containing `handle_`, or
literally named `call` / `execute_tool` as tool context, so `mcp_tool_context` is
populated without extra work.

### 2.4 Composing with the shipped scan

Run `scan_python_file(path)` for baseline coverage, then append your visitor's findings:

```python
from verity.scanner.python_ast import scan_python_file

findings = list(scan_python_file("custom_server.py"))
findings.extend(visitor.findings)
```

Both paths return `AstFinding` objects from `verity.scanner.models`, so downstream
formatters treat them identically. Note that `scan_python_file()` swallows
`SyntaxError` and unreadable files by returning `[]`; if a companion visitor must run,
parse the file yourself and handle failures explicitly.

### 2.5 Authoring guidance

- Call `super().visit_Call(node)` so stock detections keep firing.
- Override `visit_FunctionDef` / `visit_AsyncFunctionDef` only if you need to *suppress*
  or *retarget* findings inside specific scopes.
- Emit findings against an existing `RuleCatalog` constant where possible; novel
  behaviours deserve their own `CUSTOM-AST-…` id and a `RuleDefinition`.
- Prefer AST checks over regex when the discriminator is an argument name, keyword
  value, or call target.

## Tutorial 3: Extending SqlSecurityGuard

`SqlSecurityGuard` is a collection of classmethods. Custom policy is expressed by
subclassing and overriding the relevant guard, which keeps call sites unchanged.

### 3.1 Forbidden-table policy

```python
import re

from verity.mcp_library.sql_guard import SqlSecurityError, SqlSecurityGuard


class CorpSqlGuard(SqlSecurityGuard):
    FORBIDDEN_TABLES = frozenset({"payroll", "secrets", "audit_log"})

    @classmethod
    def validate_parameterized_query(cls, query, params=None, dialect="postgres"):
        super().validate_parameterized_query(query, params, dialect)
        lowered = query.lower()
        for table in cls.FORBIDDEN_TABLES:
            if re.search(rf"\b{re.escape(table)}\b", lowered):
                raise SqlSecurityError(
                    f"Table '{table}' is outside the approved data domain.",
                    rule_id="CUSTOM-FORBIDDEN-TABLE",
                )
```

Delegating to `super()` first preserves the base guarantees — dangerous interpolation
patterns, stacked statements, and dialect-aware tokenization.

### 3.2 Tenant scoping policy

`enforce_tenant_filter` normalizes caller parameters onto `tenant_id`. A corporate
deployment usually constrains the tenant namespace as well:

```python
    @classmethod
    def enforce_tenant_filter(cls, params, session_tenant):
        if not session_tenant.startswith("corp-"):
            raise SqlSecurityError(
                "session_tenant must be in the corporate namespace.",
                rule_id="CUSTOM-TENANT-NAMESPACE",
            )
        scoped = super().enforce_tenant_filter(params, session_tenant)
        scoped["tenant_id"] = session_tenant
        return scoped
```

Always return the mapping produced by the base implementation and mutate a copy — the
base already copies its input, so callers never observe aliasing.

### 3.3 Covering the policy with pytest

```python
import pytest

from verity.mcp_library.sql_guard import SqlSecurityError


def test_forbidden_table_rejected():
    with pytest.raises(SqlSecurityError, match="payroll"):
        CorpSqlGuard.validate_parameterized_query(
            "SELECT id FROM payroll WHERE id = %s"
        )


def test_approved_table_allowed():
    CorpSqlGuard.validate_parameterized_query(
        "SELECT id FROM invoices WHERE id = %s"
    )


def test_cross_tenant_filter_rejected():
    with pytest.raises(SqlSecurityError, match="corporate namespace"):
        CorpSqlGuard.enforce_tenant_filter({}, "partner-42")


def test_tenant_bound_to_parameters():
    assert CorpSqlGuard.enforce_tenant_filter({}, "corp-42")["tenant_id"] == "corp-42"
```

Assert on the exception type instead of its message wherever possible; message text is
not part of the stable contract, but `SqlSecurityError` and its optional `rule_id` are.

### 3.4 Authoring guidance

- Override only the classmethod you need; the remaining guards stay inherited.
- Raise `SqlSecurityError` (never `ValueError`) so callers can branch uniformly.
- Set `rule_id` on policy-specific errors; it flows into structured output.
- Keep allowlists lowercase and explicit — `validate_identifier_allowlist` normalizes
  input before comparing.
- Test both the reject and the accept path; a guard that rejects everything is as
  dangerous as one that rejects nothing.

## Composing extensions

The three seams are independent, so a customer integration typically:

1. Builds one `StaticRuleEvaluator` with the shipped defaults plus `custom_rules`.
2. Runs `scan_python_file()` and merges in any `McpAstVisitor` subclass findings.
3. Wraps every database call site in the `SqlSecurityGuard` subclass.

Because each seam returns plain dataclasses (`StaticRuleMatch`, `AstFinding`) or raises a
typed error, they compose without adapters. The `PRO_FEATURE_REQUIRED` degradation
contract above still applies: extensions never require `verity-pro`, and the absence of a
plugin never changes the behaviour of a locally defined rule, visitor, or guard.
