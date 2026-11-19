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
