"""Verity baseline subsystem: path canonicalization, fingerprints, ignore and baseline I/O."""

from verity.baseline.fingerprint import (
    assign_fingerprints,
    collapse_whitespace,
    compute_finding_fingerprint,
)
from verity.baseline.ignore import (
    DEFAULT_IGNORE_DIRS,
    AllowlistRule,
    IgnoreMatcher,
    IgnoreRule,
    PolicyConfig,
    PolicyValidationError,
    apply_policy_suppressions,
    load_ignore_spec,
    load_policy_config,
)
from verity.baseline.inline import (
    InlineSuppression,
    apply_inline_suppressions,
    parse_inline_suppressions,
)
from verity.baseline.paths import canonicalize_path, resolve_project_root
from verity.baseline.store import (
    BASELINE_SCHEMA_VERSION,
    BaselineDiffResult,
    BaselineSchemaError,
    diff_baseline,
    load_baseline,
    save_baseline,
    validate_rug_pull_baseline_dict,
)

__all__ = [
    "BASELINE_SCHEMA_VERSION",
    "DEFAULT_IGNORE_DIRS",
    "AllowlistRule",
    "BaselineDiffResult",
    "BaselineSchemaError",
    "IgnoreMatcher",
    "IgnoreRule",
    "InlineSuppression",
    "PolicyConfig",
    "PolicyValidationError",
    "apply_inline_suppressions",
    "apply_policy_suppressions",
    "assign_fingerprints",
    "canonicalize_path",
    "collapse_whitespace",
    "compute_finding_fingerprint",
    "diff_baseline",
    "load_baseline",
    "load_ignore_spec",
    "load_policy_config",
    "parse_inline_suppressions",
    "resolve_project_root",
    "save_baseline",
    "validate_rug_pull_baseline_dict",
]
