"""Hygiene checks for the PyPI publish GitHub Actions workflow."""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOW_PATH = (
    Path(__file__).resolve().parents[2] / ".github" / "workflows" / "workflow.yaml"
)
E2E_CONTAINERS_WORKFLOW_PATH = (
    Path(__file__).resolve().parents[2]
    / ".github"
    / "workflows"
    / "e2e-containers.yml"
)
FULL_TESTS_WORKFLOW_PATH = (
    Path(__file__).resolve().parents[2] / ".github" / "workflows" / "full-tests.yml"
)
WORKFLOWS_DIR = Path(__file__).resolve().parents[2] / ".github" / "workflows"
ALL_WORKFLOW_PATHS = tuple(
    sorted(
        path
        for path in WORKFLOWS_DIR.iterdir()
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    )
)
CHECKOUT_ACTION = "actions/checkout"
SETUP_UV_ACTION = "astral-sh/setup-uv"
EXPECTED_CHECKOUT_REF = f"{CHECKOUT_ACTION}@v5"
EXPECTED_SETUP_UV_REF = f"{SETUP_UV_ACTION}@v6"
FORBIDDEN_ACTION_FRAGMENTS = ("checkout@v4", "setup-uv@v4", "setup-uv@v5")
EXPECTED_JOB_NAMES = {
    "test-and-build",
    "full-tests",
    "pypi-publish",
    "e2e-containers",
    "update-homebrew-tap",
}
RELEASE_FIXTURE_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "gh_release_v0.2.0.json"
)
KNOWN_TRIGGERS = {"push", "release", "workflow_dispatch", "workflow_run"}
PUBLISH_ACTION = "pypa/gh-action-pypi-publish"
SAMPLE_RELEASE_TAG = "v0.2.0"


def load_workflow(path: Path = WORKFLOW_PATH) -> dict[str, Any]:
    """Parse the workflow YAML into a mapping."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path} must contain a YAML mapping"
    return data


def _raw_on(workflow: dict[str, Any]) -> Any:
    """Return the ``on`` section, tolerating PyYAML's boolean ``True`` key."""
    if "on" in workflow:
        return workflow["on"]
    return workflow.get(True)


def extract_triggers(workflow: dict[str, Any]) -> set[str]:
    """Return the set of trigger names declared under ``on``."""
    raw = _raw_on(workflow)
    if raw is None:
        return set()
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {item for item in raw if isinstance(item, str)}
    if isinstance(raw, dict):
        return {key for key in raw if isinstance(key, str)}
    raise TypeError(f"Unsupported 'on' section type: {type(raw).__name__}")


def push_tag_patterns(workflow: dict[str, Any]) -> list[str]:
    """Return the tag patterns configured under ``on.push.tags``."""
    raw = _raw_on(workflow)
    if not isinstance(raw, dict):
        return []
    push = raw.get("push")
    if not isinstance(push, dict):
        return []
    tags = push.get("tags", [])
    if isinstance(tags, str):
        return [tags]
    if isinstance(tags, list):
        return [tag for tag in tags if isinstance(tag, str)]
    return []


def _is_publish_action(uses: Any) -> bool:
    """Return True if ``uses`` references the PyPI publish action."""
    if not isinstance(uses, str):
        return False
    return uses == PUBLISH_ACTION or uses.startswith(f"{PUBLISH_ACTION}@")


def _publish_steps(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the pypi-publish job steps invoking the publish action."""
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return []
    job = jobs.get("pypi-publish")
    if not isinstance(job, dict):
        return []
    steps = job.get("steps")
    if not isinstance(steps, list):
        return []
    return [
        step
        for step in steps
        if isinstance(step, dict) and _is_publish_action(step.get("uses"))
    ]


def validate_duplicate_upload_guard(workflow: dict[str, Any]) -> None:
    """Reject workflows that could re-upload an existing release to PyPI.

    Raises:
        ValueError: if the ``release`` trigger is enabled without a
            ``skip-existing: true`` guard on the publish step.
    """
    if "release" not in extract_triggers(workflow):
        return
    for step in _publish_steps(workflow):
        with_block = step.get("with")
        if isinstance(with_block, dict) and with_block.get("skip-existing") is True:
            return
    raise ValueError(
        "Duplicate PyPI upload risk: the 'release' trigger is enabled but the "
        f"{PUBLISH_ACTION} step does not set 'skip-existing: true'. Remedies: "
        "remove 'release: types: [published]' from 'on:' or add "
        "'with: {skip-existing: true}' to the publish step."
    )


def validate_pypi_publish_job(workflow: dict[str, Any]) -> None:
    """Assert the pypi-publish job wiring required for Trusted Publishing."""
    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict), "workflow must define jobs"
    job = jobs.get("pypi-publish")
    assert isinstance(job, dict), "workflow must define a pypi-publish job"
    assert job.get("needs") == "full-tests", "pypi-publish must need full-tests"
    environment = job.get("environment")
    assert isinstance(environment, dict), "pypi-publish must define environment"
    assert environment.get("name") == "pypi", "environment.name must be 'pypi'"
    permissions = job.get("permissions")
    assert isinstance(permissions, dict), "pypi-publish must define permissions"
    assert permissions.get("id-token") == "write", (
        "permissions.id-token must be 'write'"
    )


def _build_workflow(on_section: Any, with_block: Any = None) -> dict[str, Any]:
    """Build a minimal in-memory workflow for guard unit tests."""
    step: dict[str, Any] = {"uses": f"{PUBLISH_ACTION}@release/v1"}
    if with_block is not None:
        step["with"] = with_block
    return {"on": on_section, "jobs": {"pypi-publish": {"steps": [step]}}}


@pytest.fixture(scope="module")
def workflow() -> dict[str, Any]:
    """Load the repository workflow once for read-only assertions."""
    return load_workflow()


def test_triggers_are_known_and_non_empty(workflow: dict[str, Any]) -> None:
    """Assert the workflow triggers a non-empty subset of supported events."""
    triggers = extract_triggers(workflow)
    unknown = triggers - KNOWN_TRIGGERS
    assert triggers, "workflow must declare at least one trigger"
    assert not unknown, f"unexpected triggers: {unknown}"


def test_extract_triggers_tolerates_pyyaml_boolean_key() -> None:
    """Assert an unquoted ``on:`` parsed as the boolean ``True`` key works."""
    raw = {True: {"push": {"tags": ["v*"]}, "workflow_dispatch": None}}
    assert extract_triggers(raw) == {"push", "workflow_dispatch"}


def test_push_tag_patterns_tolerates_pyyaml_boolean_key() -> None:
    """Assert push tag patterns are read when ``on:`` parses as ``True``."""
    raw = {True: {"push": {"tags": ["v*"]}, "workflow_dispatch": None}}
    assert push_tag_patterns(raw) == ["v*"]


def test_push_tags_cover_release_tags(workflow: dict[str, Any]) -> None:
    """Assert a pushed ``v*`` tag is matched by the push trigger."""
    patterns = push_tag_patterns(workflow)
    assert patterns, "push trigger must declare tag patterns"
    assert any(fnmatch.fnmatch(SAMPLE_RELEASE_TAG, p) for p in patterns), (
        f"no push tag pattern matches {SAMPLE_RELEASE_TAG!r}: {patterns}"
    )


def test_repository_has_duplicate_upload_guard(workflow: dict[str, Any]) -> None:
    """Assert the checked-in workflow cannot re-upload a release to PyPI."""
    validate_duplicate_upload_guard(workflow)


def test_repository_pypi_publish_job_contract(workflow: dict[str, Any]) -> None:
    """Assert the checked-in pypi-publish job honours the publishing contract."""
    validate_pypi_publish_job(workflow)


@pytest.mark.parametrize(
    ("on_section", "with_block"),
    [
        ({"push": {"tags": ["v*"]}, "workflow_dispatch": None}, None),
        (
            {"push": {"tags": ["v*"]}, "release": {"types": ["published"]}},
            {"skip-existing": True},
        ),
        (["push"], None),
    ],
    ids=["release-absent", "release-with-skip-existing", "list-without-release"],
)
def test_duplicate_upload_guard_accepts_valid_modes(
    on_section: Any, with_block: Any
) -> None:
    """Assert both accepted guard shapes pass validation."""
    validate_duplicate_upload_guard(_build_workflow(on_section, with_block))


@pytest.mark.parametrize(
    ("on_section", "with_block"),
    [
        ({"push": {"tags": ["v*"]}, "release": {"types": ["published"]}}, None),
        (
            {"push": {"tags": ["v*"]}, "release": {"types": ["published"]}},
            {"skip-existing": False},
        ),
        (
            {"push": {"tags": ["v*"]}, "release": {"types": ["published"]}},
            {"skip-existing": "true"},
        ),
        (["push", "release"], None),
        (["push", "release"], {"skip-existing": False}),
    ],
    ids=[
        "release-without-with",
        "release-with-skip-existing-false",
        "release-with-skip-existing-string",
        "list-release-without-with",
        "list-release-with-skip-existing-false",
    ],
)
def test_duplicate_upload_guard_rejects_unsafe_workflows(
    on_section: Any, with_block: Any
) -> None:
    """Assert release-triggered workflows without skip-existing are rejected."""
    with pytest.raises(ValueError, match="skip-existing"):
        validate_duplicate_upload_guard(_build_workflow(on_section, with_block))


def test_duplicate_upload_guard_rejects_missing_publish_step() -> None:
    """Assert a release-triggered workflow without a publish step is rejected."""
    workflow = {
        "on": {"push": {"tags": ["v*"]}, "release": {"types": ["published"]}},
        "jobs": {"pypi-publish": {"steps": [{"uses": "actions/checkout@v4"}]}},
    }
    with pytest.raises(ValueError, match="skip-existing"):
        validate_duplicate_upload_guard(workflow)


def test_duplicate_upload_guard_error_mentions_both_remedies() -> None:
    """Assert the rejection message names both accepted remedies."""
    workflow = _build_workflow(
        {"push": {"tags": ["v*"]}, "release": {"types": ["published"]}}, None
    )
    with pytest.raises(ValueError) as exc_info:
        validate_duplicate_upload_guard(workflow)
    message = str(exc_info.value)
    assert "release" in message
    assert "skip-existing" in message


def test_recorded_v020_release_fixture() -> None:
    """Assert the recorded v0.2.0 GitHub Release payload contains M7-M11 notes."""
    payload = json.loads(RELEASE_FIXTURE_PATH.read_text(encoding="utf-8"))
    assert payload.get("tagName") == "v0.2.0"
    body = payload.get("body", "")
    for milestone in ("M7", "M8", "M9", "M10", "M11"):
        assert milestone in body, f"Missing {milestone} section in v0.2.0 release body"
    assert "https://pypi.org/project/verity-redteam-core/0.2.0/" in body
    assert "verity-redteam-core==0.2.0" in body
    assert "INSTALL_SOURCE=pypi" in body


def _schedule_crons(workflow_path: Path) -> list[str]:
    """Return the cron strings declared under ``on.schedule``."""
    workflow = load_workflow(workflow_path)
    raw = _raw_on(workflow)
    assert isinstance(raw, dict), f"{workflow_path} must define an 'on' mapping"
    schedule = raw.get("schedule")
    assert isinstance(schedule, list), f"{workflow_path} must define on.schedule"
    return [
        entry["cron"]
        for entry in schedule
        if isinstance(entry, dict) and isinstance(entry.get("cron"), str)
    ]


def test_e2e_containers_has_nightly_schedule() -> None:
    """Assert e2e-containers declares the nightly 0 4 * * * schedule."""
    workflow = load_workflow(E2E_CONTAINERS_WORKFLOW_PATH)
    raw = _raw_on(workflow)
    assert isinstance(raw, dict), "e2e-containers must define an 'on' mapping"
    schedule = raw.get("schedule")
    assert isinstance(schedule, list), "e2e-containers must define on.schedule"
    assert {"cron": "0 4 * * *"} in schedule


def test_e2e_containers_preserves_existing_triggers() -> None:
    """Assert workflow_dispatch, v* tag push and pull_request paths remain."""
    workflow = load_workflow(E2E_CONTAINERS_WORKFLOW_PATH)
    raw = _raw_on(workflow)
    assert isinstance(raw, dict), "e2e-containers must define an 'on' mapping"
    assert "workflow_dispatch" in raw
    push = raw.get("push")
    assert isinstance(push, dict), "push trigger must remain a mapping"
    assert push.get("tags") == ["v*"]
    pull_request = raw.get("pull_request")
    assert isinstance(pull_request, dict), "pull_request trigger must remain"
    paths = pull_request.get("paths")
    assert isinstance(paths, list), "pull_request.paths must remain a list"
    assert set(paths) == {"src/**", "README.md", "tests/e2e_containers/**"}


def test_schedule_offset_differs_from_full_tests() -> None:
    """Assert e2e-containers runs at 0 4 * * * and full-tests at 0 3 * * *."""
    e2e_crons = _schedule_crons(E2E_CONTAINERS_WORKFLOW_PATH)
    full_crons = _schedule_crons(FULL_TESTS_WORKFLOW_PATH)
    assert "0 4 * * *" in e2e_crons
    assert "0 3 * * *" in full_crons
    assert set(e2e_crons).isdisjoint(full_crons)


def test_e2e_containers_runs_container_suite() -> None:
    """Assert the job still runs the container suite with INSTALL_SOURCE=wheel."""
    workflow = load_workflow(E2E_CONTAINERS_WORKFLOW_PATH)
    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict), "e2e-containers must define jobs"
    job = jobs.get("e2e-containers")
    assert isinstance(job, dict), "e2e-containers job must exist"
    steps = job.get("steps")
    assert isinstance(steps, list), "e2e-containers job must define steps"
    matching = [
        step
        for step in steps
        if isinstance(step, dict)
        and "bash ./tests/e2e_containers/run_e2e.sh" in str(step.get("run", ""))
    ]
    assert matching, "e2e-containers must run the container E2E suite"
    assert any(
        isinstance(step.get("env"), dict)
        and step["env"].get("INSTALL_SOURCE") == "wheel"
        for step in matching
    ), "container E2E suite must run with INSTALL_SOURCE=wheel"


def _iter_uses(workflow: dict[str, Any]) -> list[str]:
    """Return every ``uses:`` reference declared across all workflow jobs."""
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return []
    refs: list[str] = []
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if isinstance(uses, str):
                refs.append(uses)
    return refs


def _references(action: str, workflow: dict[str, Any]) -> list[str]:
    """Return every ``uses:`` entry that targets ``action`` (pinned or not)."""
    return [
        uses
        for uses in _iter_uses(workflow)
        if uses == action or uses.startswith(f"{action}@")
    ]


def _action_refs(action: str) -> set[str]:
    """Return the distinct ``action@ref`` pins used across all workflows."""
    refs: set[str] = set()
    for path in ALL_WORKFLOW_PATHS:
        refs.update(_references(action, load_workflow(path)))
    return refs


def _workflow_files() -> list[Path]:
    """Return every YAML manifest under the workflows directory."""
    return sorted(
        path
        for path in WORKFLOWS_DIR.rglob("*")
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    )


@pytest.mark.parametrize("workflow_path", ALL_WORKFLOW_PATHS, ids=lambda p: p.name)
def test_checkout_pin_is_v5(workflow_path: Path) -> None:
    """Assert every checkout use in each workflow is pinned to v5."""
    refs = _references(CHECKOUT_ACTION, load_workflow(workflow_path))
    assert refs, f"{workflow_path.name} must use {CHECKOUT_ACTION}"
    assert all(ref == EXPECTED_CHECKOUT_REF for ref in refs), refs


@pytest.mark.parametrize("workflow_path", ALL_WORKFLOW_PATHS, ids=lambda p: p.name)
def test_setup_uv_pin_is_v6(workflow_path: Path) -> None:
    """Assert every setup-uv use in each workflow is pinned to v6."""
    refs = _references(SETUP_UV_ACTION, load_workflow(workflow_path))
    assert refs, f"{workflow_path.name} must use {SETUP_UV_ACTION}"
    assert all(ref == EXPECTED_SETUP_UV_REF for ref in refs), refs


def test_no_legacy_action_pins_remain() -> None:
    """Assert no deprecated action pins remain anywhere under workflows."""
    offenders: list[str] = []
    for path in sorted(WORKFLOWS_DIR.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for fragment in FORBIDDEN_ACTION_FRAGMENTS:
            if fragment in text:
                offenders.append(f"{path}: {fragment}")
    assert not offenders, offenders


def test_no_floating_action_refs() -> None:
    """Assert no action reference uses a floating @main or @master branch."""
    offenders: list[str] = []
    for path in _workflow_files():
        for uses in _iter_uses(load_workflow(path)):
            if uses.strip().lower().endswith(("@main", "@master")):
                offenders.append(f"{path.name}: {uses}")
    assert not offenders, offenders


def test_action_pin_parity() -> None:
    """Assert each action uses exactly one pin across all four workflows."""
    checkout_refs = _action_refs(CHECKOUT_ACTION)
    setup_uv_refs = _action_refs(SETUP_UV_ACTION)
    assert checkout_refs == {EXPECTED_CHECKOUT_REF}, checkout_refs
    assert setup_uv_refs == {EXPECTED_SETUP_UV_REF}, setup_uv_refs


def test_workflows_parse_and_expose_expected_jobs() -> None:
    """Assert all workflows parse and declare the expected set of jobs."""
    found: set[str] = set()
    for path in ALL_WORKFLOW_PATHS:
        jobs = load_workflow(path).get("jobs")
        assert isinstance(jobs, dict), f"{path.name} must define jobs"
        found.update(name for name in jobs if isinstance(name, str))
    missing = EXPECTED_JOB_NAMES - found
    assert not missing, missing


def test_homebrew_tap_workflow_contract() -> None:
    """AC-30.4: Verify .github/workflows/homebrew-tap.yml triggers, pins, and tap publishing."""
    tap_path = WORKFLOWS_DIR / "homebrew-tap.yml"
    assert tap_path.is_file(), "homebrew-tap.yml must exist"
    raw_text = tap_path.read_text(encoding="utf-8")
    workflow_data = load_workflow(tap_path)
    raw_on = _raw_on(workflow_data)
    assert isinstance(raw_on, dict), "homebrew-tap.yml must define 'on' mapping"
    assert "workflow_dispatch" in raw_on
    wf_run = raw_on.get("workflow_run")
    assert isinstance(wf_run, dict), "homebrew-tap.yml must define on.workflow_run"
    assert wf_run.get("workflows") == ["Publish to PyPI"]
    assert wf_run.get("types") == ["completed"]

    assert EXPECTED_CHECKOUT_REF in _iter_uses(workflow_data)
    assert EXPECTED_SETUP_UV_REF in _iter_uses(workflow_data)
    assert "scripts/generate_homebrew_formula.py" in raw_text
    assert "HOMEBREW_TAP_TOKEN" in raw_text
    assert "JMartynov/homebrew-tap" in raw_text


def _pin_violations(workflow: dict[str, Any]) -> list[str]:
    """Return checkout/setup-uv refs that deviate from the expected pins."""
    bad: list[str] = []
    for uses in _iter_uses(workflow):
        if uses.startswith(f"{CHECKOUT_ACTION}@") and uses != EXPECTED_CHECKOUT_REF:
            bad.append(uses)
        if uses.startswith(f"{SETUP_UV_ACTION}@") and uses != EXPECTED_SETUP_UV_REF:
            bad.append(uses)
    return bad


def _job(path: Path, name: str) -> dict[str, Any]:
    jobs = load_workflow(path).get("jobs")
    assert isinstance(jobs, dict), f"{path.name} must define jobs"
    job = jobs.get(name)
    assert isinstance(job, dict), f"{path.name} must define job {name}"
    return job


def test_all_workflows_dynamically_discovered_and_pinned() -> None:
    """AC-55.1: every workflow file is discovered and pinned; v4 fixture fails."""
    names = {path.name for path in ALL_WORKFLOW_PATHS}
    on_disk = {
        p.name for p in WORKFLOWS_DIR.iterdir() if p.suffix in {".yml", ".yaml"}
    }
    assert names == on_disk
    assert {"pages.yml", "upstream-sync.yml"} <= names
    for path in ALL_WORKFLOW_PATHS:
        assert not _pin_violations(load_workflow(path)), path.name
    fixture = {
        "on": {"push": None},
        "jobs": {"x": {"steps": [{"uses": "actions/checkout@v4"}]}},
    }
    assert _pin_violations(fixture) == ["actions/checkout@v4"]


def test_ci_lints_scripts_and_checks_portal() -> None:
    """AC-55.3: CI lints scripts and checks docs portal parity."""
    ci = (WORKFLOWS_DIR / "ci.yml").read_text(encoding="utf-8")
    full = (WORKFLOWS_DIR / "full-tests.yml").read_text(encoding="utf-8")
    assert "ruff check src tests scripts" in ci
    assert "ruff check src tests scripts" in full
    assert "scripts/build_docs_portal.py --check" in ci


def test_homebrew_tap_fallback_and_preflight_contract() -> None:
    """AC-54.1: version fallback, --from-lock, ruby -c, token preflight."""
    raw = (WORKFLOWS_DIR / "homebrew-tap.yml").read_text(encoding="utf-8")
    assert "--from-lock" in raw
    assert "ruby -c" in raw
    assert "pyproject.toml" in raw
    assert '"main"' in raw or "'main'" in raw
    assert "fetch-depth: 0" in raw
    steps = _job(WORKFLOWS_DIR / "homebrew-tap.yml", "update-homebrew-tap")["steps"]
    preflight = [
        s
        for s in steps
        if isinstance(s, dict)
        and "HOMEBREW_TAP_TOKEN" in json.dumps(s.get("env", {}))
        and "run" in s
    ]
    assert preflight, "must have a HOMEBREW_TAP_TOKEN preflight run step"
    assert "::warning" in preflight[0]["run"] or "::error" in preflight[0]["run"]
    tap_checkout = [
        s
        for s in steps
        if isinstance(s, dict)
        and isinstance(s.get("with"), dict)
        and s["with"].get("repository") == "JMartynov/homebrew-tap"
    ]
    assert tap_checkout and "if" in tap_checkout[0], "tap checkout must be gated"


def test_workflow_release_artifacts_and_pypi_e2e() -> None:
    """AC-54.2: GitHub Release with artifacts on v* tags + PyPI e2e."""
    raw = WORKFLOW_PATH.read_text(encoding="utf-8")
    wf = load_workflow()
    jobs = wf["jobs"]
    publish = jobs["pypi-publish"]
    assert "refs/tags/v" in str(publish.get("if", "")), "publish only on v* tags"
    assert "SHA256SUMS.txt" in raw
    release_jobs = [
        j for j in jobs.values()
        if isinstance(j, dict) and "SHA256SUMS.txt" in json.dumps(j)
    ]
    assert release_jobs
    rel = release_jobs[0]
    assert rel.get("permissions", {}).get("contents") == "write"
    assert "refs/tags/v" in str(rel.get("if", ""))
    blob = json.dumps(rel)
    assert ".whl" in blob and ".tar.gz" in blob
    e2e_jobs = [
        j for j in jobs.values()
        if isinstance(j, dict) and "e2e-containers.yml" in str(j.get("uses", ""))
    ]
    assert e2e_jobs, "post-publish e2e must call e2e-containers.yml"
    assert e2e_jobs[0].get("with", {}).get("install_source") == "pypi"
    e2e_on = _raw_on(load_workflow(E2E_CONTAINERS_WORKFLOW_PATH))
    assert "workflow_call" in e2e_on
    assert "install_source" in json.dumps(e2e_on["workflow_dispatch"])


def test_upstream_sync_workflow_contract() -> None:
    """AC-54.3: upstream-sync triggers, pins, gates, PR, permissions."""
    path = WORKFLOWS_DIR / "upstream-sync.yml"
    assert path.is_file()
    raw = path.read_text(encoding="utf-8")
    wf = load_workflow(path)
    on = _raw_on(wf)
    assert set(on["repository_dispatch"]["types"]) == {
        "upstream_fingerprints_updated",
        "upstream_vulnerabilities_updated",
    }
    assert "schedule" in on and "workflow_dispatch" in on
    uses = _iter_uses(wf)
    assert EXPECTED_CHECKOUT_REF in uses and EXPECTED_SETUP_UV_REF in uses
    assert not _pin_violations(wf)
    assert "ruff check" in raw and "pytest" in raw
    assert "mcp-fingerprints" in raw and "mcp-vulnerabilities" in raw
    assert "gh pr" in raw or "create-pull-request" in raw
    perms = wf.get("permissions") or next(iter(wf["jobs"].values())).get("permissions")
    assert perms.get("contents") == "write"
    assert perms.get("pull-requests") == "write"
