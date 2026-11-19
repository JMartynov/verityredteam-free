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
RELEASE_FIXTURE_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "gh_release_v0.2.0.json"
)
KNOWN_TRIGGERS = {"push", "release", "workflow_dispatch"}
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
