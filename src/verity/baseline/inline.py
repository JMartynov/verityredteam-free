"""Inline ``# verity-ignore`` / ``# nosemgrep`` directive parsing and application."""

from __future__ import annotations

import io
import re
import tokenize
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from verity.baseline.ignore import PolicyValidationError

_DIRECTIVE_RE = re.compile(r"#\s*(verity-ignore|nosemgrep)\b(.*)$")


@dataclass
class InlineSuppression:
    """A single parsed inline suppression directive."""

    rule_ids: list[str] = field(default_factory=list)
    reason: str | None = None
    line_number: int = 0
    standalone: bool = False
    kind: str = "verity-ignore"

    @property
    def is_blanket(self) -> bool:
        """Return True when the directive suppresses all rules."""
        return not self.rule_ids


def _iter_comment_tokens(source_code: str) -> Iterator[tuple[int, str, int, str]]:
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source_code).readline)
        for token in tokens:
            if token.type == tokenize.COMMENT:
                yield token.start[0], token.line, token.start[1], token.string
    except (tokenize.TokenError, IndentationError, SyntaxError):
        for index, line in enumerate(source_code.splitlines(), start=1):
            marker = line.find("#")
            if marker != -1:
                yield index, line, marker, line[marker:]


def _parse_directive(
    comment_text: str,
    line_number: int,
    standalone: bool,
) -> InlineSuppression | None:
    match = _DIRECTIVE_RE.search(comment_text)
    if not match:
        return None

    raw = (match.group(2) or "").strip()
    reason: str | None = None
    if "--" in raw:
        before, _, after = raw.partition("--")
        raw = before.strip()
        reason = after.strip() or None

    rule_ids: list[str] = []
    if raw.startswith(":"):
        spec = raw[1:].strip()
        rule_ids = [part for part in re.split(r"[,\s]+", spec) if part]
    elif raw and reason is None:
        reason = raw

    return InlineSuppression(
        rule_ids=rule_ids,
        reason=reason,
        line_number=line_number,
        standalone=standalone,
        kind=match.group(1),
    )


def parse_inline_suppressions(
    source_code: str,
) -> dict[int, list[InlineSuppression]]:
    """Parse inline suppression directives keyed by their physical line number."""
    directives: dict[int, list[InlineSuppression]] = {}
    if not source_code:
        return directives

    for line_number, line_text, column, comment_text in _iter_comment_tokens(source_code):
        standalone = column == (len(line_text) - len(line_text.lstrip()))
        parsed = _parse_directive(comment_text, line_number, standalone)
        if parsed is None:
            continue
        directives.setdefault(line_number, []).append(parsed)

    return directives


def _suppression_matches(supp: InlineSuppression, finding: dict[str, Any]) -> bool:
    if not supp.rule_ids:
        return True
    rule_id = str(finding.get("rule_id") or "").upper()
    cwe_id = str(finding.get("cwe_id") or "").upper()
    for token in supp.rule_ids:
        candidate = token.strip().upper()
        if not candidate:
            continue
        if candidate in (rule_id, cwe_id):
            return True
        if rule_id.endswith("-" + candidate) or rule_id.startswith(f"VERITY-AST-{candidate}-"):
            return True
    return False


def apply_inline_suppressions(
    findings: list[dict[str, Any]],
    source_by_file: dict[str, str],
    *,
    respect_inline_ignores: bool = True,
    strict_policy: bool = False,
) -> list[dict[str, Any]]:
    """Apply parsed inline suppressions to findings."""
    if not respect_inline_ignores:
        return findings

    cache: dict[str, dict[int, list[InlineSuppression]]] = {}

    for finding in findings:
        if "suppression" in finding:
            continue

        file_path = str(finding.get("file_path") or "")
        source = source_by_file.get(file_path)
        if source is None:
            normalized = file_path.replace("\\", "/")
            for key, value in source_by_file.items():
                if str(key).replace("\\", "/") == normalized:
                    source = value
                    file_path = key
                    break
        if source is None:
            continue

        directives = cache.get(file_path)
        if directives is None:
            directives = parse_inline_suppressions(source)
            cache[file_path] = directives

        line_number = finding.get("line_number")
        if not isinstance(line_number, int) or isinstance(line_number, bool):
            continue

        matched: InlineSuppression | None = None
        for candidate_line, same_line in ((line_number, True), (line_number - 1, False)):
            for supp in directives.get(candidate_line, []):
                if not same_line and not supp.standalone:
                    continue
                if _suppression_matches(supp, finding):
                    if strict_policy and supp.kind == "verity-ignore" and not supp.reason:
                        raise PolicyValidationError(
                            f"Inline suppression on line {candidate_line} requires a reason"
                        )
                    matched = supp
                    break
            if matched is not None:
                break

        if matched is not None:
            finding["suppression"] = {
                "kind": "inSource",
                "source": "inline",
                "reason": matched.reason or "inline directive",
            }

    return findings
