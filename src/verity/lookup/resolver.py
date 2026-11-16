"""Deterministic SemVer 2.0 and PEP-440 Version Range Boundary Resolver."""

from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version


class VersionResolver:
    """Evaluates whether a candidate version string satisfies OSV event boundary ranges."""

    CLEAN_PREFIX_REGEX = re.compile(r"^[<>=~^vVrelease@\-_/\s]+(?=\d)")

    @classmethod
    def clean_version_string(cls, ver_str: str) -> str:
        """Strip comparison operators and non-version prefixes."""
        cleaned = ver_str.strip()
        return cls.CLEAN_PREFIX_REGEX.sub("", cleaned)

    @classmethod
    def parse_version(cls, ver_str: str) -> Version | None:
        """Parse version string into a comparable Version object with flexible fallback."""
        if not ver_str or not ver_str.strip():
            return None
        cleaned = cls.clean_version_string(ver_str)
        try:
            return Version(cleaned)
        except InvalidVersion:
            # Fallback: extract leading major.minor.patch numeric components
            m = re.search(r"(\d+(?:\.\d+)*(?:-[a-zA-Z0-9.]+)?(?:\+[a-zA-Z0-9.]+)?)$", cleaned)
            if m:
                try:
                    return Version(m.group(1))
                except InvalidVersion:
                    pass
            # Secondary fallback: only numbers with dots
            m_num = re.search(r"(\d+(?:\.\d+)*)", cleaned)
            if m_num:
                try:
                    return Version(m_num.group(1))
                except InvalidVersion:
                    pass
            return None

    @classmethod
    def is_version_in_range(
        cls,
        candidate_version: str,
        introduced: str | None = None,
        fixed: str | None = None,
        last_affected: str | None = None,
        limit: str | None = None,
    ) -> bool:
        """Evaluate if candidate_version falls within the given range boundary events."""
        c_ver = cls.parse_version(candidate_version)
        if c_ver is None:
            # Cannot parse candidate, fall back to string equality check with boundary endpoints
            if introduced and candidate_version == introduced:
                return True
            return bool(last_affected and candidate_version == last_affected)

        # 1. Lower bound (introduced)
        if introduced:
            clean_intro = introduced.strip()
            # If introduced starts with "<" (e.g. "< 2.47.4"), it acts as an upper bound
            if clean_intro.startswith("<"):
                upper_bound = cls.parse_version(clean_intro)
                if upper_bound is not None:
                    if clean_intro.startswith("<="):
                        if c_ver > upper_bound:
                            return False
                    elif c_ver >= upper_bound:
                        return False
            else:
                i_ver = cls.parse_version(clean_intro)
                if i_ver is not None and c_ver < i_ver:
                    return False

        # 2. Upper bound (fixed)
        if fixed:
            f_ver = cls.parse_version(fixed)
            if f_ver is not None and c_ver >= f_ver:
                return False

        # 3. Upper bound (last_affected)
        if last_affected:
            l_ver = cls.parse_version(last_affected)
            if l_ver is not None and c_ver > l_ver:
                return False

        # 4. Upper bound (limit)
        if limit:
            lim_ver = cls.parse_version(limit)
            if lim_ver is not None and c_ver >= lim_ver:
                return False

        return True

    @classmethod
    def compare(cls, ver_a: str, ver_b: str) -> int:
        """Compare two version strings. Returns -1 if a < b, 0 if a == b, 1 if a > b."""
        v_a = cls.parse_version(ver_a)
        v_b = cls.parse_version(ver_b)
        if v_a is not None and v_b is not None:
            if v_a < v_b:
                return -1
            if v_a > v_b:
                return 1
            return 0
        # String fallback
        if ver_a < ver_b:
            return -1
        if ver_a > ver_b:
            return 1
        return 0
