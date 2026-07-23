"""
pattern_detector.py
--------------------
Person 2's module: regex-based detection of known secret formats.

Contract (locked in with the group): detect(line: str) -> list[Finding]

Finding fields: {type, matched_string, start_col, end_col}

Notes for integration:
- This module only looks at ONE line at a time and knows nothing about
  file paths, git history, or context (test/ vs src/, placeholder-ness,
  severity). That's intentionally left to Person 4's
  filter_and_score()/is_placeholder() step downstream.
- Example: "AKIAEXAMPLE1234567" WILL be flagged here as an AWS_ACCESS_KEY
  match (that's correct — it matches the format). It's Person 4's job to
  recognize placeholder-style strings and suppress/downgrade them.
- Patterns live in config/patterns.json instead of being hardcoded, so
  new signatures can be added without touching this file.
"""

from __future__ import annotations

import json
import os
import re
from collections import namedtuple
from typing import List

Finding = namedtuple("Finding", ["type", "matched_string", "start_col", "end_col"])

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config", "patterns.json")

# Map string flag names (as they appear in the JSON config) to re module flags
_FLAG_MAP = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
}


class PatternDetectorError(Exception):
    """Raised on config loading/compilation problems."""


class _CompiledPattern:
    __slots__ = ("type", "description", "regex")

    def __init__(self, type_: str, description: str, regex: "re.Pattern[str]"):
        self.type = type_
        self.description = description
        self.regex = regex


def _resolve_flags(flag_names: List[str]) -> int:
    combined = 0
    for name in flag_names or []:
        try:
            combined |= _FLAG_MAP[name.upper()]
        except KeyError as e:
            raise PatternDetectorError(
                f"Unknown regex flag {name!r} in patterns config. "
                f"Valid options: {sorted(_FLAG_MAP)}"
            ) from e
    return combined


def load_patterns(config_path: str = DEFAULT_CONFIG_PATH) -> List[_CompiledPattern]:
    """Load and compile the signature library from a JSON config file."""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError as e:
        raise PatternDetectorError(f"Patterns config not found: {config_path}") from e
    except json.JSONDecodeError as e:
        raise PatternDetectorError(f"Patterns config is not valid JSON: {e}") from e

    compiled: List[_CompiledPattern] = []
    for i, entry in enumerate(raw):
        try:
            type_ = entry["type"]
            pattern = entry["regex"]
        except KeyError as e:
            raise PatternDetectorError(f"Pattern entry #{i} missing required field {e}") from e

        flags = _resolve_flags(entry.get("flags", []))
        try:
            regex = re.compile(pattern, flags)
        except re.error as e:
            raise PatternDetectorError(f"Bad regex for type {type_!r}: {e}") from e

        compiled.append(_CompiledPattern(type_, entry.get("description", ""), regex))

    return compiled


# Compiled once at import time so `detect()` is cheap to call per-line
# across a whole repo scan. If you need a different config, use
# make_detector() instead of the module-level detect().
_DEFAULT_PATTERNS = load_patterns()


def detect(line: str, patterns: List[_CompiledPattern] = None) -> List[Finding]:
    """
    Scan a single line of text against the signature library.

    Returns 0+ Findings. A line can trigger multiple findings, either from
    different pattern types or multiple matches of the same type.
    """
    if patterns is None:
        patterns = _DEFAULT_PATTERNS

    findings: List[Finding] = []
    for pat in patterns:
        for match in pat.regex.finditer(line):
            # If the pattern defines a 'value' group, report only that span
            # (just the secret itself) rather than the whole assignment —
            # keeps redaction/reporting downstream cleaner.
            has_value_group = "value" in pat.regex.groupindex
            if has_value_group:
                text = match.group("value")
                start, end = match.span("value")
            else:
                text = match.group(0)
                start, end = match.span(0)

            findings.append(
                Finding(
                    type=pat.type,
                    matched_string=text,
                    start_col=start,
                    end_col=end,
                )
            )
    return findings


def make_detector(config_path: str):
    """
    Build a standalone detect(line) function bound to a custom config file.
    Useful for unit tests that want their own tiny pattern set.
    """
    patterns = load_patterns(config_path)

    def _detect(line: str) -> List[Finding]:
        return detect(line, patterns=patterns)

    return _detect


if __name__ == "__main__":
    # Quick manual smoke test, not the real test suite.
    sample_lines = [
        'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"',
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
        'api_key = "sk_test_51Hh0dRandomLookingKeyValue1234567890"',
        'SLACK_TOKEN = "xoxb-1234567890-abcdefGHIJKLMNOP"',
        '-----BEGIN RSA PRIVATE KEY-----',
        'DATABASE_URL = "postgres://admin:S3cretPass@db.internal:5432/prod"',
        'password = "changeme"',
        'auth_header = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGhpc2lzYWZha2VzaWc"',
        'x = 42  # totally boring line, should produce nothing',
    ]

    for ln in sample_lines:
        results = detect(ln)
        print(f"\nLINE: {ln}")
        if not results:
            print("  (no matches)")
        for f in results:
            print(f"  -> {f.type}: {f.matched_string!r} [{f.start_col}:{f.end_col}]")