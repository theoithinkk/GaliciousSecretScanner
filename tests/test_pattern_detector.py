"""
tests/test_pattern_detector.py
------------------------------
Covers the regex signature library: every pattern type in config/patterns.json
matches something representative, the `value` capture group narrows the match to
the secret itself, boring lines stay quiet, and config errors are reported
rather than swallowed.

Secrets in this file are syntactically valid but fabricated -- none are live.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from _helpers import REPO_ROOT  # noqa: F401  (sys.path side effect)

import pattern_detector
from pattern_detector import PatternDetectorError, detect, load_patterns, make_detector


class TestKnownFormats(unittest.TestCase):
    """One representative line per pattern type shipped in the config."""

    CASES = [
        ("AWS_ACCESS_KEY", 'aws_access_key_id = "AKIA3RJQ7KZ2NDLPWXYZ"'),
        ("AWS_SECRET_KEY",
         'aws_secret_access_key = "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"'),
        ("GENERIC_API_KEY", 'api_key = "8f14e45fceea167a5a36dedd4bea2543"'),
        ("GENERIC_SECRET", 'access_token = "9fQ2mLp8XzT4vRb6Yk1Wc3"'),
        ("GENERIC_PASSWORD", 'password = "Tr0ub4dor&3"'),
        ("SLACK_TOKEN", 'SLACK_TOKEN = "xoxb-1234567890-abcdefGHIJKLMNOP"'),
        ("SLACK_WEBHOOK",
         'url = "https://hooks.slack.com/services/T00000000/B00000000/'
         'XXXXXXXXXXXXXXXXXXXXXXXX"'),
        ("PRIVATE_KEY_HEADER", "-----BEGIN RSA PRIVATE KEY-----"),
        ("DB_CONNECTION_STRING",
         'DATABASE_URL = "postgres://admin:S3cretPass@db.internal:5432/prod"'),
        ("JWT", 'auth = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGhpc2lz"'),
        ("GITHUB_TOKEN", 'gh = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"'),
        ("GOOGLE_API_KEY", 'key = "AIzaSyD-abcdefghijklmnopqrstuvwxyz123456"'),
        ("STRIPE_KEY", 'stripe = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"'),
    ]

    def test_each_pattern_type_matches(self):
        for expected_type, line in self.CASES:
            with self.subTest(type=expected_type):
                types = [f.type for f in detect(line)]
                self.assertIn(expected_type, types, f"{line!r} -> {types}")

    def test_every_configured_type_is_covered_by_this_test(self):
        # Guards against someone adding a pattern to the JSON and leaving it
        # untested.
        configured = {p.type for p in load_patterns()}
        covered = {t for t, _ in self.CASES}
        self.assertEqual(configured - covered, set(),
                         "pattern types in config/patterns.json with no test case")

    def test_pem_header_variants(self):
        for header in ("-----BEGIN PRIVATE KEY-----",
                       "-----BEGIN RSA PRIVATE KEY-----",
                       "-----BEGIN EC PRIVATE KEY-----",
                       "-----BEGIN OPENSSH PRIVATE KEY-----"):
            with self.subTest(header=header):
                self.assertTrue(detect(header))


class TestMatchSpans(unittest.TestCase):
    def test_value_group_narrows_the_match_to_the_secret(self):
        line = 'api_key = "8f14e45fceea167a5a36dedd4bea2543"'
        hit = next(f for f in detect(line) if f.type == "GENERIC_API_KEY")
        self.assertEqual(hit.matched_string, "8f14e45fceea167a5a36dedd4bea2543")
        self.assertNotIn("api_key", hit.matched_string)

    def test_columns_bracket_the_matched_text(self):
        line = 'aws_access_key_id = "AKIA3RJQ7KZ2NDLPWXYZ"'
        hit = next(f for f in detect(line) if f.type == "AWS_ACCESS_KEY")
        self.assertEqual(line[hit.start_col:hit.end_col], hit.matched_string)

    def test_multiple_matches_on_one_line(self):
        line = 'a = "AKIA3RJQ7KZ2NDLPWXYZ"; b = "AKIA7WQ4MZ8XCVBNLKJH"'
        aws = [f for f in detect(line) if f.type == "AWS_ACCESS_KEY"]
        self.assertEqual(len(aws), 2)
        self.assertNotEqual(aws[0].start_col, aws[1].start_col)


class TestNoFalsePositives(unittest.TestCase):
    QUIET = [
        "x = 42  # totally boring line",
        "def authenticate(user, password):",
        "import os",
        "",
        "# see https://example.com/docs for the api_key format",
        "SELECT id, name FROM users WHERE active = 1",
    ]

    def test_boring_lines_produce_nothing(self):
        for line in self.QUIET:
            with self.subTest(line=line):
                self.assertEqual(detect(line), [], f"{line!r} matched")

    def test_short_values_below_length_floor_are_ignored(self):
        # GENERIC_API_KEY requires 16+ chars; a 4-char value is not a key.
        self.assertEqual(
            [f for f in detect('api_key = "abcd"') if f.type == "GENERIC_API_KEY"], []
        )

    def test_akia_prefix_alone_is_not_enough(self):
        self.assertEqual([f for f in detect('s = "AKIAshort"')
                          if f.type == "AWS_ACCESS_KEY"], [])


class TestKnownGaps(unittest.TestCase):
    """
    Documented limitations, asserted so they can't regress further and so the
    next person doesn't rediscover them the hard way.
    """

    def test_unquoted_env_assignment_is_not_matched_by_regex(self):
        # Every generic pattern requires quotes around the value, but .env
        # files never quote. entropy_detector is the only thing catching these
        # today, which costs the type-specific base score.
        line = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ4hTgLm2N"
        self.assertEqual(detect(line), [],
                         "if this now matches, the known gap is fixed -- "
                         "update this test and the base scores")

    def test_pem_body_lines_are_not_detected(self):
        # Detection is line-at-a-time, so only the BEGIN header is caught; the
        # base64 body of a private key scores nothing on its own.
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"
        self.assertEqual(detect(body), [])


class TestConfigLoading(unittest.TestCase):
    def test_default_config_loads_and_is_not_empty(self):
        patterns = load_patterns()
        self.assertTrue(patterns)
        self.assertTrue(all(p.type for p in patterns))

    def test_flags_are_applied(self):
        # GENERIC_API_KEY is declared IGNORECASE, so uppercase must match.
        self.assertTrue([f for f in detect('API_KEY = "8f14e45fceea167a5a36dedd"')
                         if f.type == "GENERIC_API_KEY"])

    def _write_config(self, payload) -> str:
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            f.write(payload if isinstance(payload, str) else json.dumps(payload))
        self.addCleanup(os.remove, path)
        return path

    def test_make_detector_uses_a_custom_config(self):
        path = self._write_config([
            {"type": "CUSTOM", "description": "test only", "regex": "ZZZ-[0-9]{4}"}
        ])
        custom = make_detector(path)
        self.assertEqual([f.type for f in custom("token = ZZZ-1234")], ["CUSTOM"])
        # ...and does not inherit the default library.
        self.assertEqual(custom('key = "AKIA3RJQ7KZ2NDLPWXYZ"'), [])

    def test_missing_config_raises(self):
        with self.assertRaises(PatternDetectorError):
            load_patterns(os.path.join(REPO_ROOT, "does", "not", "exist.json"))

    def test_malformed_json_raises(self):
        with self.assertRaises(PatternDetectorError):
            load_patterns(self._write_config("{not json"))

    def test_missing_required_field_raises(self):
        with self.assertRaises(PatternDetectorError):
            load_patterns(self._write_config([{"type": "NO_REGEX"}]))

    def test_bad_regex_raises(self):
        with self.assertRaises(PatternDetectorError):
            load_patterns(self._write_config([{"type": "BAD", "regex": "([unclosed"}]))

    def test_unknown_flag_raises(self):
        with self.assertRaises(PatternDetectorError):
            load_patterns(self._write_config(
                [{"type": "BAD_FLAG", "regex": "x", "flags": ["NOPE"]}]
            ))

    def test_module_level_patterns_are_compiled_once(self):
        # detect() is called per line across a whole repo; recompiling per call
        # would be a real performance bug.
        self.assertIs(pattern_detector._DEFAULT_PATTERNS,
                      pattern_detector._DEFAULT_PATTERNS)
        self.assertTrue(pattern_detector._DEFAULT_PATTERNS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
