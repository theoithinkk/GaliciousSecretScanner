"""
tests/test_scorer.py
--------------------
Covers filter_and_score / generate_report / exit_code: placeholder suppression,
redaction, the scoring rubric's ordering guarantees, severity filtering, the CI
gate, and the invariant that matters most -- no renderer ever emits a raw
secret.

The scoring tests assert ORDERING and BANDS rather than exact point totals
wherever possible, so retuning the rubric doesn't require rewriting the suite.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from _helpers import REPO_ROOT  # noqa: F401  (sys.path side effect)

from models import RawFinding, ScanContext, ScoredFinding, Severity
from scorer_reporter import (
    exit_code,
    filter_and_score,
    generate_report,
    is_placeholder,
    redact_secret,
)

LIVE_AWS = "AKIA3RJQ7KZ2NDLPWXYZ"


def raw(secret=LIVE_AWS, detector_type="AWS_ACCESS_KEY", path=".env", line=1,
        commit=None, entropy=None):
    content = f'aws_access_key_id = "{secret}"'
    start = content.index(secret)
    return RawFinding(
        detector_type=detector_type, matched_string=secret, file_path=path,
        line_number=line, commit_hash=commit, line_content=content,
        entropy_score=entropy, start_col=start, end_col=start + len(secret),
    )


class TestIsPlaceholder(unittest.TestCase):
    PLACEHOLDERS = [
        "YOUR_API_KEY_HERE", "your-token-here", "insert-your-key",
        "replace_me", "changeme", "<insert-key-here>", "<token>",
        "{{ api_key }}", "AKIAIOSFODNN7EXAMPLE", "placeholder", "dummy",
        "REDACTED", "notasecret", "xxxxxxxx", "00000000", "foobar",
        "sk_test_51Hh0dRandomLookingKeyValue", "",
    ]
    REAL = [
        LIVE_AWS,
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
        "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ4hTgLm2N",
        "Zx9Qk2LpN8vRt5Wm3Yb7Jc1Fd6Hs4Ae0",
    ]

    def test_placeholders_are_recognised(self):
        for value in self.PLACEHOLDERS:
            with self.subTest(value=value):
                self.assertTrue(is_placeholder(value))

    def test_real_looking_secrets_are_not_placeholders(self):
        for value in self.REAL:
            with self.subTest(value=value):
                self.assertFalse(is_placeholder(value))

    def test_password_workflow_labels_are_not_reported_as_secrets(self):
        for value in (
            "change_password",
            "new_password",
            "reset_password",
            "update_password",
            "password_change",
        ):
            with self.subTest(value=value):
                self.assertTrue(is_placeholder(value))

    def test_low_character_variety_is_a_placeholder(self):
        self.assertTrue(is_placeholder("abababababab"))

    def test_case_insensitive(self):
        self.assertTrue(is_placeholder("ChangeMe"))
        self.assertTrue(is_placeholder("CHANGEME"))

    def test_extra_patterns_are_honoured(self):
        self.assertFalse(is_placeholder("acme-internal-token-value"))
        self.assertTrue(is_placeholder("acme-internal-token-value",
                                       extra_patterns=[r"acme-internal"]))

    def test_stripe_test_keys_are_not_live_secrets(self):
        self.assertTrue(is_placeholder("sk_test_4eC39HqLyjWDarjtT1zdp7dc"))
        self.assertFalse(is_placeholder("sk_live_4eC39HqLyjWDarjtT1zdp7dc"))


class TestRedaction(unittest.TestCase):
    def test_prefix_kept_rest_masked(self):
        out = redact_secret(LIVE_AWS)
        self.assertTrue(out.startswith("AKIA"))
        self.assertNotIn(LIVE_AWS, out)
        self.assertEqual(set(out[4:]), {"*"})

    def test_empty_secret(self):
        self.assertEqual(redact_secret(""), "")

    def test_very_short_secret_reveals_nothing(self):
        self.assertEqual(set(redact_secret("abc")), {"*"})

    def test_mask_length_is_capped(self):
        huge = "A" * 5000
        self.assertLessEqual(len(redact_secret(huge)), 24)

    def test_no_input_survives_the_mask(self):
        for value in ("a" * 9, LIVE_AWS, "sk_live_" + "b" * 24):
            with self.subTest(value=value):
                self.assertNotIn(value, redact_secret(value))

    def test_context_line_is_masked_by_span(self):
        s = filter_and_score([raw()])[0]
        self.assertNotIn(LIVE_AWS, s.redacted_context)
        self.assertIn("aws_access_key_id", s.redacted_context)

    def test_context_line_masked_even_without_columns(self):
        rf = RawFinding("AWS_ACCESS_KEY", LIVE_AWS, ".env", 1,
                        line_content=f'key = "{LIVE_AWS}"')
        s = filter_and_score([rf])[0]
        self.assertNotIn(LIVE_AWS, s.redacted_context)

    def test_long_context_line_is_truncated(self):
        rf = RawFinding("AWS_ACCESS_KEY", LIVE_AWS, ".env", 1,
                        line_content="# " + "padding " * 200 + LIVE_AWS)
        s = filter_and_score([rf])[0]
        self.assertLessEqual(len(s.redacted_context), 200)
        self.assertNotIn(LIVE_AWS, s.redacted_context)

    def test_scored_finding_carries_no_plaintext_field(self):
        s = filter_and_score([raw()])[0]
        self.assertNotIn(LIVE_AWS, json.dumps(s.to_dict()))


class TestFilterAndScore(unittest.TestCase):
    def test_placeholders_are_dropped(self):
        scored = filter_and_score([
            raw(), raw(secret="YOUR_API_KEY_HERE", detector_type="GENERIC_API_KEY",
                       path="config/settings.py"),
        ])
        self.assertEqual(len(scored), 1)
        self.assertEqual(scored[0].detector_type, "AWS_ACCESS_KEY")

    def test_keep_placeholders_downgrades_instead_of_dropping(self):
        ctx = ScanContext(keep_placeholders=True)
        scored = filter_and_score(
            [raw(secret="YOUR_API_KEY_HERE", detector_type="GENERIC_API_KEY")], ctx
        )
        self.assertEqual(len(scored), 1)
        self.assertEqual(scored[0].severity, Severity.LOW)
        self.assertIn("placeholder", scored[0].rationale)

    def test_env_file_outranks_test_path_for_the_same_key_type(self):
        scored = filter_and_score([raw(path=".env"), raw(path="tests/test_auth.py")])
        by_path = {s.file_path: s for s in scored}
        self.assertGreater(by_path[".env"].severity,
                           by_path["tests/test_auth.py"].severity)

    def test_file_classification(self):
        cases = {
            ".env": "env", ".env.production": "env",
            "config/prod.yml": "config", "settings.json": "config",
            "src/auth.py": "source", "main.go": "source",
            "tests/test_auth.py": "test", "examples/demo.py": "test",
            "README.md": "docs", "docs/setup.rst": "docs",
            "Makefile": "other",
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                s = filter_and_score([raw(path=path)])[0]
                self.assertEqual(s.file_class, expected)

    def test_docs_are_discounted_the_most(self):
        paths = [".env", "config/prod.yml", "src/auth.py", "tests/t.py", "README.md"]
        points = {p: filter_and_score([raw(path=p)])[0].points for p in paths}
        self.assertEqual(min(points, key=points.get), "README.md")
        self.assertEqual(max(points, key=points.get), ".env")

    def test_entropy_bonus_is_banded(self):
        base = filter_and_score([raw(path="src/a.py")])[0].points
        mid = filter_and_score([raw(path="src/a.py", entropy=4.2)])[0].points
        high = filter_and_score([raw(path="src/a.py", entropy=4.7)])[0].points
        self.assertLess(base, mid)
        self.assertLess(mid, high)

    def test_low_entropy_earns_no_bonus(self):
        base = filter_and_score([raw(path="src/a.py")])[0].points
        low = filter_and_score([raw(path="src/a.py", entropy=2.0)])[0].points
        self.assertEqual(base, low)

    def test_sorted_worst_first(self):
        scored = filter_and_score([
            raw(path="README.md", line=1),
            raw(path=".env", line=2),
            raw(path="src/a.py", line=3),
        ])
        severities = [s.severity for s in scored]
        self.assertEqual(severities, sorted(severities, reverse=True))

    def test_min_severity_filters_the_output(self):
        findings = [raw(path=".env"), raw(path="README.md")]
        self.assertEqual(len(filter_and_score(findings)), 2)
        strict = filter_and_score(findings, ScanContext(min_severity=Severity.CRITICAL))
        self.assertTrue(all(s.severity >= Severity.CRITICAL for s in strict))
        self.assertLess(len(strict), 2)

    def test_unknown_detector_type_gets_the_default_base(self):
        s = filter_and_score([raw(detector_type="SOME_NEW_VENDOR_KEY")])[0]
        self.assertGreater(s.points, 0)
        self.assertIn("SOME_NEW_VENDOR_KEY", s.rationale)

    def test_accepts_plain_dicts(self):
        d = {
            "detector_type": "AWS_ACCESS_KEY", "matched_string": LIVE_AWS,
            "file_path": ".env", "line_number": 3,
            "line_content": f"key={LIVE_AWS}",
        }
        self.assertEqual(len(filter_and_score([d])), 1)

    def test_dicts_with_unknown_keys_are_tolerated(self):
        d = {
            "detector_type": "AWS_ACCESS_KEY", "matched_string": LIVE_AWS,
            "file_path": ".env", "line_number": 3, "future_field": "ignored",
        }
        self.assertEqual(len(filter_and_score([d])), 1)

    def test_rejects_nonsense_input(self):
        with self.assertRaises(TypeError):
            filter_and_score([42])

    def test_empty_input(self):
        self.assertEqual(filter_and_score([]), [])

    def test_rationale_explains_every_applied_modifier(self):
        s = filter_and_score([raw(path=".env", entropy=4.7)])[0]
        for expected in ("base 50", ".env file (+15)", "entropy 4.7 (+10)"):
            self.assertIn(expected, s.rationale)


class TestRenderers(unittest.TestCase):
    def setUp(self):
        self.scored = filter_and_score([
            raw(path=".env"),
            raw(path="src/auth.py", commit="a1b2c3d4e5f6", entropy=4.7),
        ])

    def test_no_renderer_leaks_a_raw_secret(self):
        for fmt in ("terminal", "json", "html"):
            with self.subTest(fmt=fmt):
                out = generate_report(self.scored, fmt, use_color=False)
                self.assertNotIn(LIVE_AWS, out)

    def test_terminal_reports_the_count_and_severities(self):
        out = generate_report(self.scored, "terminal", use_color=False)
        self.assertIn("2 finding(s)", out)
        self.assertIn("Critical", out)

    def test_terminal_empty_result_is_explicit(self):
        self.assertIn("No secrets found", generate_report([], "terminal", use_color=False))

    def test_terminal_color_can_be_forced_off(self):
        self.assertNotIn("\033[", generate_report(self.scored, "terminal", use_color=False))

    def test_terminal_color_can_be_forced_on(self):
        self.assertIn("\033[", generate_report(self.scored, "terminal", use_color=True))

    def test_json_is_valid_and_complete(self):
        parsed = json.loads(generate_report(self.scored, "json"))
        self.assertEqual(len(parsed), 2)
        for row in parsed:
            self.assertIn("severity", row)
            self.assertIsInstance(row["severity"], str)   # label, not an int
            self.assertIn("rationale", row)
            self.assertIn("occurrences", row)

    def test_json_empty_result_is_an_empty_array(self):
        self.assertEqual(json.loads(generate_report([], "json")), [])

    def test_html_is_self_contained(self):
        out = generate_report(self.scored, "html")
        self.assertTrue(out.startswith("<!DOCTYPE html>"))
        # No CDNs or web fonts: the report has to open from a file:// path.
        for remote in ("http://", "src=\"//", "cdn."):
            self.assertNotIn(remote, out)

    def test_html_escapes_the_target(self):
        out = generate_report(self.scored, "html", target='<script>alert(1)</script>')
        self.assertNotIn("<script>alert(1)</script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_html_target_cannot_break_out_of_the_script_block(self):
        # The fix config is embedded as JSON inside <script>. json.dumps does
        # not escape '<', so a target containing '</script>' would close the
        # block early and everything after it would parse as HTML.
        out = generate_report(self.scored, "html",
                              target='</script><img src=x onerror=alert(1)>')
        self.assertNotIn("</script><img", out)
        self.assertIn("\\u003c", out)

    def test_html_escapes_findings(self):
        rf = raw(path='<img src=x onerror=alert(1)>.env')
        out = generate_report(filter_and_score([rf]), "html")
        self.assertNotIn("<img src=x", out)

    def test_html_empty_result_says_all_clear(self):
        self.assertIn("no secrets found", generate_report([], "html"))

    def test_unknown_format_raises(self):
        with self.assertRaises(ValueError):
            generate_report(self.scored, "pdf")

    def test_output_path_is_written(self):
        path = os.path.join(tempfile.mkdtemp(prefix="sentryrep_"), "out.json")
        returned = generate_report(self.scored, "json", output_path=path)
        with open(path, encoding="utf-8") as f:
            self.assertEqual(f.read(), returned)
        os.remove(path)

    def test_format_aliases(self):
        for alias in ("terminal", "TERMINAL", "text", "cli"):
            with self.subTest(alias=alias):
                self.assertIn("finding(s)",
                              generate_report(self.scored, alias, use_color=False))


class TestExitCode(unittest.TestCase):
    def setUp(self):
        self.scored = filter_and_score([raw(path=".env")])   # one Critical
        self.assertEqual(self.scored[0].severity, Severity.CRITICAL)

    def test_fail_on_none_never_fails(self):
        self.assertEqual(exit_code(self.scored, "none"), 0)

    def test_fail_on_none_object_never_fails(self):
        self.assertEqual(exit_code(self.scored, None), 0)

    def test_fail_on_matching_severity_trips(self):
        self.assertEqual(exit_code(self.scored, "critical"), 1)

    def test_fail_on_lower_severity_also_trips(self):
        for level in ("low", "medium", "high"):
            with self.subTest(level=level):
                self.assertEqual(exit_code(self.scored, level), 1)

    def test_threshold_above_everything_present_passes(self):
        docs = filter_and_score([raw(path="README.md")])
        self.assertTrue(all(s.severity < Severity.CRITICAL for s in docs))
        self.assertEqual(exit_code(docs, "critical"), 0)

    def test_clean_scan_passes_every_threshold(self):
        for level in ("low", "medium", "high", "critical", "none"):
            with self.subTest(level=level):
                self.assertEqual(exit_code([], level), 0)

    def test_severity_enum_accepted_directly(self):
        self.assertEqual(exit_code(self.scored, Severity.CRITICAL), 1)

    def test_case_insensitive(self):
        self.assertEqual(exit_code(self.scored, "CRITICAL"), 1)

    def test_unknown_threshold_raises(self):
        with self.assertRaises(ValueError):
            exit_code(self.scored, "catastrophic")


class TestSeverityEnum(unittest.TestCase):
    def test_ordering(self):
        self.assertLess(Severity.LOW, Severity.MEDIUM)
        self.assertLess(Severity.MEDIUM, Severity.HIGH)
        self.assertLess(Severity.HIGH, Severity.CRITICAL)

    def test_labels(self):
        self.assertEqual(Severity.CRITICAL.label, "Critical")
        self.assertEqual(Severity.LOW.label, "Low")

    def test_to_dict_uses_the_label_not_the_int(self):
        s = filter_and_score([raw()])[0]
        self.assertEqual(s.to_dict()["severity"], "Critical")


class TestScoredFindingShape(unittest.TestCase):
    def test_defaults_for_a_hand_built_finding(self):
        s = ScoredFinding(
            detector_type="X", file_path="a.py", line_number=1,
            severity=Severity.LOW, points=1, exposure="working_tree",
            commit_hash=None, redacted="x*", redacted_context="k=x*",
            rationale="because",
        )
        self.assertEqual(s.occurrences, 1)
        self.assertEqual(s.history_commits, ())
        self.assertFalse(s.in_history)


if __name__ == "__main__":
    unittest.main(verbosity=2)
