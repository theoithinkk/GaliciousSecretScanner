"""
tests/test_entropy_detector.py
------------------------------
Covers the entropy fallback detector: the Shannon maths, the cheap structural
rejects that run before it, the suspicious-context requirement that keeps false
positives down, and the two extraction passes (clean assignment, then quoted
strings on a suspicious line).

This is the file entropy_detector.py's docstring has been pointing at.
"""

from __future__ import annotations

import math
import unittest

from _helpers import REPO_ROOT  # noqa: F401  (sys.path side effect)

from entropy_detector import (
    ENTROPY_THRESHOLD,
    MIN_CANDIDATE_LENGTH,
    detect,
    make_detector,
    shannon_entropy,
)

# 32 chars, mixed case + digits, no repeats to speak of -- comfortably random.
RANDOM_VALUE = "Zx9Qk2LpN8vRt5Wm3Yb7Jc1Fd6Hs4Ae0"


class TestShannonEntropy(unittest.TestCase):
    def test_empty_string_is_zero(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_single_repeated_character_is_zero(self):
        self.assertEqual(shannon_entropy("aaaaaaaa"), 0.0)

    def test_two_equally_likely_characters_is_one_bit(self):
        self.assertAlmostEqual(shannon_entropy("abab"), 1.0)

    def test_four_equally_likely_characters_is_two_bits(self):
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)

    def test_n_distinct_characters_tops_out_at_log2_n(self):
        s = "abcdefgh"
        self.assertAlmostEqual(shannon_entropy(s), math.log2(len(set(s))))

    def test_random_looking_secret_clears_the_threshold(self):
        self.assertGreater(shannon_entropy(RANDOM_VALUE), ENTROPY_THRESHOLD)

    def test_entropy_is_per_character_not_total(self):
        # Doubling the string doesn't change bits/char.
        self.assertAlmostEqual(shannon_entropy("abcd"), shannon_entropy("abcdabcd"))


class TestSuspiciousContext(unittest.TestCase):
    """The context requirement is what makes this detector usable."""

    def test_random_value_in_a_secret_named_variable_is_flagged(self):
        hits = detect(f'custom_token = "{RANDOM_VALUE}"')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].type, "HIGH_ENTROPY")
        self.assertEqual(hits[0].matched_string, RANDOM_VALUE)

    def test_same_value_in_a_boring_variable_is_ignored(self):
        # Identical entropy, no secret-ish name: a build hash or cache key.
        self.assertEqual(detect(f'build_hash = "{RANDOM_VALUE}"'), [])

    def test_all_context_words_are_recognised(self):
        for word in ("key", "token", "secret", "password", "passwd", "pwd",
                     "auth", "credential"):
            with self.subTest(word=word):
                self.assertTrue(detect(f'my_{word}_value = "{RANDOM_VALUE}"'))

    def test_context_match_is_case_insensitive(self):
        self.assertTrue(detect(f'API_TOKEN = "{RANDOM_VALUE}"'))

    def test_custom_context_words_via_make_detector(self):
        d = make_detector(context_words=("nonce",))
        self.assertTrue(d(f'nonce = "{RANDOM_VALUE}"'))
        self.assertEqual(d(f'token = "{RANDOM_VALUE}"'), [])


class TestAssignmentShapes(unittest.TestCase):
    def test_equals_with_double_quotes(self):
        self.assertTrue(detect(f'token = "{RANDOM_VALUE}"'))

    def test_equals_with_single_quotes(self):
        self.assertTrue(detect(f"token = '{RANDOM_VALUE}'"))

    def test_colon_separator_yaml_style(self):
        self.assertTrue(detect(f"api_token: {RANDOM_VALUE}"))

    def test_bare_unquoted_env_style_value(self):
        # The regex detector can't see unquoted .env values; this one can.
        self.assertTrue(detect(f"SECRET_KEY={RANDOM_VALUE}"))

    def test_json_style_quoted_key(self):
        self.assertTrue(detect(f'"apiToken": "{RANDOM_VALUE}"'))

    def test_positional_argument_fallback(self):
        # No clean name=value pair, but the line mentions a keyword.
        hits = detect(f'authenticate(user, "{RANDOM_VALUE}")')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].matched_string, RANDOM_VALUE)

    def test_quoted_fallback_does_not_double_report_pass_one_hits(self):
        # A clean assignment on a suspicious line must yield exactly one hit,
        # not one from each extraction pass.
        self.assertEqual(len(detect(f'secret_token = "{RANDOM_VALUE}"')), 1)

    def test_columns_bracket_the_value(self):
        line = f'token = "{RANDOM_VALUE}"'
        hit = detect(line)[0]
        self.assertEqual(line[hit.start_col:hit.end_col], RANDOM_VALUE)

    def test_two_secrets_on_one_line_both_reported(self):
        other = "kP3xM8vZ2qL9wR5tY7bN4cF1dH6sA0eU"
        hits = detect(f'token = "{RANDOM_VALUE}"; api_key = "{other}"')
        self.assertEqual({h.matched_string for h in hits}, {RANDOM_VALUE, other})


class TestStructuralRejects(unittest.TestCase):
    """Cheap checks that run before the entropy maths."""

    def test_uuid_is_ignored(self):
        self.assertEqual(detect('session_key = "550e8400-e29b-41d4-a716-446655440000"'), [])

    def test_hex_colour_is_ignored(self):
        self.assertEqual(detect('key_color = "#3498db"'), [])

    def test_all_digits_is_ignored(self):
        self.assertEqual(detect('token = "12345678901234567890"'), [])

    def test_prose_with_whitespace_is_ignored(self):
        self.assertEqual(detect('secret = "lorem ipsum dolor sit amet consectetur"'), [])

    def test_common_words_are_ignored(self):
        for word in ("changeme", "placeholder", "development", "administrator"):
            with self.subTest(word=word):
                self.assertEqual(detect(f'password = "{word}"'), [])

    def test_value_shorter_than_the_floor_is_ignored(self):
        short = "aB3dE" * 2  # 10 chars, under MIN_CANDIDATE_LENGTH
        self.assertLess(len(short), MIN_CANDIDATE_LENGTH)
        self.assertEqual(detect(f'token = "{short}"'), [])

    def test_length_floor_boundary(self):
        # Exactly at the floor, with enough variety to clear the threshold.
        at_floor = "aB3dE7gH1jK9"
        self.assertEqual(len(at_floor), MIN_CANDIDATE_LENGTH)
        self.assertGreater(shannon_entropy(at_floor), ENTROPY_THRESHOLD)
        self.assertTrue(detect(f'token = "{at_floor}"'))

    def test_long_low_entropy_value_is_ignored(self):
        low = "abababababababababab"
        self.assertLess(shannon_entropy(low), ENTROPY_THRESHOLD)
        self.assertEqual(detect(f'token = "{low}"'), [])

    def test_env_lookups_are_not_secrets(self):
        # These are what a FIXED codebase looks like. Flagging them would mean
        # the scanner penalises the remediation it recommends -- and would make
        # fixer.py's rewrite appear not to have worked.
        for line in (
            'stripe.api_key = os.environ["STRIPE_API_KEY"]',
            'token = os.getenv("SERVICE_TOKEN")',
            "const key = process.env.STRIPE_SECRET_KEY;",
            'password = ENV["DB_PASSWORD"]',
            'secret = getenv("APP_SECRET")',
            "db_password: ${DATABASE_PASSWORD}",
            'api_key = "{{ vault_api_key }}"',
        ):
            with self.subTest(line=line):
                self.assertEqual(detect(line), [], f"{line!r} was flagged")

    def test_a_real_literal_next_to_a_lookup_is_still_caught(self):
        # The reject must key off the value, not the whole line -- otherwise
        # one env lookup would blind the detector to a genuine literal.
        line = f'a = os.environ["X"]; real_token = "{RANDOM_VALUE}"'
        self.assertEqual([h.matched_string for h in detect(line)], [RANDOM_VALUE])

    def test_empty_and_boring_lines(self):
        for line in ("", "x = 42", "import os", "# a comment about tokens"):
            with self.subTest(line=line):
                self.assertEqual(detect(line), [])


class TestTuning(unittest.TestCase):
    def test_reported_entropy_matches_the_value(self):
        hit = detect(f'token = "{RANDOM_VALUE}"')[0]
        self.assertAlmostEqual(hit.entropy_score,
                               round(shannon_entropy(RANDOM_VALUE), 2))

    def test_raising_the_threshold_suppresses_a_hit(self):
        strict = make_detector(threshold=9.0)  # above the 6.0 ceiling
        self.assertEqual(strict(f'token = "{RANDOM_VALUE}"'), [])

    def test_lowering_the_length_floor_alone_admits_nothing_new(self):
        # A string of n distinct characters has entropy log2(n), so nothing
        # shorter than 2**3.5 ~= 11.3 chars can clear ENTROPY_THRESHOLD=3.5 no
        # matter what MIN_CANDIDATE_LENGTH is set to. The length floor of 12
        # therefore sits right where the threshold already cuts -- it's a
        # cheap early-out, not an independent filter. Worth knowing before
        # anyone tunes one of the two constants and expects it to matter.
        short = "aB3dE7gH"  # 8 distinct chars -> exactly 3.0 bits/char
        self.assertLess(shannon_entropy(short), ENTROPY_THRESHOLD)
        self.assertEqual(make_detector(min_length=4)(f'token = "{short}"'), [])

    def test_lowering_both_knobs_admits_shorter_values(self):
        short = "aB3dE7gH"
        self.assertEqual(detect(f'token = "{short}"'), [])
        loose = make_detector(min_length=4, threshold=2.5)
        self.assertTrue(loose(f'token = "{short}"'))

    def test_make_detector_does_not_mutate_module_defaults(self):
        make_detector(threshold=9.0, min_length=99)
        self.assertTrue(detect(f'token = "{RANDOM_VALUE}"'),
                        "module-level detect() was affected by make_detector()")


if __name__ == "__main__":
    unittest.main(verbosity=2)
