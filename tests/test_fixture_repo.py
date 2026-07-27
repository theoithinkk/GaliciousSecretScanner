"""
tests/test_fixture_repo.py
--------------------------
Runs scripts/make_test_repo.py's own verification against a freshly built
fixture, so the vulnerable repo's 50-odd expectations are enforced on every test
run rather than only when someone remembers to pass --verify by hand.

This is the broadest test in the suite: it builds a realistic multi-commit repo
and asserts detector coverage, file-class scoring, exposure labelling, dedup,
ignore rules and redaction all at once. When it fails alongside a unit test,
fix the unit test first -- this one is downstream of everything.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import tempfile
import unittest

from _helpers import REPO_ROOT, git_available  # noqa: F401  (sys.path side effect)

_SCRIPT = os.path.join(REPO_ROOT, "scripts", "make_test_repo.py")


def _load_generator():
    """Import the generator by path -- scripts/ isn't an importable package."""
    spec = importlib.util.spec_from_file_location("make_test_repo", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(git_available(), "git is not installed")
class TestFixtureRepo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gen = _load_generator()
        cls.out = os.path.join(tempfile.mkdtemp(prefix="sentryfixture_"), "vuln-repo")
        cls.gen.build(cls.out, force=True)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(os.path.dirname(cls.out), ignore_errors=True)

    def test_script_exists_where_the_docs_say_it_does(self):
        self.assertTrue(os.path.isfile(_SCRIPT))

    def test_fixture_builds_a_real_git_repo_with_history(self):
        self.assertTrue(os.path.isdir(os.path.join(self.out, ".git")))
        log = self.gen._git(self.out, "log", "--oneline")
        self.assertEqual(len(log.strip().splitlines()), len(self.gen.STEPS))

    def test_deleted_file_is_absent_from_the_working_tree(self):
        # The history-only case depends on this actually being gone.
        self.assertFalse(os.path.exists(os.path.join(self.out, "src", "legacy_auth.py")))

    def test_uncommitted_file_is_untracked(self):
        status = self.gen._git(self.out, "status", "--porcelain", "--untracked-files=all")
        self.assertIn(".env.local", status)

    def test_all_fixture_expectations_hold(self):
        # verify() prints a PASS/FAIL table; capture it and surface it only on
        # failure so a green run stays quiet.
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = self.gen.verify(self.out)
        self.assertEqual(code, 0, "\n" + buffer.getvalue())

    def test_planted_secrets_are_format_valid(self):
        # A typo in one of the constants would silently make a detector look
        # broken, so check the shapes the regexes actually require.
        g = self.gen
        self.assertRegex(g.AWS_KEY, r"^AKIA[0-9A-Z]{16}$")
        self.assertEqual(len(g.AWS_SECRET), 40)
        self.assertRegex(g.GITHUB_TOKEN, r"^ghp_[A-Za-z0-9]{36}$")
        self.assertRegex(g.GOOGLE_KEY, r"^AIza[0-9A-Za-z\-_]{35}$")
        self.assertRegex(g.STRIPE_LIVE, r"^sk_live_[0-9a-zA-Z]{24,}$")
        self.assertRegex(g.STRIPE_LEGACY, r"^sk_live_[0-9a-zA-Z]{24,}$")

    def test_planted_secrets_are_not_placeholders(self):
        # If a planted value tripped the placeholder filter it would be
        # suppressed, and the detector it was meant to exercise would go
        # untested while still looking green.
        from scorer_reporter import is_placeholder

        for name, value in vars(self.gen).items():
            if name.isupper() and isinstance(value, str) and name in {
                "AWS_KEY", "AWS_SECRET", "STRIPE_LIVE", "STRIPE_LEGACY",
                "GITHUB_TOKEN", "GOOGLE_KEY", "SLACK_TOKEN", "JWT",
                "API_KEY", "ACCESS_TOKEN", "DB_PASSWORD",
                "ENTROPY_BLOB", "ENTROPY_BLOB_2",
            }:
                with self.subTest(secret=name):
                    self.assertFalse(is_placeholder(value),
                                     f"{name} would be suppressed as a placeholder")

    def test_expectation_lists_are_not_silently_empty(self):
        self.assertGreaterEqual(len(self.gen.EXPECT_FOUND), 15)
        self.assertGreaterEqual(len(self.gen.EXPECT_SILENT), 5)

    def test_every_configured_detector_type_is_planted(self):
        from pattern_detector import load_patterns

        configured = {p.type for p in load_patterns()}
        planted = {detector for _, detector, _ in self.gen.EXPECT_FOUND}
        self.assertEqual(configured - planted, set(),
                         "detector types with no planted secret in the fixture")


if __name__ == "__main__":
    unittest.main(verbosity=2)
