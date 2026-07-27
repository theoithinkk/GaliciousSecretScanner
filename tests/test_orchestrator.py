"""
tests/test_orchestrator.py
--------------------------
End-to-end tests through orchestrator.run_scan(), the single entry point both
app.py and cli.py call. These are the tests that would have caught the pipeline
wiring being wrong even while every module passed its own unit tests: detector
output not reaching the scorer, walker metadata not being merged, ignore rules
not being threaded through, and so on.
"""

from __future__ import annotations

import unittest

from _helpers import TempRepo, git_available  # noqa: F401  (sys.path side effect)

from models import ScanContext, Severity
from orchestrator import collect_raw_findings, run_scan
from scorer_reporter import generate_report

AWS_KEY = "AKIA3RJQ7KZ2NDLPWXYZ"
STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
CUSTOM_TOKEN = "Zx9Qk2LpN8vRt5Wm3Yb7Jc1Fd6Hs4Ae0"


def planted_repo(git: bool = False) -> TempRepo:
    """A repo with one of each interesting case planted in it."""
    repo = TempRepo(git=git)
    repo.write(".env", f"AWS_ACCESS_KEY_ID={AWS_KEY}\nDEBUG=true")
    repo.write("src/payments.py", f'stripe_key = "{STRIPE_KEY}"')
    # Unquoted, so the regex library's GENERIC_SECRET (which requires quotes)
    # can't see it -- only the entropy detector catches this one.
    repo.write("src/session.py", f"custom_token={CUSTOM_TOKEN}")
    repo.write("config/settings.py", 'api_key = "YOUR_API_KEY_HERE"')
    repo.write("tests/test_auth.py", f'key = "{AWS_KEY}"')
    repo.write("README.md", "Set `api_key` to your key. Do not commit secrets.")
    repo.write("src/util.py", "def add(a, b):\n    return a + b")
    return repo


class TestRunScan(unittest.TestCase):
    def setUp(self):
        self.repo = planted_repo()
        self.addCleanup(self.repo.cleanup)
        self.scored = run_scan(self.repo.path)
        self.by_path = {}
        for s in self.scored:
            self.by_path.setdefault(s.file_path.replace("\\", "/"), []).append(s)

    def test_finds_the_planted_secrets(self):
        for path in (".env", "src/payments.py", "src/session.py"):
            with self.subTest(path=path):
                self.assertIn(path, self.by_path)

    def test_regex_and_entropy_detectors_both_contribute(self):
        types = {s.detector_type for s in self.scored}
        self.assertIn("STRIPE_KEY", types, "pattern_detector output missing")
        # src/session.py holds an unquoted value no regex pattern matches, so
        # a surviving HIGH_ENTROPY finding proves the entropy detector is wired
        # in. Where both detectors fire on the same text, dedup keeps the more
        # specific type -- see test_entropy_evidence_survives_dedup for that.
        self.assertIn("HIGH_ENTROPY", types, "entropy_detector output missing")

    def test_entropy_evidence_survives_dedup(self):
        # The Stripe key trips both detectors. STRIPE_KEY wins the merge, but
        # the entropy score measured by the loser must come along with it.
        stripe = next(s for s in self.scored if s.detector_type == "STRIPE_KEY")
        self.assertIsNotNone(stripe.entropy_score,
                             "entropy score was lost when dedup merged the pair")

    def test_placeholder_is_suppressed(self):
        self.assertNotIn("config/settings.py", self.by_path)

    def test_clean_file_produces_nothing(self):
        self.assertNotIn("src/util.py", self.by_path)

    def test_walker_metadata_reaches_the_findings(self):
        env = self.by_path[".env"][0]
        self.assertEqual(env.line_number, 1)
        self.assertEqual(env.exposure, "working_tree")
        self.assertIsNone(env.commit_hash)

    def test_env_secret_outranks_the_same_key_in_tests(self):
        env = max(s.points for s in self.by_path[".env"])
        tests = max(s.points for s in self.by_path["tests/test_auth.py"])
        self.assertGreater(env, tests)

    def test_results_are_sorted_worst_first(self):
        severities = [s.severity for s in self.scored]
        self.assertEqual(severities, sorted(severities, reverse=True))

    def test_one_finding_per_secret_per_file(self):
        # The AWS key in .env trips the AKIA regex and looks high-entropy;
        # dedup must leave exactly one finding for it.
        env_aws = [s for s in self.by_path[".env"] if AWS_KEY[:4] in s.redacted]
        self.assertEqual(len(env_aws), 1, env_aws)

    def test_no_report_leaks_a_planted_secret(self):
        for fmt in ("terminal", "json", "html"):
            with self.subTest(fmt=fmt):
                out = generate_report(self.scored, fmt, use_color=False)
                for secret in (AWS_KEY, STRIPE_KEY, CUSTOM_TOKEN):
                    self.assertNotIn(secret, out)

    def test_min_severity_is_threaded_through(self):
        strict = run_scan(self.repo.path,
                          context=ScanContext(min_severity=Severity.CRITICAL))
        self.assertTrue(all(s.severity >= Severity.CRITICAL for s in strict))
        self.assertLess(len(strict), len(self.scored))

    def test_ignore_rules_are_threaded_through(self):
        filtered = run_scan(self.repo.path, ignore_rules=["src/"])
        paths = {s.file_path.replace("\\", "/") for s in filtered}
        self.assertNotIn("src/payments.py", paths)
        self.assertIn(".env", paths)

    def test_clean_repo_returns_no_findings(self):
        with TempRepo(git=False) as clean:
            clean.write("main.py", "print('hello')")
            self.assertEqual(run_scan(clean.path), [])

    def test_empty_repo_returns_no_findings(self):
        with TempRepo(git=False) as empty:
            self.assertEqual(run_scan(empty.path), [])


class TestScanModes(unittest.TestCase):
    def test_full_scan_reaches_ignored_directories(self):
        with TempRepo(git=False) as repo:
            repo.write("node_modules/leaky/config.js",
                       f'const stripe = "{STRIPE_KEY}";')

            quick = run_scan(repo.path, full_scan=False)
            full = run_scan(repo.path, full_scan=True)

        self.assertEqual(quick, [])
        self.assertTrue(full)
        self.assertEqual(full[0].detector_type, "STRIPE_KEY")

    def test_quick_scan_is_the_default(self):
        with TempRepo(git=False) as repo:
            repo.write("node_modules/leaky/config.js",
                       f'const stripe = "{STRIPE_KEY}";')
            self.assertEqual(run_scan(repo.path), [])


class TestCollectRawFindings(unittest.TestCase):
    def test_raw_findings_carry_both_detector_and_walker_metadata(self):
        with TempRepo(git=False) as repo:
            repo.write("src/a.py", f'stripe_key = "{STRIPE_KEY}"')
            raws = collect_raw_findings(repo.path)

        self.assertTrue(raws)
        hit = next(r for r in raws if r.detector_type == "STRIPE_KEY")
        self.assertEqual(hit.matched_string, STRIPE_KEY)      # from the detector
        self.assertEqual(hit.line_number, 1)                  # from the walker
        self.assertIn("a.py", hit.file_path)                  # from the walker
        self.assertIn(STRIPE_KEY, hit.line_content)           # from the walker

    def test_raw_findings_are_not_yet_deduplicated(self):
        # collect_raw_findings is deliberately raw: both detectors fire and
        # dedup happens later, in filter_and_score.
        with TempRepo(git=False) as repo:
            repo.write(".env", f"AWS_ACCESS_KEY_ID={AWS_KEY}")
            raws = collect_raw_findings(repo.path)
            scored = run_scan(repo.path)

        self.assertGreater(len(raws), 1, "expected overlapping detector hits")
        self.assertEqual(len(scored), 1)

    def test_columns_index_into_the_reported_line(self):
        with TempRepo(git=False) as repo:
            repo.write("src/a.py", f'stripe_key = "{STRIPE_KEY}"')
            raws = collect_raw_findings(repo.path)

        for r in raws:
            if r.start_col is not None:
                with self.subTest(type=r.detector_type):
                    self.assertEqual(
                        r.line_content[r.start_col:r.end_col], r.matched_string
                    )


@unittest.skipUnless(git_available(), "git is not installed")
class TestHistoryScanning(unittest.TestCase):
    def test_finds_a_secret_removed_from_the_working_tree(self):
        with TempRepo() as repo:
            repo.write("old_config.py", f'stripe_key = "{STRIPE_KEY}"')
            repo.commit("add config")
            repo.remove("old_config.py")
            repo.commit("remove config")

            without = run_scan(repo.path, history=False)
            with_history = run_scan(repo.path, history=True)

        self.assertEqual(without, [])
        self.assertTrue(with_history)
        self.assertEqual(with_history[0].exposure, "history_only")

    def test_history_scan_of_a_live_secret_stays_one_finding(self):
        with TempRepo() as repo:
            repo.write(".env", f"AWS_ACCESS_KEY_ID={AWS_KEY}")
            repo.commit("add env")
            repo.write(".env", f"AWS_ACCESS_KEY_ID={AWS_KEY}\nDEBUG=true")
            repo.commit("add debug flag")

            scored = run_scan(repo.path, history=True)

        env = [s for s in scored if s.file_path.endswith(".env")]
        self.assertEqual(len(env), 1, env)
        self.assertEqual(env[0].exposure, "working_tree")
        self.assertTrue(env[0].in_history)

    def test_max_commits_is_threaded_through(self):
        with TempRepo() as repo:
            repo.write("a.py", f'stripe_key = "{STRIPE_KEY}"')
            repo.commit("leak")
            repo.remove("a.py")
            repo.commit("cleanup")
            # Only look at the newest commit: the leak predates it.
            capped = run_scan(repo.path, history=True, max_commits=1)

        self.assertEqual(capped, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
