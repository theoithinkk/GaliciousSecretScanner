"""
tests/test_dedup.py
-------------------
Covers scorer_reporter.deduplicate() and the exposure labelling that depends
on it.

The bug these guard against: one AWS key, in one file, scanned with --history
reported as FOUR findings -- the regex detector and the entropy detector each
firing on the same 20 characters, times the working-tree walk and the history
walk both seeing it. Two of the four claimed the key had been "removed from the
working tree" while it was sitting in HEAD, and took a severity discount for it.
"""

from __future__ import annotations

import json
import unittest

from _helpers import TempRepo, git_available  # noqa: F401  (sys.path side effect)

from models import RawFinding, Severity
from scorer_reporter import deduplicate, filter_and_score

AWS_KEY = "AKIA3RJQ7KZ2NDLPWXYZ"
OTHER_KEY = "AKIA7WQ4MZ8XCVBNLKJH"


def raw(detector_type, secret, path="app.py", line=1, commit=None,
        entropy=None, start=None, end=None, content=None):
    """Terser RawFinding for tests; columns default to bracketing the secret."""
    if content is None:
        content = f'key = "{secret}"'
    if start is None and secret in content:
        start = content.index(secret)
        end = start + len(secret)
    return RawFinding(
        detector_type=detector_type,
        matched_string=secret,
        file_path=path,
        line_number=line,
        commit_hash=commit,
        line_content=content,
        entropy_score=entropy,
        start_col=start,
        end_col=end,
    )


class TestOverlappingDetectorHits(unittest.TestCase):
    """Pass 1: both detectors describing the same bytes."""

    def test_two_detectors_same_span_collapse_to_one(self):
        merged = deduplicate([
            raw("AWS_ACCESS_KEY", AWS_KEY),
            raw("HIGH_ENTROPY", AWS_KEY, entropy=4.7),
        ])
        self.assertEqual(len(merged), 1)

    def test_more_specific_detector_wins(self):
        # HIGH_ENTROPY (base 20) must not outrank AWS_ACCESS_KEY (base 50)
        # just because it happened to be appended second.
        for order in ([("AWS_ACCESS_KEY", None), ("HIGH_ENTROPY", 4.7)],
                      [("HIGH_ENTROPY", 4.7), ("AWS_ACCESS_KEY", None)]):
            merged = deduplicate([raw(t, AWS_KEY, entropy=e) for t, e in order])
            self.assertEqual(merged[0].detector_type, "AWS_ACCESS_KEY", order)

    def test_entropy_evidence_survives_the_merge(self):
        # The AKIA hit wins but carries no entropy score of its own. If we
        # dropped the entropy hit outright we'd also drop the +10 bonus.
        merged = deduplicate([
            raw("AWS_ACCESS_KEY", AWS_KEY),
            raw("HIGH_ENTROPY", AWS_KEY, entropy=4.7),
        ])
        self.assertEqual(merged[0].entropy_score, 4.7)

    def test_two_distinct_secrets_on_one_line_stay_separate(self):
        content = f'a = "{AWS_KEY}"; b = "{OTHER_KEY}"'
        merged = deduplicate([
            raw("AWS_ACCESS_KEY", AWS_KEY, content=content),
            raw("AWS_ACCESS_KEY", OTHER_KEY, content=content),
        ])
        self.assertEqual(len(merged), 2)

    def test_same_secret_on_different_lines_of_same_file_is_one_leak(self):
        # Line numbers drift across commits, so (file, secret) is the identity
        # of a leak -- not (file, line, secret).
        merged = deduplicate([
            raw("AWS_ACCESS_KEY", AWS_KEY, line=3),
            raw("AWS_ACCESS_KEY", AWS_KEY, line=40),
        ])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].occurrences, 2)

    def test_same_secret_in_different_files_stays_separate(self):
        merged = deduplicate([
            raw("AWS_ACCESS_KEY", AWS_KEY, path=".env"),
            raw("AWS_ACCESS_KEY", AWS_KEY, path="config/prod.yml"),
        ])
        self.assertEqual(len(merged), 2)

    def test_windows_and_posix_paths_are_the_same_file(self):
        merged = deduplicate([
            raw("AWS_ACCESS_KEY", AWS_KEY, path="config\\prod.yml"),
            raw("AWS_ACCESS_KEY", AWS_KEY, path="config/prod.yml"),
        ])
        self.assertEqual(len(merged), 1)

    def test_missing_columns_fall_back_to_comparing_text(self):
        merged = deduplicate([
            raw("AWS_ACCESS_KEY", AWS_KEY, start=None, end=None),
            raw("HIGH_ENTROPY", AWS_KEY, entropy=4.2, start=None, end=None),
        ])
        self.assertEqual(len(merged), 1)

    def test_order_is_stable(self):
        merged = deduplicate([
            raw("AWS_ACCESS_KEY", AWS_KEY, path="a.py"),
            raw("AWS_ACCESS_KEY", OTHER_KEY, path="b.py"),
        ])
        self.assertEqual([m.file_path for m in merged], ["a.py", "b.py"])

    def test_empty_input(self):
        self.assertEqual(deduplicate([]), [])


class TestCollapseAcrossCommits(unittest.TestCase):
    """Pass 2: `git log -p --all` replaying the same secret once per commit."""

    def test_many_commits_collapse_to_one_finding(self):
        merged = deduplicate([
            raw("AWS_ACCESS_KEY", AWS_KEY, commit="ccc333"),
            raw("AWS_ACCESS_KEY", AWS_KEY, commit="bbb222"),
            raw("AWS_ACCESS_KEY", AWS_KEY, commit="aaa111"),
        ])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].occurrences, 3)

    def test_history_commits_are_oldest_first(self):
        # git log walks newest-first, so the commit that INTRODUCED the secret
        # is the last one the walker handed us.
        merged = deduplicate([
            raw("AWS_ACCESS_KEY", AWS_KEY, commit="ccc333"),
            raw("AWS_ACCESS_KEY", AWS_KEY, commit="bbb222"),
            raw("AWS_ACCESS_KEY", AWS_KEY, commit="aaa111"),
        ])
        self.assertEqual(merged[0].history_commits, ("aaa111", "bbb222", "ccc333"))

    def test_repeated_commit_hash_recorded_once(self):
        merged = deduplicate([
            raw("AWS_ACCESS_KEY", AWS_KEY, commit="aaa111", line=1),
            raw("AWS_ACCESS_KEY", AWS_KEY, commit="aaa111", line=9),
        ])
        self.assertEqual(merged[0].history_commits, ("aaa111",))

    def test_history_only_leak_keeps_a_commit_hash(self):
        merged = deduplicate([raw("AWS_ACCESS_KEY", AWS_KEY, commit="aaa111")])
        self.assertIsNotNone(merged[0].commit_hash)

    def test_live_copy_wins_over_history_copies(self):
        merged = deduplicate([
            raw("AWS_ACCESS_KEY", AWS_KEY, commit="ccc333"),
            raw("AWS_ACCESS_KEY", AWS_KEY, commit=None),      # working tree
            raw("AWS_ACCESS_KEY", AWS_KEY, commit="aaa111"),
        ])
        self.assertEqual(len(merged), 1)
        self.assertIsNone(merged[0].commit_hash, "live copy must represent the leak")
        self.assertEqual(merged[0].history_commits, ("aaa111", "ccc333"))


class TestExposureLabelling(unittest.TestCase):
    """The scoring consequences of getting dedup right."""

    def _one(self, findings):
        scored = filter_and_score(findings)
        self.assertEqual(len(scored), 1, scored)
        return scored[0]

    def test_live_and_committed_is_not_labelled_history_only(self):
        s = self._one([
            raw("AWS_ACCESS_KEY", AWS_KEY, path=".env", commit=None),
            raw("AWS_ACCESS_KEY", AWS_KEY, path=".env", commit="aaa111"),
        ])
        self.assertEqual(s.exposure, "working_tree")
        self.assertNotIn("removed from working tree", s.rationale)

    def test_live_and_committed_reports_the_history_exposure_too(self):
        s = self._one([
            raw("AWS_ACCESS_KEY", AWS_KEY, path=".env", commit=None),
            raw("AWS_ACCESS_KEY", AWS_KEY, path=".env", commit="aaa111"),
        ])
        self.assertTrue(s.in_history)
        self.assertIn("committed to history", s.rationale)
        self.assertIn("aaa111", s.rationale)

    def test_live_and_committed_keeps_no_history_discount(self):
        live_only = self._one([raw("AWS_ACCESS_KEY", AWS_KEY, path=".env")])
        live_and_committed = self._one([
            raw("AWS_ACCESS_KEY", AWS_KEY, path=".env", commit=None),
            raw("AWS_ACCESS_KEY", AWS_KEY, path=".env", commit="aaa111"),
        ])
        self.assertEqual(live_and_committed.points, live_only.points)

    def test_history_only_still_takes_the_discount(self):
        live = self._one([raw("AWS_ACCESS_KEY", AWS_KEY, path=".env")])
        gone = self._one([raw("AWS_ACCESS_KEY", AWS_KEY, path=".env", commit="aaa111")])
        self.assertEqual(gone.exposure, "history_only")
        self.assertEqual(gone.points, live.points - 5)
        self.assertIn("removed from working tree", gone.rationale)

    def test_occurrences_reach_the_scored_finding(self):
        s = self._one([
            raw("AWS_ACCESS_KEY", AWS_KEY, commit="aaa111"),
            raw("AWS_ACCESS_KEY", AWS_KEY, commit="bbb222"),
        ])
        self.assertEqual(s.occurrences, 2)

    def test_merged_entropy_raises_severity_as_intended(self):
        # Merging is not just cosmetic: the entropy carried off the duplicate
        # is worth +10, which is what a real AKIA-in-.env should score.
        s = self._one([
            raw("AWS_ACCESS_KEY", AWS_KEY, path=".env"),
            raw("HIGH_ENTROPY", AWS_KEY, path=".env", entropy=4.7),
        ])
        self.assertEqual(s.severity, Severity.CRITICAL)
        self.assertEqual(s.entropy_score, 4.7)

    def test_history_commits_survive_json_serialisation(self):
        # Fed newest-first, the way the walker yields them.
        s = self._one([
            raw("AWS_ACCESS_KEY", AWS_KEY, commit="bbb222"),
            raw("AWS_ACCESS_KEY", AWS_KEY, commit="aaa111"),
        ])
        d = s.to_dict()
        self.assertEqual(d["history_commits"], ["aaa111", "bbb222"])
        self.assertIsInstance(d["history_commits"], list)
        json.dumps(d)  # must not raise: tuples would break a naive encoder


@unittest.skipUnless(git_available(), "git is not installed")
class TestDedupEndToEnd(unittest.TestCase):
    """
    The original bug, reproduced through the real pipeline rather than through
    hand-built findings.
    """

    def test_one_key_one_file_history_scan_reports_one_finding(self):
        from orchestrator import run_scan

        with TempRepo() as repo:
            repo.write("app.py", f'aws_access_key_id = "{AWS_KEY}"')
            repo.commit("add key")
            # Touch the file in later commits: git log replays the add each
            # time a commit rewrites that hunk.
            repo.write("app.py", f'aws_access_key_id = "{AWS_KEY}"  # noqa')
            repo.commit("tweak")

            scored = run_scan(repo.path, history=True)

        aws = [s for s in scored if s.file_path.endswith("app.py")]
        self.assertEqual(len(aws), 1, f"expected 1 finding, got {len(aws)}: {aws}")
        self.assertEqual(aws[0].exposure, "working_tree")
        self.assertTrue(aws[0].in_history)

    def test_secret_deleted_from_working_tree_is_history_only(self):
        from orchestrator import run_scan

        with TempRepo() as repo:
            repo.write("leak.py", f'aws_access_key_id = "{AWS_KEY}"')
            repo.commit("oops")
            repo.remove("leak.py")
            repo.commit("remove the key")

            scored = run_scan(repo.path, history=True)

        leaks = [s for s in scored if s.file_path.endswith("leak.py")]
        self.assertEqual(len(leaks), 1, leaks)
        self.assertEqual(leaks[0].exposure, "history_only")
        self.assertIsNotNone(leaks[0].commit_hash)


if __name__ == "__main__":
    unittest.main(verbosity=2)
