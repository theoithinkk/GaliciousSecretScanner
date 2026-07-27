"""
tests/test_walker.py
--------------------
Covers the file/history walk: what gets yielded, what gets skipped (binaries,
default ignores, .sentryignore, explicit rules), the git-history diff parser,
and the WalkerError paths.

These use a real temporary git repo rather than a mocked subprocess -- the
history walk's whole job is parsing real `git log -p` output, and a stubbed
subprocess would only test the stub.
"""

from __future__ import annotations

import os
import unittest

from _helpers import TempRepo, git_available  # noqa: F401  (sys.path side effect)

import walker
from walker import WalkerError, looksLikeGithubUrl, parseGitLogOutput, walk

SECRET = "AKIA3RJQ7KZ2NDLPWXYZ"


class _AllowAll:
    """Ignore spec that matches nothing, for parser tests."""

    def match_file(self, rel):
        return False


class TestWorkingTreeWalk(unittest.TestCase):
    def test_yields_every_line_with_metadata(self):
        with TempRepo(git=False) as repo:
            repo.write("a.py", "one\ntwo\nthree")
            findings = [f for f in walk(repo.path) if f.file_path.endswith("a.py")]

        self.assertEqual([f.line_content for f in findings], ["one", "two", "three"])
        self.assertEqual([f.line_number for f in findings], [1, 2, 3])
        self.assertTrue(all(f.commit_hash is None for f in findings))

    def test_file_paths_are_repo_relative(self):
        with TempRepo(git=False) as repo:
            repo.write("src/deep/a.py", "x")
            findings = list(walk(repo.path))

        self.assertTrue(findings)
        for f in findings:
            self.assertFalse(os.path.isabs(f.file_path), f.file_path)

    def test_nested_directories_are_walked(self):
        with TempRepo(git=False) as repo:
            repo.write("src/deep/nested/a.py", f'key = "{SECRET}"')
            paths = {f.file_path.replace("\\", "/") for f in walk(repo.path)}

        self.assertIn("src/deep/nested/a.py", paths)

    def test_binary_files_are_skipped(self):
        with TempRepo(git=False) as repo:
            repo.write("text.txt", "readable")
            repo.write_bytes("blob.dat", b"\x00\x01\x02binary\x00stuff")
            paths = {f.file_path for f in walk(repo.path)}

        self.assertIn("text.txt", paths)
        self.assertNotIn("blob.dat", paths)

    def test_empty_repo_yields_nothing(self):
        with TempRepo(git=False) as repo:
            self.assertEqual(list(walk(repo.path)), [])

    def test_unreadable_file_does_not_abort_the_scan(self):
        # A directory entry that looks like a file to os.walk shouldn't kill
        # the whole run; the other file must still come through.
        with TempRepo(git=False) as repo:
            repo.write("good.py", "still scanned")
            repo.write_bytes("weird.bin", b"\x00" * 10)
            paths = {f.file_path for f in walk(repo.path)}

        self.assertIn("good.py", paths)


class TestIgnoreRules(unittest.TestCase):
    def test_default_ignores_skip_vendor_directories(self):
        with TempRepo(git=False) as repo:
            repo.write("app.py", "kept")
            repo.write("node_modules/pkg/index.js", "skipped")
            repo.write("__pycache__/x.pyc", "skipped")
            paths = {f.file_path.replace("\\", "/") for f in walk(repo.path)}

        self.assertIn("app.py", paths)
        self.assertNotIn("node_modules/pkg/index.js", paths)

    def test_full_scan_disables_default_ignores(self):
        with TempRepo(git=False) as repo:
            repo.write("node_modules/pkg/index.js", f'key = "{SECRET}"')

            quick = {f.file_path.replace("\\", "/")
                     for f in walk(repo.path, use_default_ignores=True)}
            full = {f.file_path.replace("\\", "/")
                    for f in walk(repo.path, use_default_ignores=False)}

        self.assertNotIn("node_modules/pkg/index.js", quick)
        self.assertIn("node_modules/pkg/index.js", full)

    def test_sentryignore_is_respected(self):
        with TempRepo(git=False) as repo:
            repo.write(".sentryignore", "secrets_ok.txt\n# a comment\n")
            repo.write("secrets_ok.txt", f'key = "{SECRET}"')
            repo.write("app.py", "kept")
            paths = {f.file_path for f in walk(repo.path)}

        self.assertNotIn("secrets_ok.txt", paths)
        self.assertIn("app.py", paths)

    def test_sentryignore_applies_during_full_scan_too(self):
        with TempRepo(git=False) as repo:
            repo.write(".sentryignore", "skipme.txt\n")
            repo.write("skipme.txt", "x")
            paths = {f.file_path
                     for f in walk(repo.path, use_default_ignores=False)}

        self.assertNotIn("skipme.txt", paths)

    def test_explicit_ignore_rules_are_applied(self):
        with TempRepo(git=False) as repo:
            repo.write("keep.py", "kept")
            repo.write("drop.py", "dropped")
            paths = {f.file_path for f in walk(repo.path, ignore_rules=["drop.py"])}

        self.assertIn("keep.py", paths)
        self.assertNotIn("drop.py", paths)

    def test_directory_pattern_prunes_the_whole_tree(self):
        with TempRepo(git=False) as repo:
            repo.write("build/out/a.js", "x")
            repo.write("src/a.js", "y")
            paths = {f.file_path.replace("\\", "/")
                     for f in walk(repo.path, ignore_rules=["build/"])}

        self.assertNotIn("build/out/a.js", paths)
        self.assertIn("src/a.js", paths)

    @unittest.skipUnless(walker.hasPathspec,
                         "negation patterns need pathspec (see requirements.txt)")
    def test_negation_pattern_re_includes_a_file(self):
        with TempRepo(git=False) as repo:
            repo.write("logs/a.log", "x")
            repo.write("logs/keep.log", "y")
            paths = {f.file_path.replace("\\", "/") for f in walk(
                repo.path, ignore_rules=["*.log", "!logs/keep.log"])}

        self.assertNotIn("logs/a.log", paths)
        self.assertIn("logs/keep.log", paths)


class TestTargetResolution(unittest.TestCase):
    def test_missing_path_raises(self):
        with self.assertRaises(WalkerError):
            list(walk(os.path.join(os.path.dirname(__file__), "no_such_dir_here")))

    def test_file_instead_of_directory_raises(self):
        with TempRepo(git=False) as repo:
            target = repo.write("a.py", "x")
            with self.assertRaises(WalkerError):
                list(walk(target))

    def test_github_url_detection(self):
        for url in ("https://github.com/owner/repo",
                    "http://github.com/owner/repo.git",
                    "git@github.com:owner/repo.git",
                    "HTTPS://GitHub.com/owner/repo"):
            with self.subTest(url=url):
                self.assertTrue(looksLikeGithubUrl(url))

    def test_non_github_inputs_are_treated_as_paths(self):
        for value in ("/home/me/project", "C:\\Users\\me\\project", "./relative",
                      "https://gitlab.com/owner/repo", "not a url"):
            with self.subTest(value=value):
                self.assertFalse(looksLikeGithubUrl(value))


@unittest.skipUnless(git_available(), "git is not installed")
class TestHistoryWalk(unittest.TestCase):
    def test_finds_a_secret_that_was_added_then_deleted(self):
        with TempRepo() as repo:
            repo.write("leak.py", f'key = "{SECRET}"')
            repo.commit("add")
            repo.remove("leak.py")
            repo.commit("remove")

            tree = [f for f in walk(repo.path, history=False)]
            hist = [f for f in walk(repo.path, history=True) if f.commit_hash]

        self.assertFalse([f for f in tree if SECRET in f.line_content],
                         "secret should be gone from the working tree")
        self.assertTrue([f for f in hist if SECRET in f.line_content],
                        "secret should still be findable in history")

    def test_history_findings_carry_a_commit_hash(self):
        with TempRepo() as repo:
            repo.write("a.py", f'key = "{SECRET}"')
            repo.commit("add")
            hist = [f for f in walk(repo.path, history=True) if f.commit_hash]

        self.assertTrue(hist)
        for f in hist:
            self.assertRegex(f.commit_hash, r"^[0-9a-f]{7,12}$")

    def test_history_off_by_default(self):
        with TempRepo() as repo:
            repo.write("a.py", f'key = "{SECRET}"')
            repo.commit("add")
            self.assertEqual([f for f in walk(repo.path) if f.commit_hash], [])

    def test_max_commits_caps_the_walk(self):
        with TempRepo() as repo:
            for i in range(5):
                repo.write(f"f{i}.py", f'key{i} = "value{i}"')
                repo.commit(f"commit {i}")

            capped = {f.commit_hash for f in walk(repo.path, history=True, max_commits=1)
                      if f.commit_hash}
            everything = {f.commit_hash for f in walk(repo.path, history=True)
                          if f.commit_hash}

        self.assertEqual(len(capped), 1)
        self.assertGreater(len(everything), len(capped))

    def test_history_on_a_non_git_folder_is_quiet(self):
        # Asking for history where there's no repo is not an error -- the
        # working-tree results should still come back.
        with TempRepo(git=False) as repo:
            repo.write("a.py", "x")
            findings = list(walk(repo.path, history=True))

        self.assertTrue(findings)
        self.assertTrue(all(f.commit_hash is None for f in findings))

    def test_ignored_paths_are_skipped_in_history_too(self):
        with TempRepo() as repo:
            repo.write("node_modules/pkg/i.js", f'key = "{SECRET}"')
            repo.write("app.py", "x")
            repo.commit("add both")
            hist_files = {f.file_path for f in walk(repo.path, history=True)
                          if f.commit_hash}

        self.assertNotIn("node_modules/pkg/i.js", hist_files)


class TestGitLogParser(unittest.TestCase):
    """
    Parser-level tests with canned `git log -p --unified=0` output, so line
    numbering and hunk handling can be checked precisely.
    """

    LOG = (
        "commit a1b2c3d4e5f67890abcdef1234567890abcdef12\n"
        "Author: T <t@example.invalid>\n"
        "\n"
        "    add config\n"
        "\n"
        "diff --git a/config.py b/config.py\n"
        "--- a/config.py\n"
        "+++ b/config.py\n"
        "@@ -0,0 +10,2 @@\n"
        "+first_added = 1\n"
        "+second_added = 2\n"
    )

    def test_commit_hash_is_shortened(self):
        findings = list(parseGitLogOutput(self.LOG, _AllowAll()))
        self.assertTrue(findings)
        self.assertEqual(findings[0].commit_hash, "a1b2c3d4e5f6")

    def test_added_lines_are_yielded_without_the_plus(self):
        findings = list(parseGitLogOutput(self.LOG, _AllowAll()))
        self.assertEqual([f.line_content for f in findings],
                         ["first_added = 1", "second_added = 2"])

    def test_line_numbers_come_from_the_hunk_header(self):
        findings = list(parseGitLogOutput(self.LOG, _AllowAll()))
        self.assertEqual([f.line_number for f in findings], [10, 11])

    def test_file_path_comes_from_the_diff_header(self):
        findings = list(parseGitLogOutput(self.LOG, _AllowAll()))
        self.assertEqual({f.file_path for f in findings}, {"config.py"})

    def test_removed_lines_are_not_yielded(self):
        log = self.LOG + "@@ -20,1 +0,0 @@\n-deleted_line = 3\n"
        contents = [f.line_content for f in parseGitLogOutput(log, _AllowAll())]
        self.assertNotIn("deleted_line = 3", contents)

    def test_diff_metadata_lines_are_not_yielded(self):
        contents = [f.line_content for f in parseGitLogOutput(self.LOG, _AllowAll())]
        for meta in ("a/config.py", "b/config.py"):
            self.assertNotIn(meta, contents)

    def test_multiple_files_in_one_commit(self):
        log = self.LOG + (
            "diff --git a/other.py b/other.py\n"
            "--- a/other.py\n"
            "+++ b/other.py\n"
            "@@ -0,0 +1,1 @@\n"
            "+other = 1\n"
        )
        by_file = {}
        for f in parseGitLogOutput(log, _AllowAll()):
            by_file.setdefault(f.file_path, []).append(f.line_content)
        self.assertEqual(set(by_file), {"config.py", "other.py"})

    def test_empty_log_yields_nothing(self):
        self.assertEqual(list(parseGitLogOutput("", _AllowAll())), [])

    def test_lines_before_any_diff_header_are_skipped(self):
        log = "commit " + "a" * 40 + "\n\n    a commit message\n\n"
        self.assertEqual(list(parseGitLogOutput(log, _AllowAll())), [])


class TestFnmatchFallback(unittest.TestCase):
    """
    The reduced matcher used when pathspec isn't installed. It must still
    handle the basics, because it's silently in charge whenever the dependency
    is missing.
    """

    def setUp(self):
        self.spec = walker.FnmatchFallbackSpec(
            ["*.pyc", "node_modules/", "build/", "secret.txt"]
        )

    def test_extension_glob(self):
        self.assertTrue(self.spec.match_file("a.pyc"))
        self.assertTrue(self.spec.match_file("src/deep/a.pyc"))
        self.assertFalse(self.spec.match_file("a.py"))

    def test_directory_pattern(self):
        self.assertTrue(self.spec.match_file("node_modules/pkg/index.js"))
        self.assertTrue(self.spec.match_file("src/node_modules/pkg/index.js"))

    def test_exact_name(self):
        self.assertTrue(self.spec.match_file("secret.txt"))
        self.assertFalse(self.spec.match_file("not_secret.txt"))

    def test_unmatched_paths_pass_through(self):
        self.assertFalse(self.spec.match_file("src/app.py"))

    def test_windows_separators_are_normalised(self):
        self.assertTrue(self.spec.match_file("node_modules\\pkg\\index.js"))

    def test_empty_pattern_list_matches_nothing(self):
        self.assertFalse(walker.FnmatchFallbackSpec([]).match_file("anything.py"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
