"""
tests/test_cli.py
-----------------
Covers cli.py's argparse wrapper and its exit codes -- the contract anything
using SecretSentry as a CI or pre-commit gate depends on.

main() is called in-process with an argv list rather than by spawning a
subprocess, so a traceback in the CLI surfaces here as a real failure instead
of an opaque non-zero exit.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _helpers import TempRepo  # noqa: F401  (sys.path side effect)

import cli

AWS_KEY = "AKIA3RJQ7KZ2NDLPWXYZ"


def run_cli(*argv):
    """Run cli.main(argv), returning (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestArgumentParsing(unittest.TestCase):
    def assertRejected(self, argv):
        """argparse exits AND prints usage to stderr -- swallow the noise."""
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.build_parser().parse_args(argv)

    def test_target_defaults_to_the_current_directory(self):
        # --staged runs from a pre-commit hook with no arguments, so a missing
        # target means "here" rather than an error. Worth knowing that a bare
        # `python cli.py` scans whatever directory you are standing in.
        args = cli.build_parser().parse_args([])
        self.assertEqual(args.target, ".")

    def test_defaults(self):
        args = cli.build_parser().parse_args(["some/path"])
        self.assertEqual(args.format, "terminal")
        self.assertEqual(args.fail_on, "none")
        self.assertEqual(args.min_severity, "low")
        self.assertFalse(args.history)
        self.assertIsNone(args.max_commits)

    def test_invalid_format_rejected(self):
        self.assertRejected(["p", "--format", "pdf"])

    def test_invalid_fail_on_rejected(self):
        self.assertRejected(["p", "--fail-on", "catastrophic"])

    def test_invalid_min_severity_rejected(self):
        self.assertRejected(["p", "--min-severity", "urgent"])

    def test_flags_are_parsed(self):
        args = cli.build_parser().parse_args([
            "p", "--history", "--format", "json", "--max-commits", "5",
            "--fail-on", "high", "--min-severity", "medium",
        ])
        self.assertTrue(args.history)
        self.assertEqual(args.format, "json")
        self.assertEqual(args.max_commits, 5)
        self.assertEqual(args.fail_on, "high")
        self.assertEqual(args.min_severity, "medium")


class TestExitCodes(unittest.TestCase):
    def setUp(self):
        self.repo = TempRepo(git=False)
        self.addCleanup(self.repo.cleanup)
        self.repo.write(".env", f"AWS_ACCESS_KEY_ID={AWS_KEY}")

    def test_report_only_mode_succeeds_despite_findings(self):
        code, out, _ = run_cli(self.repo.path)
        self.assertEqual(code, 0)
        self.assertIn("finding(s)", out)

    def test_fail_on_critical_trips_the_gate(self):
        code, _, _ = run_cli(self.repo.path, "--fail-on", "critical")
        self.assertEqual(code, 1)

    def test_clean_repo_passes_the_gate(self):
        with TempRepo(git=False) as clean:
            clean.write("main.py", "print('hi')")
            code, out, _ = run_cli(clean.path, "--fail-on", "low")
        self.assertEqual(code, 0)
        self.assertIn("No secrets found", out)

    def test_missing_path_is_a_usage_error_not_a_crash(self):
        missing = os.path.join(self.repo.path, "nope", "nowhere")
        code, _, err = run_cli(missing)
        self.assertEqual(code, 2)
        self.assertIn("error:", err)
        self.assertNotIn("Traceback", err)

    def test_unreadable_ignore_file_is_a_usage_error(self):
        code, _, err = run_cli(self.repo.path, "--ignore-file",
                               os.path.join(self.repo.path, "no_such_file"))
        self.assertEqual(code, 2)
        self.assertIn("--ignore-file", err)

    def test_min_severity_can_empty_the_report(self):
        self.repo.write("README.md", f"example key {AWS_KEY}")
        code, out, _ = run_cli(self.repo.path, "--min-severity", "critical",
                               "--fail-on", "none")
        self.assertEqual(code, 0)
        self.assertNotIn("Low:", out.split("\n")[0])


class TestOutputFormats(unittest.TestCase):
    def setUp(self):
        self.repo = TempRepo(git=False)
        self.addCleanup(self.repo.cleanup)
        self.repo.write(".env", f"AWS_ACCESS_KEY_ID={AWS_KEY}")

    def test_json_to_stdout_is_parseable(self):
        _, out, _ = run_cli(self.repo.path, "--format", "json")
        parsed = json.loads(out)
        self.assertTrue(parsed)
        self.assertNotIn(AWS_KEY, out)

    def test_output_file_is_written_and_summarised(self):
        path = os.path.join(tempfile.mkdtemp(prefix="sentrycli_"), "report.json")
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))

        code, out, _ = run_cli(self.repo.path, "--format", "json", "-o", path)
        self.assertEqual(code, 0)
        self.assertIn("wrote json report", out)
        with open(path, encoding="utf-8") as f:
            self.assertTrue(json.load(f))

    def test_ignore_file_rules_are_applied(self):
        rules = os.path.join(self.repo.path, "myignore")
        with open(rules, "w", encoding="utf-8") as f:
            f.write("# skip the env file\n.env\n")

        _, out, _ = run_cli(self.repo.path, "--ignore-file", rules)
        self.assertIn("No secrets found", out)

    def test_no_format_leaks_the_secret(self):
        for fmt in ("terminal", "json", "html"):
            with self.subTest(fmt=fmt):
                _, out, _ = run_cli(self.repo.path, "--format", fmt)
                self.assertNotIn(AWS_KEY, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
