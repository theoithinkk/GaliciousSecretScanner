"""
tests/test_fixer.py
-------------------
Covers the one-click fix. This module writes to files on disk, so the tests
lean hardest on the things that would be damaging to get wrong:

  - path containment: a crafted file_path must not escape the scanned directory
  - ordering: .gitignore must cover .env BEFORE the secret is written into it
  - refusal: a file that changed since the scan must abort, not be corrupted
  - honesty: every result must carry the rotation warning, and history findings
    must carry the second warning about the blob still being reachable
"""

from __future__ import annotations

import os
import unittest

from _helpers import TempRepo  # noqa: F401  (sys.path side effect)

from web import fixer
from web.fixer import FixError, apply_fix, derive_env_name, describe, locate_secret

AWS_KEY = "AKIA3RJQ7KZ2NDLPWXYZ"
STRIPE = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"


def read(repo, rel):
    with open(repo.abs(rel), encoding="utf-8") as f:
        return f.read()


class TestPathContainment(unittest.TestCase):
    """The guard that matters most, since file_path arrives over HTTP."""

    def setUp(self):
        self.repo = TempRepo(git=False)
        self.addCleanup(self.repo.cleanup)

    def test_normal_path_resolves(self):
        self.repo.write("src/a.py", "x = 1")
        got = fixer.resolve_inside(self.repo.path, "src/a.py")
        self.assertTrue(got.startswith(os.path.realpath(self.repo.path)))

    def test_parent_traversal_is_refused(self):
        for evil in ("../outside.txt", "../../etc/passwd",
                     "src/../../escape.py", r"..\..\windows.ini"):
            with self.subTest(path=evil):
                with self.assertRaises(FixError):
                    fixer.resolve_inside(self.repo.path, evil)

    def test_absolute_path_outside_is_refused(self):
        with self.assertRaises(FixError):
            fixer.resolve_inside(self.repo.path, os.path.abspath(os.sep + "etc"))

    def test_apply_refuses_traversal(self):
        result = apply_fix(self.repo.path, "../evil.py", 1, "AWS_ACCESS_KEY")
        self.assertFalse(result.ok)
        self.assertIn("outside", result.error)


class TestLocateSecret(unittest.TestCase):
    def test_finds_the_matching_detector_hit(self):
        line = f'key = "{AWS_KEY}"'
        secret, start, end = locate_secret(line, "AWS_ACCESS_KEY")
        self.assertEqual(secret, AWS_KEY)
        self.assertEqual(line[start:end], AWS_KEY)

    def test_missing_detector_type_raises(self):
        with self.assertRaises(FixError) as ctx:
            locate_secret('key = "nothing here"', "AWS_ACCESS_KEY")
        self.assertIn("changed since the scan", str(ctx.exception))


class TestDeriveEnvName(unittest.TestCase):
    def test_named_after_the_variable(self):
        line = f'api_key = "{AWS_KEY}"'
        self.assertEqual(derive_env_name(line, line.index(AWS_KEY), "X"), "API_KEY")

    def test_dotted_attribute_flattened(self):
        line = f'stripe.api_key = "{STRIPE}"'
        self.assertEqual(derive_env_name(line, line.index(STRIPE), "X"),
                         "STRIPE_API_KEY")

    def test_falls_back_to_detector_type(self):
        line = f'    "{AWS_KEY}",'
        self.assertEqual(derive_env_name(line, line.index(AWS_KEY), "AWS_ACCESS_KEY"),
                         "AWS_ACCESS_KEY")

    def test_never_starts_with_a_digit(self):
        line = f'2fa_token = "{AWS_KEY}"'
        name = derive_env_name(line, line.index(AWS_KEY), "X")
        self.assertFalse(name[0].isdigit(), name)


class TestDescribe(unittest.TestCase):
    def test_history_only_is_not_fixable(self):
        ok, why = describe("src/a.py", "source", "history_only")
        self.assertFalse(ok)
        self.assertIn("history", why)

    def test_supported_source_is_fixable(self):
        self.assertTrue(describe("src/a.py", "source", "working_tree")[0])

    def test_env_file_is_fixable(self):
        self.assertTrue(describe(".env", "env", "working_tree")[0])

    def test_pem_is_not_rewritten(self):
        ok, why = describe("keys/id.pem", "other", "working_tree")
        self.assertFalse(ok)
        self.assertIn("regenerated", why)

    def test_unknown_extension_is_refused(self):
        self.assertFalse(describe("data.xyz", "other", "working_tree")[0])


class TestApplyToPython(unittest.TestCase):
    def setUp(self):
        self.repo = TempRepo(git=False)
        self.addCleanup(self.repo.cleanup)

    def test_rewrites_the_literal_to_an_env_lookup(self):
        self.repo.write("src/payments.py",
                        "import stripe\n"
                        f'stripe.api_key = "{STRIPE}"\n'
                        "print(stripe.api_key)\n")
        result = apply_fix(self.repo.path, "src/payments.py", 2, "STRIPE_KEY")
        self.assertTrue(result.ok, result.error)

        src = read(self.repo, "src/payments.py")
        self.assertNotIn(STRIPE, src)
        self.assertIn('stripe.api_key = os.environ["STRIPE_API_KEY"]', src)
        self.assertIn("print(stripe.api_key)", src)   # other lines untouched

    def test_secret_lands_in_dotenv(self):
        self.repo.write("a.py", f'token = "{STRIPE}"\n')
        apply_fix(self.repo.path, "a.py", 1, "STRIPE_KEY")
        self.assertIn(f"TOKEN={STRIPE}", read(self.repo, ".env"))

    def test_gitignore_covers_env_before_the_secret_is_written(self):
        # Ordering matters: writing a plaintext secret into a tracked .env
        # would make things worse, not better.
        self.repo.write("a.py", f'token = "{STRIPE}"\n')
        result = apply_fix(self.repo.path, "a.py", 1, "STRIPE_KEY")
        self.assertIn(".env", read(self.repo, ".gitignore"))
        gitignore_step = next(i for i, s in enumerate(result.steps) if ".gitignore" in s)
        env_step = next(i for i, s in enumerate(result.steps) if ".env" in s and "gitignore" not in s)
        self.assertLess(gitignore_step, env_step, result.steps)

    def test_existing_gitignore_entry_is_not_duplicated(self):
        self.repo.write(".gitignore", "__pycache__/\n.env\n")
        self.repo.write("a.py", f'token = "{STRIPE}"\n')
        apply_fix(self.repo.path, "a.py", 1, "STRIPE_KEY")
        self.assertEqual(read(self.repo, ".gitignore").count(".env"), 1)

    def test_import_os_added_when_missing(self):
        self.repo.write("a.py", f'token = "{STRIPE}"\n')
        apply_fix(self.repo.path, "a.py", 1, "STRIPE_KEY")
        self.assertIn("import os", read(self.repo, "a.py"))

    def test_import_os_not_duplicated(self):
        self.repo.write("a.py", f'import os\ntoken = "{STRIPE}"\n')
        apply_fix(self.repo.path, "a.py", 2, "STRIPE_KEY")
        self.assertEqual(read(self.repo, "a.py").count("import os"), 1)

    def test_import_goes_after_a_module_docstring(self):
        # Inserting above the docstring would demote it to a plain expression.
        self.repo.write("a.py",
                        '"""Module docstring."""\n'
                        f'token = "{STRIPE}"\n')
        apply_fix(self.repo.path, "a.py", 2, "STRIPE_KEY")
        lines = read(self.repo, "a.py").splitlines()
        self.assertTrue(lines[0].startswith('"""'))
        self.assertEqual(lines[1], "import os")

    def test_import_goes_after_a_multiline_docstring(self):
        self.repo.write("a.py",
                        '"""\nMulti\nline\n"""\n'
                        f'token = "{STRIPE}"\n')
        apply_fix(self.repo.path, "a.py", 5, "STRIPE_KEY")
        lines = read(self.repo, "a.py").splitlines()
        self.assertEqual(lines[4], "import os")

    def test_import_goes_after_a_shebang(self):
        self.repo.write("a.py", "#!/usr/bin/env python3\n" f'token = "{STRIPE}"\n')
        apply_fix(self.repo.path, "a.py", 2, "STRIPE_KEY")
        lines = read(self.repo, "a.py").splitlines()
        self.assertTrue(lines[0].startswith("#!"))
        self.assertEqual(lines[1], "import os")

    def test_file_still_compiles_afterwards(self):
        self.repo.write("a.py",
                        '"""Doc."""\n'
                        f'token = "{STRIPE}"\n'
                        "def go():\n    return token\n")
        apply_fix(self.repo.path, "a.py", 2, "STRIPE_KEY")
        compile(read(self.repo, "a.py"), "a.py", "exec")   # raises on bad syntax


class TestApplyToOtherLanguages(unittest.TestCase):
    def setUp(self):
        self.repo = TempRepo(git=False)
        self.addCleanup(self.repo.cleanup)

    def test_javascript(self):
        self.repo.write("a.js", f'const k = "{STRIPE}";\n')
        self.assertTrue(apply_fix(self.repo.path, "a.js", 1, "STRIPE_KEY").ok)
        self.assertIn("process.env.K", read(self.repo, "a.js"))

    def test_yaml(self):
        self.repo.write("c.yml", f'stripe_key: "{STRIPE}"\n')
        self.assertTrue(apply_fix(self.repo.path, "c.yml", 1, "STRIPE_KEY").ok)
        self.assertIn("${STRIPE_KEY}", read(self.repo, "c.yml"))

    def test_unsupported_extension_is_refused(self):
        self.repo.write("a.xyz", f'k = "{STRIPE}"\n')
        result = apply_fix(self.repo.path, "a.xyz", 1, "STRIPE_KEY")
        self.assertFalse(result.ok)
        self.assertIn("no safe rewrite", result.error)


class TestEnvFileFix(unittest.TestCase):
    def test_env_file_gets_gitignored_not_rewritten(self):
        with TempRepo(git=False) as repo:
            repo.write(".env", f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
            result = apply_fix(repo.path, ".env", 1, "AWS_ACCESS_KEY")
            self.assertTrue(result.ok, result.error)
            self.assertEqual(result.kind, "gitignore")
            # The value stays put -- .env is where it belongs.
            self.assertIn(AWS_KEY, read(repo, ".env"))
            self.assertIn(".env", read(repo, ".gitignore"))
            self.assertTrue(any("git rm --cached" in w for w in result.warnings))


class TestRefusals(unittest.TestCase):
    def setUp(self):
        self.repo = TempRepo(git=False)
        self.addCleanup(self.repo.cleanup)

    def test_missing_file(self):
        result = apply_fix(self.repo.path, "gone.py", 1, "STRIPE_KEY")
        self.assertFalse(result.ok)
        self.assertIn("no longer exists", result.error)

    def test_line_out_of_range(self):
        self.repo.write("a.py", "x = 1\n")
        result = apply_fix(self.repo.path, "a.py", 99, "STRIPE_KEY")
        self.assertFalse(result.ok)
        self.assertIn("no line 99", result.error)

    def test_file_changed_since_scan_leaves_it_untouched(self):
        original = "x = 1\ny = 2\n"
        self.repo.write("a.py", original)
        result = apply_fix(self.repo.path, "a.py", 1, "STRIPE_KEY")
        self.assertFalse(result.ok)
        self.assertEqual(read(self.repo, "a.py"), original)

    def test_missing_root(self):
        result = apply_fix(os.path.join(self.repo.path, "nope"), "a.py", 1, "STRIPE_KEY")
        self.assertFalse(result.ok)


class TestHonesty(unittest.TestCase):
    """A fix must never look like it finished the job."""

    def setUp(self):
        self.repo = TempRepo(git=False)
        self.addCleanup(self.repo.cleanup)
        self.repo.write("a.py", f'token = "{STRIPE}"\n')

    def test_rotation_warning_is_always_present(self):
        result = apply_fix(self.repo.path, "a.py", 1, "STRIPE_KEY")
        self.assertTrue(any("ROTATE" in w for w in result.warnings), result.warnings)

    def test_history_finding_warns_the_blob_is_still_reachable(self):
        result = apply_fix(self.repo.path, "a.py", 1, "STRIPE_KEY", in_history=True)
        self.assertTrue(any("git-filter-repo" in w for w in result.warnings),
                        result.warnings)

    def test_no_history_warning_when_never_committed(self):
        result = apply_fix(self.repo.path, "a.py", 1, "STRIPE_KEY", in_history=False)
        self.assertFalse(any("git-filter-repo" in w for w in result.warnings))

    def test_result_serialises_for_the_api(self):
        d = apply_fix(self.repo.path, "a.py", 1, "STRIPE_KEY").to_dict()
        for key in ("ok", "kind", "steps", "warnings", "error", "env_var"):
            self.assertIn(key, d)


class TestFixClearsTheFinding(unittest.TestCase):
    def test_rescanning_after_a_fix_no_longer_reports_it(self):
        """The end-to-end promise: fix it, rescan, it's gone from the tree."""
        from orchestrator import run_scan

        with TempRepo(git=False) as repo:
            repo.write("src/payments.py", "import stripe\n"
                                          f'stripe.api_key = "{STRIPE}"\n')
            before = run_scan(repo.path)
            hit = next(s for s in before if s.detector_type == "STRIPE_KEY")

            result = apply_fix(repo.path, hit.file_path, hit.line_number, "STRIPE_KEY")
            self.assertTrue(result.ok, result.error)

            after = run_scan(repo.path)
            paths = {s.file_path.replace("\\", "/") for s in after}
            self.assertNotIn("src/payments.py", paths)


if __name__ == "__main__":
    unittest.main(verbosity=2)
