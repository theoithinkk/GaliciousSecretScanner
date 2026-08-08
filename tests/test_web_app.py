"""
test_web_app.py
---------------
The Flask routes. The web UI is the project's primary interface, so the
endpoints behind it need the same coverage as the engine underneath.

What matters most here isn't that the happy path renders -- it's the refusals.
/api/browse walks real directories, /api/fix rewrites real files, and
/api/baseline writes into the user's repo, so the tests that earn their keep
are the ones asserting those say no.

Every secret planted below is fabricated: format-valid so the detectors fire,
but issued by nobody. No test opens a socket.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

try:
    import flask  # noqa: F401
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

if HAS_FLASK:
    from web import app as app_module


# Fabricated, non-functional, and reused from scripts/make_test_repo.py rather
# than invented here. A Stripe-shaped fixture is blocked by GitHub push
# protection (Stripe keys are checkable against the provider, so GitHub refuses
# the push whether or not the key is real), which would make this file
# unpushable. An AKIA-shaped one trips our detectors just as well.
FAKE_AWS_KEY = "AKIA3RJQ7KZ2NDLPWXYZ"


@unittest.skipUnless(HAS_FLASK, "web UI tests need Flask (see requirements.txt)")
class WebTestCase(unittest.TestCase):
    """A scratch repo with one planted secret, and a client pointed at it."""

    def setUp(self):
        self.repo = tempfile.mkdtemp(prefix="galicious_web_")
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)
        with open(os.path.join(self.repo, "settings.py"), "w", encoding="utf-8") as f:
            f.write('aws_access_key_id = "%s"\n' % FAKE_AWS_KEY)

        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

        # _LAST_SCAN is module state; reset it so test order can't matter.
        self._saved_scan = dict(app_module._LAST_SCAN)
        app_module._LAST_SCAN.update(scored=[], target="", suppressed=0)
        self.addCleanup(app_module._LAST_SCAN.update, self._saved_scan)

    def scan(self, **form):
        form.setdefault("target", self.repo)
        return self.client.post("/", data=form)


class TestBrowseIsConfined(WebTestCase):
    """
    /api/browse lists real directories, so without a ceiling it is an
    unauthenticated filesystem browser for the whole machine.
    """

    def setUp(self):
        super().setUp()
        self.root = tempfile.mkdtemp(prefix="galicious_root_")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        os.mkdir(os.path.join(self.root, "inside"))
        self._saved_root = app_module._BROWSE_ROOT
        app_module._BROWSE_ROOT = os.path.realpath(self.root)
        self.addCleanup(setattr, app_module, "_BROWSE_ROOT", self._saved_root)

    def test_no_path_lists_the_root(self):
        data = self.client.get("/api/browse").get_json()
        self.assertIsNone(data["error"])
        self.assertEqual([d["name"] for d in data["dirs"]], ["inside"])

    def test_root_offers_no_parent(self):
        """Otherwise "Up" walks straight out of the ceiling."""
        self.assertIsNone(self.client.get("/api/browse").get_json()["parent"])

    def test_absolute_path_outside_the_root_is_refused(self):
        res = self.client.get("/api/browse",
                              query_string={"path": os.path.dirname(self.root)})
        self.assertEqual(res.status_code, 400)
        self.assertIn("Outside the browsable root", res.get_json()["error"])

    def test_traversal_is_refused(self):
        res = self.client.get("/api/browse", query_string={"path": "../.."})
        self.assertEqual(res.status_code, 400)
        self.assertIn("Outside the browsable root", res.get_json()["error"])

    def test_backslash_traversal_is_refused(self):
        """A backslash is a path separator here even on Linux."""
        res = self.client.get("/api/browse", query_string={"path": r"..\..\etc"})
        self.assertEqual(res.status_code, 400)

    def test_inside_the_root_is_allowed(self):
        res = self.client.get("/api/browse",
                              query_string={"path": os.path.join(self.root, "inside")})
        self.assertEqual(res.status_code, 200)
        self.assertIsNotNone(res.get_json()["parent"])


class TestWriteEndpointsRefuseRemoteTargets(WebTestCase):
    """
    A GitHub URL is cloned to a temp dir the walker deletes when the scan ends,
    so there is nothing on disk to fix or baseline. Both endpoints re-check
    server-side rather than trusting the UI to have hidden the button.
    """

    URL = "https://github.com/someone-else/their-repo"

    def test_fix_refuses_a_url(self):
        res = self.client.post("/api/fix", json={
            "target": self.URL, "file_path": "settings.py",
            "line_number": 1, "detector_type": "AWS_ACCESS_KEY"})
        self.assertEqual(res.status_code, 400)
        self.assertFalse(res.get_json()["ok"])

    def test_fix_rejects_a_bad_line_number(self):
        res = self.client.post("/api/fix", json={
            "target": self.repo, "file_path": "settings.py",
            "line_number": 0, "detector_type": "AWS_ACCESS_KEY"})
        self.assertEqual(res.status_code, 400)
        self.assertIn("positive integer", res.get_json()["error"])

    def test_baseline_refuses_a_target_this_session_never_scanned(self):
        """Otherwise any request could name a directory and get a file written."""
        self.scan()
        res = self.client.post("/api/baseline", json={"target": tempfile.gettempdir()})
        self.assertEqual(res.status_code, 400)
        self.assertFalse(res.get_json()["ok"])


class TestScanForm(WebTestCase):

    def test_get_renders_the_form(self):
        body = self.client.get("/").get_data(as_text=True)
        self.assertIn('name="target"', body)
        for field in ("min_severity", "max_commits", "use_baseline"):
            self.assertIn('name="%s"' % field, body)

    def test_shared_chrome_is_not_html_escaped(self):
        """
        base_css/base_js render through |safe. Without it, autoescaping mangles
        the quotes in font-family and every `<` in the script.
        """
        body = self.client.get("/").get_data(as_text=True)
        self.assertIn("--green:#00ff9c", body)
        self.assertIn("i < drops.length", body)
        self.assertNotIn("&#39;", body.split("</style>")[0])

    def test_empty_target_is_rejected(self):
        body = self.client.post("/", data={"target": "  "}).get_data(as_text=True)
        self.assertIn("Please enter a repository path", body)

    def test_bad_min_severity_is_rejected(self):
        self.assertIn("Unknown severity",
                      self.scan(min_severity="nonsense").get_data(as_text=True))

    def test_bad_max_commits_is_rejected(self):
        self.assertIn("1 or more",
                      self.scan(history="on", max_commits="-3").get_data(as_text=True))
        self.assertIn("whole number",
                      self.scan(history="on", max_commits="lots").get_data(as_text=True))

    def test_missing_target_directory_is_reported_not_a_500(self):
        res = self.client.post("/", data={"target": os.path.join(self.repo, "nope")})
        self.assertEqual(res.status_code, 200)
        self.assertIn("does not exist", res.get_data(as_text=True))


class TestReportPage(WebTestCase):

    def test_report_never_contains_the_plaintext_secret(self):
        self.assertNotIn(FAKE_AWS_KEY, self.scan().get_data(as_text=True))

    def test_findings_carry_their_remediation_steps(self):
        """
        The steps remediation.annotate() computed have to reach the panel, or
        the HTML report is the one format that disagrees with the others.
        """
        page = self.scan().get_data(as_text=True)
        self.assertIn("data-remediation", page)
        self.assertIn("Deactivate this key in the IAM console", page)

    def test_served_page_offers_the_server_backed_controls(self):
        page = self.scan().get_data(as_text=True)
        for control in ('id="baselineBtn"', 'href="/report.sarif"', 'class="homebtn"'):
            self.assertIn(control, page)

    def test_min_severity_reaches_the_scan(self):
        """
        Asserted as the contract rather than a fixture count: nothing below the
        floor comes back, whatever the planted secret happens to score.
        """
        from models import Severity
        for name in ("low", "medium", "high", "critical"):
            with self.subTest(min_severity=name):
                self.scan(min_severity=name)
                floor = Severity.from_name(name)
                self.assertTrue(
                    all(f.severity >= floor for f in app_module._LAST_SCAN["scored"]),
                    "a finding below the %s floor came back" % name)

        # And a floor the fixture cannot reach really does empty the report:
        # the planted key is source-code (+5), so putting it under tests/
        # (-20) drops it two bands.
        os.makedirs(os.path.join(self.repo, "tests"), exist_ok=True)
        os.replace(os.path.join(self.repo, "settings.py"),
                   os.path.join(self.repo, "tests", "settings.py"))
        self.scan(min_severity="critical")
        self.assertEqual(app_module._LAST_SCAN["scored"], [])


class TestReportDownloads(WebTestCase):

    def test_download_before_any_scan_is_a_404(self):
        self.assertEqual(self.client.get("/report.json").status_code, 404)

    def test_unknown_format_is_a_404(self):
        self.scan()
        self.assertEqual(self.client.get("/report.pdf").status_code, 404)

    def test_each_format_downloads_and_leaks_nothing(self):
        self.scan()
        for fmt, needle in (("json", '"detector_type"'),
                            ("sarif", '"$schema"'),
                            ("html", "<!DOCTYPE html>")):
            with self.subTest(fmt=fmt):
                res = self.client.get("/report.%s" % fmt)
                self.assertEqual(res.status_code, 200)
                body = res.get_data(as_text=True)
                self.assertIn(needle, body)
                self.assertIn("attachment", res.headers["Content-Disposition"])
                self.assertNotIn(FAKE_AWS_KEY, body)

    def test_json_download_carries_remediation(self):
        self.scan()
        self.assertIn('"remediation_steps"',
                      self.client.get("/report.json").get_data(as_text=True))

    def test_downloaded_html_has_no_server_only_controls(self):
        """A file on disk has no server behind it, so no dead buttons."""
        self.scan()
        body = self.client.get("/report.html").get_data(as_text=True)
        for dead in ('id="baselineBtn"', 'href="/report.', 'class="homebtn"'):
            self.assertNotIn(dead, body)


class TestBaselineRoundTrip(WebTestCase):

    def test_accepting_findings_suppresses_them_on_the_next_scan(self):
        self.scan()
        written = self.client.post("/api/baseline",
                                   json={"target": self.repo}).get_json()
        self.assertTrue(written["ok"])
        self.assertGreaterEqual(written["count"], 1)
        self.assertTrue(os.path.isfile(os.path.join(self.repo, ".sentrybaseline")))

        page = self.scan(use_baseline="on").get_data(as_text=True)
        self.assertIn("suppressed by .sentrybaseline", page)
        self.assertEqual(app_module._LAST_SCAN["scored"], [])

    def test_baseline_is_ignored_unless_asked_for(self):
        self.scan()
        self.client.post("/api/baseline", json={"target": self.repo})
        self.scan()      # no use_baseline
        self.assertEqual(len(app_module._LAST_SCAN["scored"]), 1)


if __name__ == "__main__":
    unittest.main()
