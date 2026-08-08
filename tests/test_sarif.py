"""
tests/test_sarif.py
-------------------
Covers render_sarif and the generate_report(fmt="sarif") branch.

These assert the parts of SARIF 2.1.0 that GitHub Code Scanning actually
rejects an upload over, since that is the only consumer this format exists
for: every ruleId resolving to a declared rule, forward-slashed relative
URIs, and 1-based line numbers. A JSON schema validator would cover the rest,
but that means a new dependency plus a vendored 300KB schema for one output
format -- the real proof is an upload-sarif step in CI.
"""

from __future__ import annotations

import json
import unittest

from _helpers import REPO_ROOT  # noqa: F401  (sys.path side effect)

from models import RawFinding
from reporters import render_sarif
from scorer_reporter import filter_and_score, generate_report

LIVE_AWS = "AKIA3RJQ7KZ2NDLPWXYZ"
STRIPE = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
ENTROPY_BLOB = "Zx9Qk2LpN8vRt5Wm3Yb7Jc1Fd6Hs4Ae0"


def raw(secret=LIVE_AWS, detector_type="AWS_ACCESS_KEY", path=".env", line=1,
        commit=None, entropy=None):
    content = f'key = "{secret}"'
    start = content.index(secret)
    return RawFinding(
        detector_type=detector_type, matched_string=secret, file_path=path,
        line_number=line, commit_hash=commit, line_content=content,
        entropy_score=entropy, start_col=start, end_col=start + len(secret),
    )


def sarif_for(findings, context=None):
    return json.loads(render_sarif(filter_and_score(findings, context)))


def location_of(log, index=0):
    return log["runs"][0]["results"][index]["locations"][0]["physicalLocation"]


class TestEnvelope(unittest.TestCase):
    def setUp(self):
        self.log = sarif_for([raw()])

    def test_version_and_schema(self):
        self.assertEqual(self.log["version"], "2.1.0")
        self.assertIn("sarif-schema-2.1.0.json", self.log["$schema"])

    def test_exactly_one_run_with_a_named_driver(self):
        self.assertEqual(len(self.log["runs"]), 1)
        driver = self.log["runs"][0]["tool"]["driver"]
        self.assertTrue(driver["name"])
        self.assertTrue(driver["version"])
        self.assertTrue(driver["informationUri"].startswith("https://"))

    def test_no_findings_still_produces_a_valid_log(self):
        log = sarif_for([])
        self.assertEqual(log["runs"][0]["results"], [])
        # The rule catalogue doesn't depend on what turned up this run.
        self.assertTrue(log["runs"][0]["tool"]["driver"]["rules"])


class TestRules(unittest.TestCase):
    def setUp(self):
        self.log = sarif_for([
            raw(),
            raw(secret=STRIPE, detector_type="STRIPE_KEY", path="src/pay.py"),
            raw(secret=ENTROPY_BLOB, detector_type="HIGH_ENTROPY",
                path="src/session.py", entropy=4.7),
        ])
        self.driver = self.log["runs"][0]["tool"]["driver"]

    def test_every_result_rule_id_resolves_to_a_declared_rule(self):
        declared = {r["id"] for r in self.driver["rules"]}
        used = {r["ruleId"] for r in self.log["runs"][0]["results"]}
        self.assertTrue(used)
        self.assertEqual(used - declared, set())

    def test_rule_ids_are_unique(self):
        ids = [r["id"] for r in self.driver["rules"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_descriptions_come_from_the_signature_library(self):
        by_id = {r["id"]: r for r in self.driver["rules"]}
        self.assertEqual(by_id["AWS_ACCESS_KEY"]["shortDescription"]["text"],
                         "AWS Access Key ID")

    def test_entropy_detector_gets_a_rule_despite_not_being_in_patterns_json(self):
        by_id = {r["id"]: r for r in self.driver["rules"]}
        self.assertIn("HIGH_ENTROPY", by_id)
        self.assertTrue(by_id["HIGH_ENTROPY"]["shortDescription"]["text"])

    def test_security_severity_is_a_number_github_can_bucket(self):
        for rule in self.driver["rules"]:
            with self.subTest(rule=rule["id"]):
                value = float(rule["properties"]["security-severity"])
                self.assertGreaterEqual(value, 0.0)
                self.assertLessEqual(value, 10.0)


class TestResults(unittest.TestCase):
    def test_high_and_critical_are_errors_low_is_a_note(self):
        aws = sarif_for([raw()])
        self.assertEqual(aws["runs"][0]["results"][0]["level"], "error")

        in_docs = sarif_for([raw(secret=ENTROPY_BLOB, detector_type="HIGH_ENTROPY",
                                 path="docs/README.md")])
        self.assertEqual(in_docs["runs"][0]["results"][0]["level"], "note")

    def test_windows_paths_are_normalised_to_forward_slashes(self):
        log = sarif_for([raw(path="src\\config\\settings.py")])
        uri = location_of(log)["artifactLocation"]["uri"]
        self.assertEqual(uri, "src/config/settings.py")
        self.assertNotIn("\\", uri)

    def test_uris_are_relative(self):
        log = sarif_for([raw(path="/src/app.py")])
        self.assertFalse(location_of(log)["artifactLocation"]["uri"].startswith("/"))

    def test_start_line_is_never_below_one(self):
        log = sarif_for([raw(line=0)])
        self.assertEqual(location_of(log)["region"]["startLine"], 1)

    def test_message_carries_the_rationale(self):
        scored = filter_and_score([raw()])
        log = json.loads(render_sarif(scored))
        self.assertEqual(log["runs"][0]["results"][0]["message"]["text"],
                         scored[0].rationale)

    def test_fingerprint_is_stable_across_runs_and_unique_per_finding(self):
        findings = [raw(),
                    raw(secret=STRIPE, detector_type="STRIPE_KEY", path="src/pay.py")]
        first = sarif_for(findings)["runs"][0]["results"]
        second = sarif_for(findings)["runs"][0]["results"]

        prints = [r["partialFingerprints"]["secretHash/v1"] for r in first]
        self.assertEqual(
            prints, [r["partialFingerprints"]["secretHash/v1"] for r in second])
        self.assertEqual(len(set(prints)), 2)

    def test_verified_flag_only_appears_once_a_check_actually_ran(self):
        log = sarif_for([raw()])
        self.assertNotIn("verifiedLive",
                         log["runs"][0]["results"][0]["properties"])


class TestNoLeakage(unittest.TestCase):
    def test_the_raw_secret_never_reaches_the_sarif(self):
        # The same invariant the other renderers are held to, and it matters
        # more here: a SARIF file gets uploaded to GitHub and shown in the
        # Security tab, so a leak lands somewhere permanent and shared.
        findings = [
            raw(),
            raw(secret=STRIPE, detector_type="STRIPE_KEY", path="src/pay.py"),
            raw(secret=ENTROPY_BLOB, detector_type="HIGH_ENTROPY",
                path="src/session.py", entropy=4.7),
        ]
        text = render_sarif(filter_and_score(findings))
        for secret in (LIVE_AWS, STRIPE, ENTROPY_BLOB):
            with self.subTest(secret=secret[:6]):
                self.assertNotIn(secret, text)


class TestGenerateReportBranch(unittest.TestCase):
    def test_sarif_is_reachable_through_generate_report(self):
        out = generate_report(filter_and_score([raw()]), "sarif")
        self.assertEqual(json.loads(out)["version"], "2.1.0")

    def test_unknown_format_still_errors(self):
        with self.assertRaises(ValueError):
            generate_report([], "yaml")


if __name__ == "__main__":
    unittest.main()
