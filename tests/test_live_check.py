"""
tests/test_live_check.py
------------------------
Covers live_check.py and the way filter_and_score consumes it.

Every test patches live_check._http, the single seam all four providers go
through, so the suite never opens a socket. Two things get asserted that are
easy to lose track of:

  - "could not check" (None) never turns into "dead" (False) anywhere
  - nothing calls a provider unless ScanContext.verify_live was explicitly set

The one thing a mocked HTTP layer cannot prove is that our SigV4 signature is
valid, since no mock ever verifies a signature. The HMAC chain is pinned
against the worked example published in the AWS SigV4 docs instead -- see
TestSigV4.
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from _helpers import REPO_ROOT  # noqa: F401  (sys.path side effect)

import live_check
from models import RawFinding, ScanContext, Severity
from scorer_reporter import filter_and_score

GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
SLACK_TOKEN = "xoxb-1234567890-abcdefGHIJKLMNOP"
AWS_KEY = "AKIA3RJQ7KZ2NDLPWXYZ"
AWS_SECRET = "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"


def ok(status: int, body=b""):
    """Shorthand for the (status, body) tuple _http hands back."""
    return status, body


class TestGitHub(unittest.TestCase):
    def test_200_is_live(self):
        with patch.object(live_check, "_http", return_value=ok(200, b"{}")):
            self.assertIs(live_check.check_github(GITHUB_TOKEN), True)

    def test_401_is_dead(self):
        with patch.object(live_check, "_http", return_value=ok(401)):
            self.assertIs(live_check.check_github(GITHUB_TOKEN), False)

    def test_403_is_unknown_not_dead(self):
        # Rate limiting and SSO-blocked tokens both land here, and neither
        # means the credential stopped working.
        with patch.object(live_check, "_http", return_value=ok(403)):
            self.assertIsNone(live_check.check_github(GITHUB_TOKEN))

    def test_transport_failure_is_unknown(self):
        with patch.object(live_check, "_http", return_value=None):
            self.assertIsNone(live_check.check_github(GITHUB_TOKEN))

    def test_token_is_sent_as_a_bearer_header(self):
        with patch.object(live_check, "_http", return_value=ok(200)) as http:
            live_check.check_github(GITHUB_TOKEN)
        _, url, headers = http.call_args.args[:3]
        self.assertEqual(url, "https://api.github.com/user")
        self.assertEqual(headers["Authorization"], f"Bearer {GITHUB_TOKEN}")


class TestStripe(unittest.TestCase):
    def test_200_is_live(self):
        with patch.object(live_check, "_http", return_value=ok(200, b"{}")):
            self.assertIs(live_check.check_stripe(STRIPE_KEY), True)

    def test_401_is_dead(self):
        with patch.object(live_check, "_http", return_value=ok(401)):
            self.assertIs(live_check.check_stripe(STRIPE_KEY), False)

    def test_429_is_unknown(self):
        with patch.object(live_check, "_http", return_value=ok(429)):
            self.assertIsNone(live_check.check_stripe(STRIPE_KEY))


class TestSlack(unittest.TestCase):
    def test_ok_true_is_live(self):
        with patch.object(live_check, "_http",
                          return_value=ok(200, b'{"ok": true, "user": "bot"}')):
            self.assertIs(live_check.check_slack(SLACK_TOKEN), True)

    def test_invalid_auth_is_dead(self):
        with patch.object(live_check, "_http",
                          return_value=ok(200, b'{"ok": false, "error": "invalid_auth"}')):
            self.assertIs(live_check.check_slack(SLACK_TOKEN), False)

    def test_ratelimited_is_unknown(self):
        # Slack answers 200 with ok:false here too, but it says nothing about
        # whether the token still works.
        with patch.object(live_check, "_http",
                          return_value=ok(200, b'{"ok": false, "error": "ratelimited"}')):
            self.assertIsNone(live_check.check_slack(SLACK_TOKEN))

    def test_unparseable_body_is_unknown(self):
        with patch.object(live_check, "_http", return_value=ok(200, b"<html>502</html>")):
            self.assertIsNone(live_check.check_slack(SLACK_TOKEN))


class TestAWS(unittest.TestCase):
    def test_missing_secret_half_skips_the_request_entirely(self):
        with patch.object(live_check, "_http") as http:
            self.assertIsNone(live_check.check_aws(AWS_KEY, None))
        http.assert_not_called()

    def test_200_is_live(self):
        with patch.object(live_check, "_http", return_value=ok(200, b"<GetCallerIdentity/>")):
            self.assertIs(live_check.check_aws(AWS_KEY, AWS_SECRET), True)

    def test_invalid_client_token_is_dead(self):
        body = b"<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>"
        with patch.object(live_check, "_http", return_value=ok(403, body)):
            self.assertIs(live_check.check_aws(AWS_KEY, AWS_SECRET), False)

    def test_signature_mismatch_is_unknown_not_dead(self):
        # The key id is real here; we just paired it with the wrong secret.
        # Calling that "dead" would be wrong in the dangerous direction.
        body = b"<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>"
        with patch.object(live_check, "_http", return_value=ok(403, body)):
            self.assertIsNone(live_check.check_aws(AWS_KEY, AWS_SECRET))


class TestSigV4(unittest.TestCase):
    def test_signing_key_matches_the_published_aws_example(self):
        # The worked example from AWS's own docs for deriving a SigV4 signing
        # key. A mocked provider can't tell us the signature is right, so this
        # fixed vector is what actually pins the HMAC chain.
        key = live_check.derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830", "us-east-1", "iam",
        )
        self.assertEqual(
            key.hex(),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9",
        )

    def test_authorization_header_is_well_formed(self):
        headers = live_check._sigv4_headers(AWS_KEY, AWS_SECRET, "Action=GetCallerIdentity")
        auth = headers["Authorization"]
        self.assertTrue(auth.startswith("AWS4-HMAC-SHA256 Credential="))
        self.assertIn(f"{AWS_KEY}/", auth)
        self.assertIn("/us-east-1/sts/aws4_request", auth)
        self.assertIn("SignedHeaders=content-type;host;x-amz-date", auth)
        signature = auth.rsplit("Signature=", 1)[1]
        self.assertEqual(len(signature), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in signature))

    def test_the_secret_never_appears_in_the_headers(self):
        headers = live_check._sigv4_headers(AWS_KEY, AWS_SECRET, "Action=GetCallerIdentity")
        self.assertNotIn(AWS_SECRET, json.dumps(headers))


class TestVerifyDispatch(unittest.TestCase):
    def test_types_with_no_provider_never_hit_the_network(self):
        with patch.object(live_check, "_http") as http:
            for detector_type in ("JWT", "HIGH_ENTROPY", "PRIVATE_KEY_HEADER",
                                  "DB_CONNECTION_STRING", "GENERIC_PASSWORD"):
                with self.subTest(detector_type=detector_type):
                    self.assertIsNone(live_check.verify(detector_type, "whatever"))
        http.assert_not_called()

    def test_empty_secret_is_not_checked(self):
        with patch.object(live_check, "_http") as http:
            self.assertIsNone(live_check.verify("GITHUB_TOKEN", ""))
        http.assert_not_called()

    def test_verifiable_types_are_the_four_providers(self):
        self.assertEqual(
            set(live_check.verifiable_types()),
            {"AWS_ACCESS_KEY", "GITHUB_TOKEN", "STRIPE_KEY", "SLACK_TOKEN"},
        )


def raw(secret=GITHUB_TOKEN, detector_type="GITHUB_TOKEN", path="src/app.py", line=1):
    content = f'token = "{secret}"'
    start = content.index(secret)
    return RawFinding(
        detector_type=detector_type, matched_string=secret, file_path=path,
        line_number=line, line_content=content,
        start_col=start, end_col=start + len(secret),
    )


class TestScorerIntegration(unittest.TestCase):
    """filter_and_score's half of the feature: opt-in, scoring, wording."""

    def test_verification_is_off_by_default(self):
        with patch.object(live_check, "verify") as verify:
            scored = filter_and_score([raw()])
        verify.assert_not_called()
        self.assertIsNone(scored[0].verified)

    def test_placeholders_are_never_sent_to_a_provider(self):
        ctx = ScanContext(verify_live=True, keep_placeholders=True)
        with patch.object(live_check, "verify") as verify:
            filter_and_score([raw(secret="YOUR_API_KEY_HERE")], ctx)
        verify.assert_not_called()

    def test_live_credential_outranks_the_same_unverified_one(self):
        ctx = ScanContext(verify_live=True)
        with patch.object(live_check, "verify", return_value=True):
            live = filter_and_score([raw()], ctx)[0]
        unchecked = filter_and_score([raw()])[0]

        self.assertIs(live.verified, True)
        self.assertGreater(live.points, unchecked.points)
        self.assertGreaterEqual(live.severity, unchecked.severity)

    def test_a_live_key_in_a_test_path_is_promoted_to_critical(self):
        # The whole point of verification. The -20 test-path discount exists
        # to quiet fixtures full of fake keys, and it is exactly what would
        # bury a real credential somebody pasted into tests/ -- confirming it
        # live has to be enough to overrule the location.
        ctx = ScanContext(verify_live=True)
        with patch.object(live_check, "verify", return_value=True):
            live = filter_and_score([raw(path="tests/test_api.py")], ctx)[0]
        unchecked = filter_and_score([raw(path="tests/test_api.py")])[0]

        self.assertEqual(live.severity, Severity.CRITICAL)
        self.assertEqual(unchecked.severity, Severity.HIGH)

    def test_dead_credential_is_floored_at_low(self):
        ctx = ScanContext(verify_live=True)
        with patch.object(live_check, "verify", return_value=False):
            dead = filter_and_score([raw(path=".env")], ctx)[0]
        self.assertIs(dead.verified, False)
        self.assertEqual(dead.severity, Severity.LOW)

    def test_unknown_verdict_leaves_the_score_alone(self):
        ctx = ScanContext(verify_live=True)
        with patch.object(live_check, "verify", return_value=None):
            unknown = filter_and_score([raw()], ctx)[0]
        baseline = filter_and_score([raw()])[0]
        self.assertIsNone(unknown.verified)
        self.assertEqual(unknown.points, baseline.points)

    def test_rationale_distinguishes_all_three_verdicts(self):
        ctx = ScanContext(verify_live=True)
        wording = {}
        for verdict in (True, False, None):
            with patch.object(live_check, "verify", return_value=verdict):
                wording[verdict] = filter_and_score([raw()], ctx)[0].rationale

        self.assertIn("provider accepted", wording[True])
        self.assertIn("provider rejected", wording[False])
        self.assertIn("Not verified", wording[None])
        # A reader must never have to guess which of the three they got.
        self.assertEqual(len(set(wording.values())), 3)

    def test_aws_key_is_paired_with_a_secret_from_the_same_file(self):
        # Separate lines on purpose: two hits on one line of one file are the
        # same leak as far as dedup is concerned, and a real credential pair
        # is written out as two lines anyway.
        findings = [
            raw(secret=AWS_KEY, detector_type="AWS_ACCESS_KEY", path=".env", line=1),
            raw(secret=AWS_SECRET, detector_type="AWS_SECRET_KEY", path=".env", line=2),
        ]
        ctx = ScanContext(verify_live=True)
        with patch.object(live_check, "verify", return_value=None) as verify:
            filter_and_score(findings, ctx)

        paired = {c.args[0]: c.kwargs.get("aws_secret_key") for c in verify.call_args_list}
        self.assertEqual(paired["AWS_ACCESS_KEY"], AWS_SECRET)

    def test_aws_key_alone_in_a_file_gets_no_secret_to_pair_with(self):
        ctx = ScanContext(verify_live=True)
        findings = [raw(secret=AWS_KEY, detector_type="AWS_ACCESS_KEY", path=".env")]
        with patch.object(live_check, "verify", return_value=None) as verify:
            filter_and_score(findings, ctx)
        self.assertIsNone(verify.call_args.kwargs.get("aws_secret_key"))


if __name__ == "__main__":
    unittest.main()
