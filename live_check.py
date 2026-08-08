"""
live_check.py
-------------
Opt-in verification: ask the provider itself whether a candidate secret still
works.

The rest of the scanner answers "does this look like an AWS key". This answers
"is this a live AWS key". It is also our answer to "why not just use GitHub's
secret scanning" -- GitHub let every fabricated key in this project's own test
fixture through, because none of them are live.

Contract:
    verify(detector_type, secret, aws_secret_key=None) -> True | False | None

    True   the provider accepted the credential
    False  the provider rejected it (revoked, rotated, or never existed)
    None   no verifier for that detector type, or the check could not be
           completed -- offline, rate limited, timed out, unexpected status

None is NOT a soft False. Nothing downstream may report "dead" on a None.

This is the only module in the project that makes outbound requests, and it
gets there by sending the candidate secret to a third party. So:
  - nothing calls it unless ScanContext.verify_live is explicitly set
  - request and response bodies stay inside this module; callers get a verdict
    and nothing else
  - the secret still never reaches a report, since ScoredFinding only ever
    carries the redacted form
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

# Short by design. A scan can verify many findings, and a provider that has
# gone unreachable should cost the scan seconds, not minutes.
TIMEOUT = 6.0

_UA = "GaliciousSecretScanner/1.0 (credential verification)"


def _http(method: str, url: str, headers: dict = None, body: bytes = None):
    """
    Return (status, body_bytes), or None if the request never completed.

    Every provider check goes through here, so the test suite has exactly one
    seam to patch. The suite must never touch a real network.
    """
    req = urllib.request.Request(
        url, method=method, data=body,
        headers={"User-Agent": _UA, **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        # A 401 is an answer, not a failure -- read it like any other response.
        return e.code, e.read()
    except (urllib.error.URLError, OSError, ValueError):
        return None


def check_github(token: str) -> Optional[bool]:
    """GET /user -- 200 means the token authenticated as somebody."""
    r = _http("GET", "https://api.github.com/user", {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    })
    if r is None:
        return None
    status = r[0]
    if status == 200:
        return True
    if status == 401:
        return False
    # 403 covers rate limiting and tokens that are valid but blocked by an org
    # SSO policy. Neither of those means the credential is dead.
    return None


def check_stripe(key: str) -> Optional[bool]:
    """GET /v1/account -- the cheapest authenticated call Stripe exposes."""
    r = _http("GET", "https://api.stripe.com/v1/account",
              {"Authorization": f"Bearer {key}"})
    if r is None:
        return None
    status = r[0]
    if status == 200:
        return True
    if status == 401:
        return False
    return None


# Slack error codes that mean the token itself is finished. Anything else
# (ratelimited, fatal_error, internal_error) is a failed check, not a dead key.
_SLACK_DEAD = {"invalid_auth", "account_inactive", "token_revoked", "token_expired"}


def check_slack(token: str) -> Optional[bool]:
    """
    auth.test. Slack answers 200 for a bad token too, so the verdict is in the
    body's `ok` field rather than the status code.
    """
    r = _http(
        "POST", "https://slack.com/api/auth.test",
        {"Content-Type": "application/x-www-form-urlencoded"},
        urllib.parse.urlencode({"token": token}).encode(),
    )
    if r is None:
        return None
    status, body = r
    if status != 200:
        return None
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return None
    if payload.get("ok"):
        return True
    return False if payload.get("error") in _SLACK_DEAD else None


def _sigv4_headers(access_key_id: str, secret_key: str, body: str) -> dict:
    """
    Signature Version 4 for one fixed request: POST sts:GetCallerIdentity in
    us-east-1.

    Hand-rolled on hmac/hashlib because botocore is not a dependency here and
    pulling in the AWS SDK for a single signature is not worth the install.
    """
    host = "sts.amazonaws.com"
    region, service = "us-east-1", "sts"
    content_type = "application/x-www-form-urlencoded; charset=utf-8"

    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")

    signed_headers = "content-type;host;x-amz-date"
    canonical_headers = (
        f"content-type:{content_type}\n"
        f"host:{host}\n"
        f"x-amz-date:{amz_date}\n"
    )
    canonical_request = "\n".join([
        "POST", "/", "",
        canonical_headers,
        signed_headers,
        hashlib.sha256(body.encode()).hexdigest(),
    ])

    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    key = derive_signing_key(secret_key, datestamp, region, service)
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()

    return {
        "Content-Type": content_type,
        "X-Amz-Date": amz_date,
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        ),
    }


def derive_signing_key(secret_key: str, datestamp: str,
                       region: str, service: str) -> bytes:
    """
    The four-step HMAC chain from the SigV4 spec. Split out from
    _sigv4_headers so the test suite can check it against AWS's published
    worked example -- the rest of the signature is bound to the current
    timestamp and can't be pinned to a fixed expected value.
    """
    key = f"AWS4{secret_key}".encode()
    for part in (datestamp, region, service, "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    return key


def check_aws(access_key_id: str, secret_key: Optional[str]) -> Optional[bool]:
    """
    sts:GetCallerIdentity, the standard "who am I" probe -- it needs no IAM
    permissions, so it works for any credential that exists at all.

    Both halves of the credential are required to sign the request. A bare
    AKIA... with no matching secret found nearby is therefore unverifiable and
    returns None instead of a guess.
    """
    if not access_key_id or not secret_key:
        return None

    body = "Action=GetCallerIdentity&Version=2011-06-15"
    r = _http("POST", "https://sts.amazonaws.com/",
              _sigv4_headers(access_key_id, secret_key, body), body.encode())
    if r is None:
        return None

    status, payload = r
    if status == 200:
        return True

    text = payload.decode("utf-8", "replace") if payload else ""
    if "InvalidClientTokenId" in text:
        return False        # no AWS account has ever held this key id
    # SignatureDoesNotMatch says the key id is real but the secret we paired it
    # with belongs to something else. That is not proof this pair is usable, so
    # it stays unknown rather than being called live.
    return None


_CHECKERS = {
    "GITHUB_TOKEN": check_github,
    "STRIPE_KEY": check_stripe,
    "SLACK_TOKEN": check_slack,
}


def verify(detector_type: str, secret: str,
           aws_secret_key: Optional[str] = None) -> Optional[bool]:
    """
    Dispatch to the right provider. An unknown detector type is not an error --
    most findings (JWTs, private keys, DB strings, entropy hits) have nobody to
    ask, and they come back None.
    """
    if not secret:
        return None
    if detector_type == "AWS_ACCESS_KEY":
        return check_aws(secret, aws_secret_key)
    checker = _CHECKERS.get(detector_type)
    return checker(secret) if checker else None


def verifiable_types() -> tuple:
    """Detector types this module can actually reach a provider for."""
    return ("AWS_ACCESS_KEY", *_CHECKERS)
