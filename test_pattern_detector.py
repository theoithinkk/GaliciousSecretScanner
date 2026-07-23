"""
Unit tests for pattern_detector.py

Run with:  python3 -m pytest test_pattern_detector.py -v
(or, no pytest installed: python3 test_pattern_detector.py)
"""

from pattern_detector import detect


def _types(line):
    return {f.type for f in detect(line)}


# ---- true positives: each known format should be caught ----

def test_aws_access_key():
    assert "AWS_ACCESS_KEY" in _types('AKIA_KEY = "AKIAIOSFODNN7EXAMPLE"')

def test_aws_secret_key():
    assert "AWS_SECRET_KEY" in _types(
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    )

def test_generic_api_key():
    assert "GENERIC_API_KEY" in _types('api_key = "abcdefghij1234567890"')

def test_generic_password():
    assert "GENERIC_PASSWORD" in _types('password = "hunter2hunter2"')

def test_slack_token():
    assert "SLACK_TOKEN" in _types('token = "xoxb-0000000000-0000000000-0000000000000000000"')

def test_private_key_header():
    assert "PRIVATE_KEY_HEADER" in _types("-----BEGIN RSA PRIVATE KEY-----")

def test_db_connection_string():
    assert "DB_CONNECTION_STRING" in _types(
        'DATABASE_URL = "postgres://admin:S3cretPass@db.internal:5432/prod"'
    )

def test_jwt():
    assert "JWT" in _types(
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGhpc2lzYWZha2VzaWc"
    )

def test_github_token():
    assert "GITHUB_TOKEN" in _types("ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8")

def test_google_api_key():
    assert "GOOGLE_API_KEY" in _types("AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY")

def test_stripe_key():
    assert "STRIPE_KEY" in _types("sk_live_" + "abcdefghijklmnopqrstuvwx")


# ---- known non-secrets: should NOT be flagged ----

def test_boring_line_no_match():
    assert detect("x = 42  # just an int") == []

def test_short_password_below_threshold():
    # too short to meet the 4-char minimum after quotes are stripped
    assert _types('pwd = "ab"') == set()

def test_normal_prose_no_match():
    assert detect("The quick brown fox jumps over the lazy dog.") == []

def test_hex_color_no_match():
    # not a key/token/secret variable name, so nothing should trigger
    assert detect("background-color: #3498db;") == []


# ---- format-matches-but-is-a-placeholder ----
# NOTE: by design, detect() still flags these — recognizing that a
# format-valid string is a placeholder (YOUR_API_KEY_HERE, xxxxxxxx, etc.)
# is Person 4's job (is_placeholder / filter_and_score), not this module's.

def test_placeholder_style_key_is_still_matched_here():
    # AKIAEXAMPLE... matches the AWS format even though it's a placeholder.
    # This is intentional -- suppression happens downstream.
    assert "AWS_ACCESS_KEY" in _types('key = "AKIAIOSFODNN8EXAMPLE"')


if __name__ == "__main__":
    # allow running without pytest installed
    import sys

    tests = [
        (name, obj) for name, obj in list(globals().items())
        if name.startswith("test_") and callable(obj)
    ]
    failures = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError:
            failures += 1
            print(f"FAIL  {name}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)