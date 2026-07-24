"""
Unit tests for entropy_detector.py

Run with:  python3 -m pytest test_entropy_detector.py -v
(or, no pytest installed: python3 test_entropy_detector.py)
"""

from entropy_detector import detect, shannon_entropy

# A stand-in for "some real generated secret" used across several tests --
# high character variety, no dictionary structure, 32 chars long.
RANDOM_LOOKING_SECRET = "Zx9Qk2LpN8vRt5Wm3Yb7Jc1Fd6Hs4Ae0"


def _flagged(line):
    return bool(detect(line))


# ---- shannon_entropy() itself ----

def test_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0

def test_entropy_of_repeated_char_is_zero():
    # only one distinct character -> zero uncertainty -> zero entropy
    assert shannon_entropy("aaaaaaaaaaaa") == 0.0

def test_entropy_of_random_looking_string_is_high():
    assert shannon_entropy(RANDOM_LOOKING_SECRET) >= 4.0


# ---- true positives: high-entropy value + suspicious context ----

def test_flags_high_entropy_assignment_with_equals():
    assert _flagged(f'api_key = "{RANDOM_LOOKING_SECRET}"')

def test_flags_high_entropy_assignment_with_colon():
    assert _flagged(f'internal_secret: {RANDOM_LOOKING_SECRET}')

def test_flags_high_entropy_bare_unquoted_value():
    assert _flagged(f"auth_token={RANDOM_LOOKING_SECRET}")

def test_flags_high_entropy_in_function_call_fallback():
    # no clean name=value pair here -- relies on the pass-2 fallback that
    # looks for a context keyword anywhere on the line ("authenticate")
    assert _flagged(f'authenticate(user, "{RANDOM_LOOKING_SECRET}")')

def test_finding_shape_is_correct():
    findings = detect(f'api_key = "{RANDOM_LOOKING_SECRET}"')
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "HIGH_ENTROPY"
    assert f.matched_string == RANDOM_LOOKING_SECRET
    assert f.entropy_score >= 3.5
    assert f.start_col >= 0 and f.end_col > f.start_col


# ---- context requirement: no suspicious keyword -> never flag ----

def test_high_entropy_value_without_context_word_is_not_flagged():
    # same random-looking value as the passing tests above, but the
    # variable name doesn't mention key/token/secret/password/auth/credential
    assert not _flagged(f'value = "{RANDOM_LOOKING_SECRET}"')

def test_high_entropy_value_in_plain_line_is_not_flagged():
    assert not _flagged(RANDOM_LOOKING_SECRET)


# ---- known non-secrets: should NOT be flagged even WITH context ----

def test_uuid_used_as_id_not_flagged():
    # deliberately uses "secret" in the name so the only thing that can
    # save this from a false positive is the UUID structural filter
    assert not _flagged('secret_id = "550e8400-e29b-41d4-a716-446655440000"')

def test_hex_color_not_flagged():
    # deliberately uses "key" in the name -- hex-color filter must catch it
    assert not _flagged('api_key = "#3498db"')

def test_short_hex_color_not_flagged():
    assert not _flagged('auth_color = "#fff"')

def test_all_numeric_not_flagged():
    assert not _flagged('password = "12345678901234"')

def test_lorem_ipsum_not_flagged():
    assert not _flagged('secret_phrase = "lorem ipsum dolor sit amet"')

def test_common_placeholder_word_not_flagged():
    assert not _flagged('auth_key = "administrator"')

def test_short_string_below_min_length_not_flagged():
    # random-looking but under MIN_CANDIDATE_LENGTH (12)
    assert not _flagged('api_key = "Zx9Qk2"')

def test_boring_line_no_match():
    assert detect("x = 42  # just an int") == []


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
