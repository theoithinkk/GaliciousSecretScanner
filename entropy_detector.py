"""
entropy_detector.py
--------------------
Person 3's module: entropy-based detection of secrets that don't match a
known format (custom/internal tokens, one-off API keys, anything
pattern_detector.py's signature library doesn't know about).

Contract locked in with the group: detect(line: str) -> list[Finding]

Finding fields: {type: "HIGH_ENTROPY", matched_string, entropy_score, start_col, end_col}

Notes for integration:
- This module only looks at ONE line at a time, same as pattern_detector.py.
  It knows nothing about file paths, git history, or context (test/ vs src/,
  placeholder-ness, severity) -- that's Person 4's filter_and_score() step
  downstream, same as for pattern_detector.py's findings.
- The two modules are complementary, not overlapping: pattern_detector.py
  matches *known shapes* (AKIA..., xoxb-..., etc). This module exists for
  the secrets that AREN'T a known shape -- it flags high-randomness values
  sitting in a suspicious variable/key context instead of matching a regex
  signature.

Design summary (see inline comments for the reasoning behind each piece):
1. Tokenize the line into candidate (name, value) pairs -- either a clean
   `name = "value"` / `name: value` assignment, or (as a fallback) any
   quoted string on a line that otherwise mentions a suspicious keyword
   (e.g. a function call like `authenticate(user, "xK9...")` with no
   clean assignment to point at).
2. Throw out "obviously not a secret" candidates cheaply, before doing any
   entropy math: too short, all-digits, a UUID, a hex color, multi-word
   prose, or a small set of common placeholder-ish words.
3. Score what's left with Shannon entropy (bits/char). Below the
   threshold -> not random enough to be a generated secret, discard.
4. Only keep candidates whose (name or line) context contains one of:
   key, token, secret, password, passwd, pwd, auth, credential.
   This context requirement is what keeps false positives down --
   without it, plenty of ordinary high-entropy strings (hashes, IDs,
   build artifacts) would get flagged.
"""

from __future__ import annotations

import math
import re
from collections import Counter, namedtuple
from typing import Iterable, List, Optional, Tuple

Finding = namedtuple(
    "Finding", ["type", "matched_string", "entropy_score", "start_col", "end_col"]
)

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

# Shannon entropy of the candidate string, in bits/char. Typical guidance
# for base64/hex-ish secrets puts "clearly random" in the ~3.5-4.5 bits/char
# range (a purely random hex string tops out at log2(16) = 4.0 bits/char;
# a purely random base64 string tops out at log2(64) = 6.0 bits/char, but
# real generated secrets rarely hit that ceiling because they're short
# enough that not every character class gets used evenly).
#
# We picked the LOW end of that range (3.5) rather than the middle,
# because false negatives here are silently missed secrets, while false
# positives just get downgraded/filtered by Person 4's scoring step
# downstream. Between the two failure modes, this module would rather
# over-flag than under-flag.
ENTROPY_THRESHOLD = 3.5

# Below this length, entropy math gets noisy (a short string can look
# "random" just from having a few different characters) and short strings
# are also less useful to attackers anyway. 12 matches the minimum length
# pattern_detector.py already uses for its own GENERIC_SECRET pattern, so
# the two modules agree on what counts as "long enough to matter".
MIN_CANDIDATE_LENGTH = 12

# Variable/key names containing any of these (case-insensitive substring
# match) count as a "suspicious context". Extends the spec's base list
# (key, token, secret, password, auth, credential) with "passwd"/"pwd"
# since pattern_detector.py's own GENERIC_PASSWORD regex already treats
# those as password-equivalent -- keeps the two modules consistent.
CONTEXT_WORDS: Tuple[str, ...] = (
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "auth",
    "credential",
)

# Small, explicit list of words that could otherwise slip past the entropy
# check (long-ish, decent letter variety) but are obviously not secrets.
# Not trying to be a full dictionary -- just the placeholder-ish words
# that show up often enough in test/demo code to be worth naming.
COMMON_WORDS = frozenset(
    {
        "password",
        "changeme",
        "change_me",
        "example",
        "placeholder",
        "development",
        "production",
        "localhost",
        "administrator",
        "username",
        "letmein",
        "temporary",
        "undefined",
        "notasecret",
        "testing",
        "hunter2",
    }
)

# Values that FETCH a secret rather than BEING one. `os.environ["API_KEY"]` is
# long, sits next to a suspicious variable name, and scores well over the
# entropy threshold -- so without this, a codebase that has correctly moved its
# secrets into environment variables gets flagged for the reference it left
# behind. That is exactly backwards: it penalises the fix. A secret is a
# literal, never an expression that looks one up.
_ENV_REFERENCE_RE = re.compile(
    r"""
      os\.environ              # Python
    | os\.getenv
    | \bgetenv\s*\(            # C / PHP / Go
    | process\.env\b           # Node
    | \bENV\s*\[               # Ruby
    | System\.getenv           # Java
    | \$\{[^}]*\}              # ${VAR}      shell, compose, YAML
    | \{\{[^}]*\}\}            # {{ var }}   templating
    | <%=?[^%]*%>              # <%= var %>  ERB / EJS
    """,
    re.VERBOSE | re.IGNORECASE,
)

_HEX_COLOR_RE = re.compile(r"^#?[0-9A-Fa-f]{3}(?:[0-9A-Fa-f]{3})?$")
_UUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)

# Candidate 1: clean `name = value` / `name: value` assignments (Python,
# .env, JSON, YAML, JS object literals all fall into this shape). The name
# may itself be quoted (JSON-style keys). The value is either single- or
# double-quoted, or a bare token that stops at whitespace/comma/semicolon/
# a trailing comment.
_ASSIGNMENT_RE = re.compile(
    r"""
    ['"]?(?P<name>[A-Za-z_][A-Za-z0-9_\-]{1,60})['"]?
    \s*[:=]\s*
    (?:
        '(?P<sval>[^']*)'
      | "(?P<dval>[^"]*)"
      | (?P<bval>[^\s,;#]+)
    )
    """,
    re.VERBOSE,
)

# Candidate 2 (fallback): any quoted string, used only on lines that
# mention a suspicious keyword somewhere but didn't match a clean
# assignment above (e.g. positional function arguments).
_QUOTED_RE = re.compile(r"'([^']*)'|\"([^\"]*)\"")


class EntropyDetectorError(Exception):
    """Raised on bad input to the public helpers below."""


def shannon_entropy(s: str) -> float:
    """Shannon entropy of s, in bits/char. Empty string -> 0.0."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _has_suspicious_context(text: str, context_words: Iterable[str]) -> bool:
    lowered = text.lower()
    return any(word in lowered for word in context_words)


def _is_path_like_value(value: str) -> bool:
    """Common quoted literals that look like paths/URL/route strings, not secrets."""
    if value.startswith(('/', './', '../')):
        return True
    if value.startswith(('http://', 'https://')):
        return True
    return False


def _is_obvious_non_secret(value: str, min_length: int) -> bool:
    """Cheap structural checks that rule a candidate out before we bother
    computing entropy at all."""
    if len(value) < min_length:
        return True
    if value.isdigit():
        return True
    if _HEX_COLOR_RE.match(value):
        return True
    if _UUID_RE.match(value):
        return True
    if _ENV_REFERENCE_RE.search(value):
        return True
    if any(ch.isspace() for ch in value):
        # Real secrets don't contain whitespace. This is also what catches
        # multi-word prose like "lorem ipsum dolor sit amet".
        return True
    if value.lower() in COMMON_WORDS:
        return True
    return False


def _extract_value(match: "re.Match[str]") -> Optional[Tuple[str, int, int]]:
    for group in ("sval", "dval", "bval"):
        text = match.group(group)
        if text is not None:
            return text, match.start(group), match.end(group)
    return None


def _is_quoted_object_key(line: str, end: int) -> bool:
    """Quoted strings followed immediately by ':' are likely object keys."""
    return bool(re.match(r"\s*:\s*", line[end:]))


def _score_candidate(
    value: str, start: int, end: int, threshold: float, min_length: int
) -> Optional[Finding]:
    if _is_obvious_non_secret(value, min_length):
        return None

    score = shannon_entropy(value)
    if score < threshold:
        return None

    return Finding(
        type="HIGH_ENTROPY",
        matched_string=value,
        entropy_score=round(score, 2),
        start_col=start,
        end_col=end,
    )


def detect(
    line: str,
    threshold: float = ENTROPY_THRESHOLD,
    min_length: int = MIN_CANDIDATE_LENGTH,
    context_words: Iterable[str] = CONTEXT_WORDS,
) -> List[Finding]:
    """
    Scan a single line of text for high-entropy values sitting in a
    suspicious variable/key context.

    Returns 0+ Findings, same calling convention as pattern_detector.detect().
    threshold/min_length/context_words are exposed as parameters (rather
    than hardcoded) so unit tests -- and Person 4's tuning during the code
    review -- don't need to monkeypatch module constants.
    """
    findings: List[Finding] = []
    consumed_spans: List[Tuple[int, int]] = []

    # Pass 1: clean assignments, checked against the variable/key name.
    for match in _ASSIGNMENT_RE.finditer(line):
        extracted = _extract_value(match)
        if extracted is None:
            continue
        value, start, end = extracted
        consumed_spans.append((start, end))

        if not _has_suspicious_context(match.group("name"), context_words):
            continue

        finding = _score_candidate(value, start, end, threshold, min_length)
        if finding:
            findings.append(finding)

    # Pass 2 (fallback): no clean name=value pair, but the line mentions a
    # suspicious keyword somewhere (e.g. `authenticate(user, "xK9...")`).
    # Only look at quoted strings here -- bare tokens with no assignment
    # syntax are too ambiguous to isolate reliably.
    if _has_suspicious_context(line, context_words):
        for qmatch in _QUOTED_RE.finditer(line):
            value = qmatch.group(1) if qmatch.group(1) is not None else qmatch.group(2)
            start, end = (qmatch.span(1) if qmatch.group(1) is not None else qmatch.span(2))

            if any(s <= start < e or s < end <= e for s, e in consumed_spans):
                continue  # already handled in pass 1

            if _is_quoted_object_key(line, end):
                continue  # ignore quoted object keys when scanning suspicious lines

            if _is_path_like_value(value):
                continue  # ignore quoted routes/URLs in suspicious lines

            finding = _score_candidate(value, start, end, threshold, min_length)
            if finding:
                findings.append(finding)

    return findings


def make_detector(
    threshold: float = ENTROPY_THRESHOLD,
    min_length: int = MIN_CANDIDATE_LENGTH,
    context_words: Iterable[str] = CONTEXT_WORDS,
):
    """
    Build a standalone detect(line) function bound to custom tuning
    parameters. Mirrors pattern_detector.make_detector()'s shape so the two
    modules are easy to use side by side in the orchestration step.
    """

    def _detect(line: str) -> List[Finding]:
        return detect(
            line, threshold=threshold, min_length=min_length, context_words=context_words
        )

    return _detect


if __name__ == "__main__":
    # Quick manual smoke test, not the real test suite (see
    # test_entropy_detector.py for that).
    sample_lines = [
        'custom_token = "Zx9Qk2LpN8vRt5Wm3Yb7Jc1Fd6Hs4Ae0"',
        'internal_secret: 9fQ2mLp8XzT4vRb6Yk1Wc3Nd7Hs0Ae5G',
        'authenticate(user, "kP3xM8vZ2qL9wR5tY7bN4cF1dH6sA0e")',
        'session_id = "550e8400-e29b-41d4-a716-446655440000"',
        'background_color = "#3498db"',
        'retry_count = "12345678901234"',
        'bio = "lorem ipsum dolor sit amet consectetur"',
        'password = "changeme"',
        'greeting = "hello world"',
        'x = 42  # totally boring line, should produce nothing',
    ]

    for ln in sample_lines:
        results = detect(ln)
        print(f"\nLINE: {ln}")
        if not results:
            print("  (no matches)")
        for f in results:
            print(
                f"  -> {f.type}: {f.matched_string!r} "
                f"entropy={f.entropy_score} [{f.start_col}:{f.end_col}]"
            )
