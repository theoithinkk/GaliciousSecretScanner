"""
scorer_reporter.py
------------------
Person 4's module: filter, score, and report.

Takes the RAW findings produced upstream (Person 2's regex detector +
Person 3's entropy detector, each already tied back to Person 1's walker
metadata: file path, commit hash, line number, line content) and turns them
into a clean, ranked, human-explainable report.

Public contract (locked in with the group):
    filter_and_score(findings, context=None) -> list[ScoredFinding]
    generate_report(scored_findings, fmt="terminal", output_path=None) -> str

Everything else in here is a helper. The two functions above are the API.

What this module is responsible for (and the upstream modules are NOT):
- Suppressing placeholders (YOUR_API_KEY_HERE, changeme, xxxx, <insert-key>).
- Scoring severity from context: where the file lives (test/ vs source vs
  .env), whether the secret is still in the working tree or only in history,
  and how confident the detector was (entropy).
- Redaction: no full secret ever reaches an output -- not the masked value,
  and not the surrounding line either.
- A plain-language rationale per finding, so a reviewer never has to reverse
  engineer the score.

Data shapes live in models.py; the terminal/JSON/SARIF renderers live in
reporters.py (the themed HTML one lives in web/html_report.py); collapsing
duplicate hits into one leak lives in dedup.py. This file is just the scoring
logic.

Asking a provider whether a secret is actually live lives in live_check.py.
It only runs when ScanContext.verify_live is set, because it puts the
candidate secret on the network.

The scoring rubric is deliberately a small, documented point system (see
SCORING RUBRIC below) rather than a black box, because it has to be
defensible out loud in a code review.
"""

from __future__ import annotations

import os
import re
from typing import Iterable, List, Optional, Union

import live_check
from dedup import deduplicate as _dedup
from models import Severity, RawFinding, ScoredFinding, ScanContext
from reporters import render_terminal, render_json, render_sarif


# Placeholder filter

# Values that LOOK like secrets to a regex/entropy check but are obviously
# fill-in-the-blanks. Matched case-insensitively against the secret itself.
_PLACEHOLDER_PATTERNS = [
    r"your[_\- ]?(api[_\-]?)?(key|token|secret|password)[_\- ]?here",
    r"insert[_\- ].*(key|token|secret)",
    r"replace[_\- ]?me",
    r"change[_\- ]?me",
    r"<[^>]+>",                     # <insert-key-here>, <token>, angle-bracket tokens
    r"\{\{.*\}\}",                  # {{ template placeholders }}
    r"\$\{[^}]*\}",                 # ${DB_PASSWORD} -- substitution, not a literal
    # An env lookup is the correct way to hold a secret, so flagging the lookup
    # itself would penalise code that has already been fixed.
    r"os\.environ|os\.getenv|process\.env|getenv\s*\(|System\.getenv",
    r"example",
    r"placeholder",
    r"dummy",
    r"redacted",
    r"notasecret",
    r"^x{4,}$",                     # xxxxxxxx
    r"^0{4,}$",                     # 00000000
    r"^(foo|bar|baz|qux)+$",
    r"^(sk_test_|pk_test_)",       # Stripe TEST keys are not live secrets
]
_PLACEHOLDER_RE = re.compile("|".join(_PLACEHOLDER_PATTERNS), re.IGNORECASE)


def is_placeholder(secret: str, extra_patterns: Iterable[str] = ()) -> bool:
    """
    True if the value is a known placeholder rather than a real secret.
    Two cheap signals: it matches a placeholder pattern, or it has almost no
    character variety (e.g. 'xxxxxxxxxxxx' -> 1 distinct char).
    """
    if not secret:
        return True

    s = secret.strip().lower()

    # Password workflow labels are not secrets; they are UI/form-field names or
    # human-readable labels, not literal credentials. Suppress them before they
    # reach the score/report layer.
    workflow_patterns = [
        r"^changeme$",
        r"^change[_-]?password$",
        r"^new[_-]?password$",
        r"^reset[_-]?password$",
        r"^update[_-]?password$",
        r"^confirm[_-]?password$",
        r"^current[_-]?password$",
        r"^old[_-]?password$",
        r"^password[_-]?(change|reset|update|new|confirm|current|old)$",
        r"^password[_-]?changed$",
    ]
    if any(re.fullmatch(p, s) for p in workflow_patterns):
        return True

    if _PLACEHOLDER_RE.search(secret):
        return True
    for pat in extra_patterns:
        if re.search(pat, secret, re.IGNORECASE):
            return True
    # 8+ char string built from <=2 distinct chars is not a generated secret
    if len(secret) >= 8 and len(set(secret)) <= 2:
        return True
    return False


# Redaction

def redact_secret(secret: str) -> str:
    """Keep a short recognizable prefix, mask the rest. 'AKIA...' -> 'AKIA****'."""
    if not secret:
        return ""
    n = len(secret)
    reveal = 4 if n > 8 else (1 if n > 3 else 0)
    stars = min(n - reveal, 20)          # cap so a huge blob doesn't produce a huge mask
    return secret[:reveal] + ("*" * stars)


def _redact_line(line: str, secret: str, redacted: str,
                 start: Optional[int], end: Optional[int]) -> str:
    """Return the source line with the secret spliced out and masked."""
    if not line:
        return ""
    if start is not None and end is not None and 0 <= start < end <= len(line):
        line = line[:start] + redacted + line[end:]
    elif secret and secret in line:
        line = line.replace(secret, redacted)
    # Safety net: if for any reason the raw secret still survives, blanket-mask it.
    if secret and secret in line:
        line = line.replace(secret, redacted)
    return line.strip()[:200]


# ---------------------------------------------------------------------------
# SCORING RUBRIC  (explainable point system)
# ---------------------------------------------------------------------------
#
# Final points -> severity band:
#     >= 45  CRITICAL      >= 30  HIGH      >= 15  MEDIUM      else  LOW
#
# Base points = "how bad is a real leak of this KIND of secret":
#     50  live cloud / signing credentials (AWS, DB creds, private keys, Stripe live, GitHub, Google)
#     35  scoped service tokens (Slack, generic API keys, JWT)
#     20  weak / low-confidence signals (generic secret, generic password, high-entropy blob)
#
# Modifiers = "how exposed / how confident is THIS instance":
#     +15  file is a .env file            (secrets in .env are meant to be real)
#     +10  file is a config file          (yaml/json/ini/toml/...)
#      +5  file is source code
#     -20  file lives under test/example/mock/sample/fixture
#     -25  file is docs/README/markdown
#      -5  history-only (already removed from working tree -- still leaked, less urgent)
#     +10  entropy >= 4.5   /   +5  entropy >= 4.0   (stronger evidence it's a real random secret)
#     +25  confirmed live by the provider  (--verify-live only; see live_check.py)
#     cap 10  confirmed dead by the provider -- floors it at LOW
#
# Rationale: false NEGATIVES (a missed live key) are far more expensive than
# false POSITIVES (a downgraded test fixture), so the base numbers lean high
# and the discounts for test/docs contexts are what pull noise back down.

_BASE_POINTS = {
    # 50 - live, high-blast-radius credentials
    "AWS_ACCESS_KEY": 50, "AWS_SECRET_KEY": 50, "PRIVATE_KEY_HEADER": 50,
    "DB_CONNECTION_STRING": 50, "STRIPE_KEY": 50, "GITHUB_TOKEN": 50,
    "GOOGLE_API_KEY": 50,
    # 35 - scoped service tokens
    "SLACK_TOKEN": 35, "SLACK_WEBHOOK": 35, "GENERIC_API_KEY": 35, "JWT": 35,
    # 20 - weak / low-confidence
    "GENERIC_SECRET": 20, "GENERIC_PASSWORD": 20, "HIGH_ENTROPY": 20,
}
_DEFAULT_BASE = 25   # unknown detector type: treat as mid-tier

_TEST_SEGMENTS = {
    "test", "tests", "spec", "specs", "example", "examples", "mock", "mocks",
    "__mocks__", "sample", "samples", "fixture", "fixtures", "testdata", "demo",
}
_CONFIG_EXTS = {".yml", ".yaml", ".json", ".ini", ".toml", ".cfg", ".conf",
                ".properties", ".xml", ".env"}
_SOURCE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb",
                ".php", ".c", ".cpp", ".cs", ".sh", ".rs", ".kt", ".swift",
                ".scala", ".pl"}
_DOC_EXTS = {".md", ".markdown", ".rst", ".txt"}


def _classify_file(path: str) -> str:
    """One label per file: env | config | source | test | docs | other."""
    p = path.replace("\\", "/").lower()
    base = os.path.basename(p)
    _, ext = os.path.splitext(base)
    segments = set(p.split("/"))

    if segments & _TEST_SEGMENTS:
        return "test"
    if base == ".env" or base.startswith(".env"):
        return "env"
    if base in {"readme", "readme.md", "changelog", "changelog.md"} or ext in _DOC_EXTS:
        return "docs"
    if ext in _CONFIG_EXTS:
        return "config"
    if ext in _SOURCE_EXTS:
        return "source"
    return "other"


def _score_one(rf: RawFinding,
               verified: Optional[bool] = None) -> tuple[int, str, List[str]]:
    """Return (points, file_class, list-of-reason-clauses) for a raw finding."""
    points = _BASE_POINTS.get(rf.detector_type, _DEFAULT_BASE)
    reasons = [f"{rf.detector_type} pattern (base {points})"]

    file_class = _classify_file(rf.file_path)
    if file_class == "env":
        points += 15
        reasons.append("in a .env file (+15)")
    elif file_class == "config":
        points += 10
        reasons.append("in a config file (+10)")
    elif file_class == "source":
        points += 5
        reasons.append("in source code (+5)")
    elif file_class == "test":
        points -= 20
        reasons.append("in a test/example path (-20)")
    elif file_class == "docs":
        points -= 25
        reasons.append("in docs/markdown (-25)")

    # Only reachable for history-ONLY findings: deduplicate() gives a leak that
    # is still in the working tree a representative with commit_hash=None, even
    # when the same secret also appears in history. So this discount can no
    # longer be applied to a live credential.
    if rf.commit_hash:
        points -= 5
        reasons.append("history-only, removed from working tree (-5)")

    if rf.entropy_score is not None:
        if rf.entropy_score >= 4.5:
            points += 10
            reasons.append(f"very high entropy {rf.entropy_score} (+10)")
        elif rf.entropy_score >= 4.0:
            points += 5
            reasons.append(f"high entropy {rf.entropy_score} (+5)")

    # Applied last, because a provider's answer outranks everything inferred
    # from where the file sits. A live key in tests/ is still a live key, and
    # no amount of .env context makes a revoked one urgent.
    if verified is True:
        points += 25
        reasons.append("confirmed live by the provider (+25)")
    elif verified is False:
        points = min(points, 10)
        reasons.append("provider rejected this credential (capped)")

    return points, file_class, reasons


def _band(points: int) -> Severity:
    if points >= 45:
        return Severity.CRITICAL
    if points >= 30:
        return Severity.HIGH
    if points >= 15:
        return Severity.MEDIUM
    return Severity.LOW


# Deduplication lives in dedup.py; it only needs to know which detector type is
# the more specific match, which is a scoring judgement, so the rubric's base
# points are handed to it rather than imported from here (and the import stays
# one-directional).

def _base_points(detector_type: str) -> int:
    return _BASE_POINTS.get(detector_type, _DEFAULT_BASE)


def deduplicate(findings: Iterable[RawFinding]) -> List[RawFinding]:
    """
    Collapse raw findings so one leaked secret produces one finding.
    See dedup.py for what "the same leak" means and why it matters.
    """
    return _dedup(findings, _base_points)



# Public API 1: filter_and_score

def _coerce(f: Union[RawFinding, dict]) -> RawFinding:
    """Accept a RawFinding or a plain dict (e.g. loaded from JSON)."""
    if isinstance(f, RawFinding):
        return f
    if isinstance(f, dict):
        allowed = RawFinding.__dataclass_fields__.keys()
        return RawFinding(**{k: v for k, v in f.items() if k in allowed})
    raise TypeError(f"Cannot interpret finding of type {type(f).__name__}")


def _aws_secrets_by_file(findings: List[RawFinding]) -> dict:
    """
    Map file path -> AWS secret access key found in that file.

    Signing an STS request needs the access key id AND its secret, but the
    detectors report them as two separate findings. Pairing them by file is
    the assumption that actually holds in practice: whoever hardcodes an
    AKIA... puts the matching secret on the next line of the same .env or
    config. Anything that doesn't pair up stays unverifiable, which is the
    honest answer rather than a guess.
    """
    return {
        rf.file_path: rf.matched_string
        for rf in findings
        if rf.detector_type == "AWS_SECRET_KEY"
    }


def filter_and_score(
    findings: Iterable[Union[RawFinding, dict]],
    context: Optional[ScanContext] = None,
) -> List[ScoredFinding]:
    """
    Deduplicate, drop placeholders, score the rest, and return them sorted
    worst-first.

    `context` is optional scan-wide config (see ScanContext). Per-finding
    context (file location, working-tree vs history, entropy) is read from
    each finding's own metadata.

    Dedup runs FIRST so that one leaked secret is scored once (see the
    DEDUPLICATION section above) and so the entropy evidence merged off
    duplicates is available to the scorer.
    """
    ctx = context or ScanContext()
    scored: List[ScoredFinding] = []

    deduped = list(deduplicate(_coerce(f) for f in findings))
    aws_secrets = _aws_secrets_by_file(deduped) if ctx.verify_live else {}

    for rf in deduped:
        placeholder = is_placeholder(rf.matched_string, ctx.extra_placeholder_patterns)
        if placeholder and not ctx.keep_placeholders:
            continue  # suppressed entirely

        # Opt-in, and skipped for placeholders -- there is no point spending a
        # network round trip to be told YOUR_API_KEY_HERE isn't a live token.
        verified = None
        if ctx.verify_live and not placeholder:
            verified = live_check.verify(
                rf.detector_type, rf.matched_string,
                aws_secret_key=aws_secrets.get(rf.file_path),
            )

        points, file_class, reasons = _score_one(rf, verified)
        if placeholder:  # kept only because ctx.keep_placeholders is on
            points = min(points, 10)
            reasons.append("looks like a placeholder (capped)")

        severity = _band(points)
        exposure = "history_only" if rf.commit_hash else "working_tree"
        redacted = redact_secret(rf.matched_string)
        redacted_ctx = _redact_line(
            rf.line_content, rf.matched_string, redacted, rf.start_col, rf.end_col
        )

        if exposure == "working_tree":
            exposure_phrase = "still in the working tree"
            if rf.history_commits:
                # Live AND committed: deleting the line is not enough, the
                # blob stays reachable in history until it's purged.
                exposure_phrase += (
                    f" and committed to history (introduced in "
                    f"{rf.history_commits[0]}, {len(rf.history_commits)} commit(s))"
                )
        else:
            exposure_phrase = f"only in git history (commit {rf.commit_hash})"
            if len(rf.history_commits) > 1:
                exposure_phrase += f", seen in {len(rf.history_commits)} commits"

        rationale = (
            f"{severity.label} severity: {redacted} ({rf.detector_type}), "
            f"{exposure_phrase}. Score {points} from " + ", ".join(reasons) + "."
        )
        # Say which of the three answers this was, in words. "Not checked" and
        # "checked, came back dead" lead to opposite actions, so a reader must
        # never have to infer which one they're looking at.
        if verified is True:
            rationale += (" Verified: the provider accepted this credential, "
                          "so it is live and needs rotating now.")
        elif verified is False:
            rationale += (" Verified: the provider rejected this credential, "
                          "so it is already dead -- clean it up, no rush.")
        elif ctx.verify_live:
            rationale += (" Not verified: no provider check is available for "
                          "this type, or the check could not be completed.")

        scored.append(ScoredFinding(
            detector_type=rf.detector_type,
            file_path=rf.file_path,
            line_number=rf.line_number,
            severity=severity,
            points=points,
            exposure=exposure,
            commit_hash=rf.commit_hash,
            redacted=redacted,
            redacted_context=redacted_ctx,
            rationale=rationale,
            entropy_score=rf.entropy_score,
            file_class=file_class,
            occurrences=rf.occurrences,
            history_commits=rf.history_commits,
            verified=verified,
        ))

    scored = [s for s in scored if s.severity >= ctx.min_severity]
    scored.sort(key=lambda s: (s.severity, s.points), reverse=True)
    return scored


# Public API 2: generate_report
def generate_report(
    scored_findings: List[ScoredFinding],
    fmt: str = "terminal",
    output_path: Optional[str] = None,
    use_color: Optional[bool] = None,
    target: str = "",
    fix_enabled: bool = False,
    home_url: Optional[str] = None,
    suppressed: int = 0,
) -> str:
    """
    Render scored findings. fmt is "terminal" | "json" | "sarif" | "html".
    Returns the rendered string; also writes it to output_path if given.

    Terminal/json/sarif rendering lives in reporters.py, alongside the detection
    engine at the repo root. HTML rendering lives in web/html_report.py and is
    only imported here, lazily, when fmt="html" is actually requested -- so
    nothing at the root has a hard import-time dependency on the web/
    package (or on Flask, which web/app.py needs but this module doesn't).

    fix_enabled (html only) turns on the one-click fix in the report's detail
    panel, home_url (html only) adds a link back to the scan form, and
    suppressed (html only) states how many findings a baseline hid. Only
    web/app.py passes any of them -- the first two need a live server behind
    the page, which a report saved to disk doesn't have.
    """
    fmt = fmt.lower()
    if fmt in ("terminal", "text", "cli"):
        out = render_terminal(scored_findings, use_color)
    elif fmt == "json":
        out = render_json(scored_findings)
    elif fmt == "sarif":
        out = render_sarif(scored_findings)
    elif fmt == "html":
        from web.html_report import render_html
        out = render_html(scored_findings, target=target, fix_enabled=fix_enabled,
                          home_url=home_url, suppressed=suppressed)
    else:
        raise ValueError(
            f"Unknown report format {fmt!r} (use terminal|json|sarif|html)"
        )

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(out)
    return out


# CI / pre-commit gate

def exit_code(scored: List[ScoredFinding], fail_on: Union[str, Severity, None]) -> int:
    """
    Process exit code for use as a CI / pre-commit gate.

    Returns 1 if any finding is at or above the `fail_on` severity, else 0.
    `fail_on` may be a Severity, a name ("low"/"medium"/"high"/"critical"),
    or "none"/None to never fail (report-only mode).
    """
    if fail_on is None:
        return 0
    if isinstance(fail_on, str):
        if fail_on.strip().lower() == "none":
            return 0
        fail_on = Severity.from_name(fail_on)   # raises ValueError on a typo
    return 1 if any(s.severity >= fail_on for s in scored) else 0
