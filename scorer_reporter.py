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

Data shapes live in models.py; the three renderers (terminal, JSON, HTML)
live in reporters.py; collapsing duplicate hits into one leak lives in
dedup.py. This file is just the scoring logic.

The scoring rubric is deliberately a small, documented point system (see
SCORING RUBRIC below) rather than a black box, because it has to be
defensible out loud in a code review.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Iterable, List, Optional, Union

from dedup import deduplicate as _dedup
from models import Severity, RawFinding, ScoredFinding, ScanContext
from reporters import render_terminal, render_json


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


def _score_one(rf: RawFinding) -> tuple[int, str, List[str]]:
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

    for rf in deduplicate(_coerce(f) for f in findings):
        placeholder = is_placeholder(rf.matched_string, ctx.extra_placeholder_patterns)
        if placeholder and not ctx.keep_placeholders:
            continue  # suppressed entirely

        points, file_class, reasons = _score_one(rf)
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
) -> str:
    """
    Render scored findings. fmt is "terminal" | "json" | "html".
    Returns the rendered string; also writes it to output_path if given.

    Terminal/json rendering lives in reporters.py, alongside the detection
    engine at the repo root. HTML rendering lives in web/html_report.py and is
    only imported here, lazily, when fmt="html" is actually requested -- so
    nothing at the root has a hard import-time dependency on the web/
    package (or on Flask, which web/app.py needs but this module doesn't).

    fix_enabled (html only) turns on the one-click fix in the report's detail
    panel, and home_url (html only) adds a link back to the scan form. Only
    web/app.py passes either -- both need a live server behind the page,
    which a report saved to disk doesn't have.
    """
    fmt = fmt.lower()
    if fmt in ("terminal", "text", "cli"):
        out = render_terminal(scored_findings, use_color)
    elif fmt == "json":
        out = render_json(scored_findings)
    elif fmt == "html":
        from web.html_report import render_html
        out = render_html(scored_findings, target=target, fix_enabled=fix_enabled,
                          home_url=home_url)
    else:
        raise ValueError(f"Unknown report format {fmt!r} (use terminal|json|html)")

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(out)
    return out


# CI / pre-commit gate

# Accepts severity names (and "none" = never fail the build).
_SEVERITY_BY_NAME = {s.name.lower(): s for s in Severity}


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
        key = fail_on.lower()
        if key == "none":
            return 0
        if key not in _SEVERITY_BY_NAME:
            raise ValueError(
                f"Unknown --fail-on value {fail_on!r} "
                f"(use none|{'|'.join(s.name.lower() for s in Severity)})"
            )
        fail_on = _SEVERITY_BY_NAME[key]
    return 1 if any(s.severity >= fail_on for s in scored) else 0


def main(argv: Optional[List[str]] = None) -> int:
    """
    CLI entrypoint. Reads a JSON list of RAW findings (the merged output of
    Persons 2+3, produced by the orchestrator), scores them, renders a
    report, and returns an exit code driven by --fail-on so this can gate a
    CI pipeline or pre-commit hook.

    Run with no findings file to execute the built-in self-check/demo.
    """
    p = argparse.ArgumentParser(
        prog="scorer_reporter",
        description="Filter, score, and report secret-scan findings.",
    )
    p.add_argument("findings", nargs="?",
                   help="JSON file of raw findings; omit to run the built-in demo")
    p.add_argument("--format", default="terminal",
                   choices=["terminal", "json", "html"], help="report format")
    p.add_argument("-o", "--output", help="write the report to this file")
    p.add_argument("--fail-on", default="none",
                   choices=["none"] + [s.name.lower() for s in Severity],
                   help="exit 1 if any finding is at/above this severity (default: none)")
    p.add_argument("--min-severity", default="low",
                   choices=[s.name.lower() for s in Severity],
                   help="drop findings below this severity from the report")
    args = p.parse_args(argv)

    if not args.findings:
        _demo()
        return 0

    try:
        with open(args.findings, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: could not read findings file: {e}", file=sys.stderr)
        return 2
    if not isinstance(raw, list):
        print("error: findings file must contain a JSON list", file=sys.stderr)
        return 2

    ctx = ScanContext(min_severity=_SEVERITY_BY_NAME[args.min_severity])
    scored = filter_and_score(raw, ctx)
    report = generate_report(scored, args.format, args.output)

    # Print to console when there's no file target, or when the format is the
    # human-readable terminal one (so CI logs still show the summary).
    if not args.output or args.format == "terminal":
        print(report)
    elif args.output:
        print(f"wrote {args.format} report to {args.output} ({len(scored)} finding(s))")

    return exit_code(scored, args.fail_on)


# Self-check  (run: py scorer_reporter.py)

def _demo() -> None:
    # Fake but realistic-shaped key. (The canonical AKIAIOSFODNN7EXAMPLE is
    # intentionally NOT used here: it contains "EXAMPLE" and would be -- correctly
    # -- suppressed by the placeholder filter.)
    live_aws = "AKIA3RJQ7KZ2NDLPWXYZ"
    raw = [
        # critical: AWS access key in a live .env file
        RawFinding("AWS_ACCESS_KEY", live_aws, ".env", 3,
                   line_content=f'aws_access_key_id={live_aws}'),
        # placeholder -> must be suppressed
        RawFinding("GENERIC_API_KEY", "YOUR_API_KEY_HERE", "config/settings.py", 10,
                   line_content='api_key = "YOUR_API_KEY_HERE"'),
        # same shape but in a test path -> downgraded
        RawFinding("AWS_ACCESS_KEY", "AKIAI44QH8DHBZZZZZZZ", "tests/test_auth.py", 7,
                   line_content='key = "AKIAI44QH8DHBZZZZZZZ"'),
        # history-only high-entropy generic
        RawFinding("HIGH_ENTROPY", "Zx9Qk2LpN8vRt5Wm3Yb7Jc1Fd6Hs4Ae0", "auth.py", 42,
                   commit_hash="a1b2c3d4e5f6", entropy_score=4.7,
                   line_content='custom_token = "Zx9Qk2LpN8vRt5Wm3Yb7Jc1Fd6Hs4Ae0"'),
    ]

    scored = filter_and_score(raw)

    # Placeholder was dropped.
    assert len(scored) == 3, f"expected 3 kept, got {len(scored)}"
    assert all("YOUR_API_KEY" not in s.redacted for s in scored)

    by_file = {s.file_path: s for s in scored}
    # Live .env AWS key is the worst.
    assert by_file[".env"].severity == Severity.CRITICAL
    # Same key type in tests/ scores strictly lower.
    assert by_file["tests/test_auth.py"].severity < by_file[".env"].severity
    # History finding is labeled, not dropped.
    assert by_file["auth.py"].exposure == "history_only"
    # Sorted worst-first.
    assert scored[0].severity >= scored[-1].severity

    # No output leaks a full secret -- check every renderer.
    for fmt in ("terminal", "json", "html"):
        text = generate_report(scored, fmt, use_color=False)
        assert live_aws not in text, f"raw secret leaked into {fmt} output"

    # Gate behavior: there IS a critical here, so --fail-on critical trips.
    assert exit_code(scored, "critical") == 1
    assert exit_code(scored, "none") == 0
    assert exit_code([], "low") == 0            # nothing found -> pass
    # Threshold above everything present -> pass (no finding reaches it).
    high_only = [s for s in scored if s.severity < Severity.CRITICAL]
    assert exit_code(high_only, "critical") == 0

    generate_report(scored, "html", output_path="report_sample.html")
    print(generate_report(scored, "terminal", use_color=True))
    print("\nself-check passed; wrote report_sample.html")


if __name__ == "__main__":
    sys.exit(main())
