"""
cli.py
------
Lance's module: CLI & Orchestration (command-line entry point).

The group pivoted to a Flask web app (web/app.py) as the primary interface, but
this CLI is kept alongside it -- same run_scan() pipeline underneath, so
it's useful for scripting/CI use and as a fallback if the web demo has
issues on presentation day. Nothing here duplicates orchestration logic;
it's a thin argparse wrapper around orchestrator.run_scan().

Usage:
    python cli.py <path-or-url> [--history | --staged] [--full-scan]
                  [--format terminal|json|sarif|html] [-o OUTPUT]
                  [--baseline [PATH]] [--update-baseline [PATH]]
                  [--fail-on none|low|medium|high|critical] [--verify-live]

Pre-commit use:
    python cli.py --staged --baseline --fail-on high
"""

from __future__ import annotations

import os
import sys
from typing import List, Optional

import baseline
from orchestrator import run_scan
from walker import WalkerError
from scorer_reporter import generate_report, exit_code
from models import ScanContext, Severity

import argparse

_SEVERITY_BY_NAME = {s.name.lower(): s for s in Severity}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentry",
        description="SecretSentry -- scan a local folder or GitHub repo for exposed secrets.",
    )
    p.add_argument(
        "target", nargs="?", default=".",
        help="local folder path or GitHub URL (default: current directory)",
    )

    # What to scan
    p.add_argument(
        "--history", action="store_true",
        help="also scan git history for secrets that were added then removed",
    )
    p.add_argument(
        "--staged", action="store_true",
        help="scan only the lines staged for commit (for a pre-commit hook)",
    )
    p.add_argument(
        "--full-scan", action="store_true",
        help="skip the default ignore list (binaries, node_modules, ...) and scan everything",
    )
    p.add_argument(
        "--max-commits", type=int, default=None,
        help="cap how many commits --history walks (useful for big repos / demo speed)",
    )
    p.add_argument(
        "--ignore-file",
        help="extra .sentryignore-style file (gitignore syntax), merged with defaults",
    )

    # How hard to look
    p.add_argument(
        "--verify-live", action="store_true",
        help="ask the provider whether each AWS/GitHub/Stripe/Slack secret still "
             "works. This sends the candidate secret to that provider over the "
             "network, so it stays off unless you ask for it",
    )

    # What to suppress
    p.add_argument(
        "--baseline", nargs="?", const=baseline.DEFAULT_BASELINE_NAME, default=None,
        metavar="PATH",
        help="suppress findings listed in this baseline file "
             f"(default: {baseline.DEFAULT_BASELINE_NAME} in the target)",
    )
    p.add_argument(
        "--update-baseline", nargs="?", const=baseline.DEFAULT_BASELINE_NAME,
        default=None, metavar="PATH",
        help="write the current findings to a baseline file and exit 0 "
             "(accept everything found today)",
    )
    p.add_argument(
        "--min-severity", default="low",
        choices=[s.name.lower() for s in Severity],
        help="drop findings below this severity from the report (default: low)",
    )

    # What to emit
    p.add_argument(
        "--format", default="terminal",
        choices=["terminal", "json", "sarif", "html"],
        help="report format (default: terminal). sarif uploads to GitHub Code Scanning",
    )
    p.add_argument("-o", "--output", help="write the report to this file")
    p.add_argument(
        "--fail-on", default="none",
        choices=["none"] + [s.name.lower() for s in Severity],
        help="exit 1 if any finding is at/above this severity (default: none, never fails)",
    )
    return p


def _load_ignore_rules(path: Optional[str]) -> Optional[List[str]]:
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as f:
        return [
            line.rstrip("\n") for line in f
            if line.strip() and not line.strip().startswith("#")
        ]


def _baseline_path(given: str, target: str) -> str:
    """
    Resolve a baseline path.

    A bare --baseline (no value) means "the default name, inside the scanned
    target", since that is where the file belongs -- it describes that repo,
    travels with it, and gets committed alongside it. An explicit path is used
    as given, so CI can keep one somewhere else.
    """
    if given != baseline.DEFAULT_BASELINE_NAME:
        return given
    if os.path.isdir(target):
        return baseline.default_path(target)
    return given


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        ignore_rules = _load_ignore_rules(args.ignore_file)
    except OSError as e:
        print(f"error: could not read --ignore-file: {e}", file=sys.stderr)
        return 2

    if args.staged and args.history:
        print("error: --staged and --history are mutually exclusive "
              "(staged content isn't committed yet)", file=sys.stderr)
        return 2

    ctx = ScanContext(
        min_severity=_SEVERITY_BY_NAME[args.min_severity],
        verify_live=args.verify_live,
    )

    try:
        scored = run_scan(
            args.target,
            history=args.history,
            ignore_rules=ignore_rules,
            max_commits=args.max_commits,
            context=ctx,
            full_scan=args.full_scan,
            staged=args.staged,
        )
    except WalkerError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    # --update-baseline accepts everything found right now, then exits clean.
    # It deliberately never renders a report or consults --fail-on: the whole
    # point of the run is to record the current state, not to judge it.
    if args.update_baseline is not None:
        path = _baseline_path(args.update_baseline, args.target)
        try:
            count = baseline.save(path, scored)
        except OSError as e:
            print(f"error: could not write baseline: {e}", file=sys.stderr)
            return 2
        print(f"wrote {count} fingerprint(s) to {path}")
        return 0

    suppressed = 0
    if args.baseline is not None:
        path = _baseline_path(args.baseline, args.target)
        try:
            known = baseline.load(path)
        except OSError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        scored, suppressed = baseline.apply(scored, known)

    report = generate_report(scored, args.format, args.output)

    if not args.output or args.format == "terminal":
        print(report)
    else:
        print(f"wrote {args.format} report to {args.output} ({len(scored)} finding(s))")

    # Printed after the report so it can't be mistaken for part of it, but
    # always printed when non-zero -- a suppressed finding that vanishes with
    # no trace is how a baseline quietly hides a real regression.
    if suppressed:
        print(f"\n({suppressed} finding(s) suppressed by baseline)")

    return exit_code(scored, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())