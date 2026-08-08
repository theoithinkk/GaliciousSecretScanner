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
    python cli.py <path-or-url> [--history] [--format terminal|json|sarif|html]
                  [-o OUTPUT] [--fail-on none|low|medium|high|critical]
                  [--verify-live]
"""

from __future__ import annotations

import sys
from typing import List, Optional

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
    p.add_argument("target", help="local folder path or GitHub URL")
    p.add_argument(
        "--history", action="store_true",
        help="also scan git history for secrets that were added then removed",
    )
    p.add_argument(
        "--format", default="terminal",
        choices=["terminal", "json", "sarif", "html"],
        help="report format (default: terminal). sarif uploads to GitHub Code Scanning",
    )
    p.add_argument(
        "--verify-live", action="store_true",
        help="ask the provider whether each AWS/GitHub/Stripe/Slack secret still "
             "works. This sends the candidate secret to that provider over the "
             "network, so it stays off unless you ask for it",
    )
    p.add_argument("-o", "--output", help="write the report to this file")
    p.add_argument(
        "--ignore-file",
        help="extra .sentryignore-style file (gitignore syntax), merged with defaults",
    )
    p.add_argument(
        "--max-commits", type=int, default=None,
        help="cap how many commits --history walks (useful for big repos / demo speed)",
    )
    p.add_argument(
        "--fail-on", default="none",
        choices=["none"] + [s.name.lower() for s in Severity],
        help="exit 1 if any finding is at/above this severity (default: none, never fails)",
    )
    p.add_argument(
        "--min-severity", default="low",
        choices=[s.name.lower() for s in Severity],
        help="drop findings below this severity from the report (default: low)",
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


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        ignore_rules = _load_ignore_rules(args.ignore_file)
    except OSError as e:
        print(f"error: could not read --ignore-file: {e}", file=sys.stderr)
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
        )
    except WalkerError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    report = generate_report(scored, args.format, args.output)

    if not args.output or args.format == "terminal":
        print(report)
    else:
        print(f"wrote {args.format} report to {args.output} ({len(scored)} finding(s))")

    return exit_code(scored, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
