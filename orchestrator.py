"""
orchestrator.py
----------------
Lance's module: CLI & Orchestration.

Wires the whole pipeline together, in order:

    walker.walk()
        -> yields (file_path, commit_hash, line_number, line_content)
    for each line:
        pattern_detector.detect(line)   -> 0+ Findings (known formats)
        entropy_detector.detect(line)   -> 0+ Findings (high-entropy blobs)
    each detector Finding is merged with the walker Finding it came from
        -> RawFinding.from_detection()
    scorer_reporter.filter_and_score(raw_findings)
        -> ScoredFinding list, placeholders dropped, severity assigned
    scorer_reporter.generate_report(scored)
        -> terminal / json / html

This file owns exactly one thing: gluing the other four people's modules
together in the right order with the right data shapes. It doesn't contain
any detection or scoring logic itself -- that all belongs upstream.

run_scan() is the single entry point both app.py (the Flask web app) and
cli.py (optional command-line entry point) call, so there's only one place
the pipeline order is ever defined.
"""

from __future__ import annotations

from typing import Iterable, List, Optional

import pattern_detector
import entropy_detector
from walker import walk, WalkerError  # noqa: F401  (re-exported for callers)
from models import RawFinding, ScanContext, ScoredFinding
from scorer_reporter import filter_and_score


def collect_raw_findings(
    target: str,
    history: bool = False,
    ignore_rules: Optional[Iterable[str]] = None,
    max_commits: Optional[int] = None,
) -> List[RawFinding]:
    """
    Run the walker over `target`, run BOTH detectors over every line it
    yields, and merge each detector hit with the walker's line metadata
    into a RawFinding.

    A single line can produce zero, one, or several RawFindings (e.g. a
    line could trip a regex pattern AND look high-entropy in a different
    span -- both get kept, scorer_reporter decides what matters).
    """
    raw_findings: List[RawFinding] = []

    for walker_finding in walk(
        target,
        ignore_rules=ignore_rules,
        history=history,
        max_commits=max_commits,
    ):
        line = walker_finding.line_content
        if not line:
            continue

        for hit in pattern_detector.detect(line):
            raw_findings.append(RawFinding.from_detection(hit, walker_finding))

        for hit in entropy_detector.detect(line):
            raw_findings.append(RawFinding.from_detection(hit, walker_finding))

    return raw_findings


def run_scan(
    target: str,
    history: bool = False,
    ignore_rules: Optional[Iterable[str]] = None,
    max_commits: Optional[int] = None,
    context: Optional[ScanContext] = None,
) -> List[ScoredFinding]:
    """
    Full pipeline in one call: walk -> detect (both detectors) -> merge ->
    filter & score. Returns ScoredFindings, worst-first, ready to hand
    straight to scorer_reporter.generate_report().

    Raises WalkerError for expected failure conditions (bad path, bad URL,
    git not installed, clone failure, etc) -- callers (Flask route / CLI)
    are expected to catch this and show a friendly message rather than a
    stack trace.
    """
    raw = collect_raw_findings(
        target,
        history=history,
        ignore_rules=ignore_rules,
        max_commits=max_commits,
    )
    return filter_and_score(raw, context)
