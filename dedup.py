"""
dedup.py
--------
Collapses raw findings so that one leaked secret produces one finding.

Split out of scorer_reporter.py, which owns scoring policy; this file owns only
the question of which raw hits describe the same leak.

One leaked secret arrives from upstream as several raw findings, for two
unrelated reasons, and both have to be collapsed or the report inflates:

1. BOTH detectors fire on the same text. An AWS key matches pattern_detector's
   AKIA regex AND looks high-entropy to entropy_detector, so the same 20
   characters produce two hits on the same line at the same columns.

2. `git log -p --all` replays every commit that ever ADDED a line, so a secret
   that has sat in a file for 50 commits is re-emitted by the history walk once
   per commit that touched it -- plus once more by the working-tree walk,
   because it is still there.

Left alone, a single AWS key in a single file scanned with --history reports as
four findings, two of which claim it was "removed from the working tree" while
it is sitting in HEAD. Pass 1 fixes (1), pass 2 fixes (2).

`base_points` is injected rather than imported: deciding that AWS_ACCESS_KEY is
a more specific match than HIGH_ENTROPY is a scoring judgement, and it lives in
scorer_reporter with the rest of the rubric.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from models import RawFinding

BasePoints = Callable[[str], int]


def _norm_path(path: str) -> str:
    """Compare paths the same way regardless of which OS produced them."""
    return (path or "").replace("\\", "/")


def _same_text(a: RawFinding, b: RawFinding) -> bool:
    """
    True if two hits on the same line are pointing at the same piece of text.
    Prefers column spans; falls back to comparing the matched text when a
    detector didn't report columns.
    """
    cols = (a.start_col, a.end_col, b.start_col, b.end_col)
    if any(c is None for c in cols):
        return a.matched_string == b.matched_string
    return a.start_col < b.end_col and b.start_col < a.end_col


def _pick_representative(candidates: List[RawFinding],
                         base_points: BasePoints) -> RawFinding:
    """
    The most specific hit wins: a typed regex match (AWS_ACCESS_KEY, base 50)
    beats a generic HIGH_ENTROPY match (base 20) describing the same bytes.
    Longer match breaks a tie, on the grounds that it captured more of the
    secret.
    """
    return max(
        candidates,
        key=lambda rf: (base_points(rf.detector_type), len(rf.matched_string)),
    )


def _with_entropy_from(rep: RawFinding, members: Iterable[RawFinding]) -> RawFinding:
    """
    Carry the entropy score off a discarded duplicate onto the survivor.

    Without this, merging costs us evidence: the AKIA hit wins on base points
    but has no entropy_score, so collapsing the pair would silently drop the
    "+10 very high entropy" bonus the entropy hit was contributing.
    """
    if rep.entropy_score is not None:
        return rep
    for other in members:
        if other.entropy_score is not None:
            return replace(rep, entropy_score=other.entropy_score)
    return rep


def _collapse_overlapping_hits(findings: List[RawFinding],
                               base_points: BasePoints) -> List[RawFinding]:
    """Pass 1: merge hits from different detectors covering the same text."""
    by_line: Dict[Tuple[str, Optional[str], int], List[RawFinding]] = {}
    for rf in findings:
        key = (_norm_path(rf.file_path), rf.commit_hash, rf.line_number)
        by_line.setdefault(key, []).append(rf)

    merged: List[RawFinding] = []
    for group in by_line.values():
        # Cluster the line's hits by which ones overlap each other. A line can
        # legitimately hold two different secrets, so we can't just collapse
        # the whole line into one finding.
        clusters: List[List[RawFinding]] = []
        for rf in group:
            for cluster in clusters:
                if any(_same_text(rf, member) for member in cluster):
                    cluster.append(rf)
                    break
            else:
                clusters.append([rf])

        for cluster in clusters:
            rep = _pick_representative(cluster, base_points)
            merged.append(_with_entropy_from(rep, cluster))
    return merged


def _collapse_across_commits(findings: List[RawFinding],
                             base_points: BasePoints) -> List[RawFinding]:
    """
    Pass 2: one secret in one file is ONE finding, however many commits it
    appears in and whether or not it is also in the working tree.

    Keyed on (file, secret) rather than including the line number, because a
    secret's line number drifts as the file is edited -- the same leak sits at
    line 12 in one commit and line 40 in another.

    If any copy is in the working tree the leak is LIVE: that copy becomes the
    finding and the commits it also appears in are recorded on
    `history_commits`. That is what stops the report from claiming a secret
    currently in HEAD was "already removed", and it keeps the -5 history
    discount from being applied to a live credential.
    """
    groups: Dict[Tuple[str, str], List[RawFinding]] = {}
    for rf in findings:
        groups.setdefault((_norm_path(rf.file_path), rf.matched_string), []).append(rf)

    collapsed: List[RawFinding] = []
    for members in groups.values():
        # `git log` walks newest-first, so reversing puts the commit that
        # INTRODUCED the secret first -- the useful one to name in a report.
        commits = [rf.commit_hash for rf in members if rf.commit_hash]
        history_commits = tuple(dict.fromkeys(reversed(commits)))

        live = [rf for rf in members if rf.commit_hash is None]
        # Nothing live -> represent the leak by its oldest history hit, which
        # is the last one the newest-first walk handed us.
        rep = _pick_representative(live or [members[-1]], base_points)
        rep = _with_entropy_from(rep, members)

        collapsed.append(replace(
            rep,
            occurrences=len(members),
            history_commits=history_commits,
        ))
    return collapsed


def deduplicate(findings: Iterable[RawFinding],
                base_points: BasePoints) -> List[RawFinding]:
    """
    Collapse raw findings so that one leaked secret produces one finding.

    Returns RawFindings with `occurrences` and `history_commits` filled in.
    Order is stable: a leak keeps the position of its first raw hit.
    """
    listed = list(findings)
    return _collapse_across_commits(
        _collapse_overlapping_hits(listed, base_points), base_points
    )
