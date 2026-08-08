"""
models.py
shared data shapes. kept on their own so scorer_reporter.py (logic) and
reporters.py (rendering) can both import these without importing each other.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Iterable, List, Optional


# Data shapes
class Severity(IntEnum):
    """Ordered so findings sort high-to-low with plain int comparison."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass
class RawFinding:
    """
    One merged finding as it arrives from upstream: a detector hit
    (Person 2/3) already joined to the line it came from (Person 1).

    The orchestration step builds these; `from_detection` is the helper it
    uses so nobody has to remember the field order.
    """
    detector_type: str # "AWS_ACCESS_KEY", "HIGH_ENTROPY", ...
    matched_string: str # the raw secret text (always redacted)
    file_path: str
    line_number: int
    commit_hash: Optional[str] = None # if none, then found in the working tree
    line_content: str = ""
    entropy_score: Optional[float] = None
    start_col: Optional[int] = None
    end_col: Optional[int] = None

    # Filled in by scorer_reporter.deduplicate(), NOT by the detectors or the
    # walker. Upstream always leaves these at their defaults; the dedup step
    # rewrites them when it collapses several raw hits into one leak.
    occurrences: int = 1                      # how many raw hits merged into this
    history_commits: tuple = ()               # every commit this secret was seen in, oldest first

    @classmethod
    def from_detection(cls, detector_finding, walker_finding) -> "RawFinding":
        """
        Merge a Person 2/3 Finding with the Person 1 Finding for the same
        line. Works with either detector's namedtuple (entropy_score is
        pulled if present, otherwise left None).
        """
        return cls(
            detector_type=detector_finding.type,
            matched_string=detector_finding.matched_string,
            file_path=walker_finding.file_path,
            line_number=walker_finding.line_number,
            commit_hash=walker_finding.commit_hash,
            line_content=walker_finding.line_content,
            entropy_score=getattr(detector_finding, "entropy_score", None),
            start_col=getattr(detector_finding, "start_col", None),
            end_col=getattr(detector_finding, "end_col", None),
        )


@dataclass
class ScoredFinding:
    """
    A raw finding after filtering + scoring. Note what is NOT here: the
    plaintext secret. Once scored we keep only the redacted forms, so a
    ScoredFinding is safe to serialize, log, or hand to a template.
    """
    detector_type: str
    file_path: str
    line_number: int
    severity: Severity
    points: int
    exposure: str # "working_tree" (live now) or "history_only" (leaked, removed)
    commit_hash: Optional[str]
    redacted: str # masked secret, like "AKIA****************"
    redacted_context: str # the source line with the secret masked out
    rationale: str
    entropy_score: Optional[float] = None
    file_class: str = "other"     # env | config | source | test | docs | other

    # What the provider said when asked whether this credential still works.
    # True = accepted, False = rejected, None = never checked, or checked and
    # the answer didn't arrive. None and False are different answers and must
    # not be collapsed when rendering. See live_check.py.
    verified: Optional[bool] = None

    # What to actually do about this finding, filled in by
    # remediation.annotate(). Declared here rather than attached as a loose
    # attribute so it always exists (renderers can test it without guarding)
    # and so asdict() carries it into the JSON and SARIF reports.
    remediation_steps: List[str] = field(default_factory=list)

    # Dedup bookkeeping, so a reader can tell "one leak seen 40 times" apart
    # from "40 separate leaks".
    occurrences: int = 1
    history_commits: tuple = ()

    @property
    def in_history(self) -> bool:
        """
        True if this secret exists in git history -- including when it is ALSO
        still in the working tree. `exposure == "history_only"` answers a
        narrower question (is it *only* in history), so remediation advice
        should key off this instead: a live secret that is also committed
        needs the history purged too, not just the file edited.
        """
        return bool(self.history_commits)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["history_commits"] = list(self.history_commits)
        return d


@dataclass
class ScanContext:
    """
    Optional scan-wide knobs (the second arg of the locked contract).
    Everything has a sane default, so callers can pass nothing.
    """
    keep_placeholders: bool = False           # if True, don't drop placeholders, just downgrade
    min_severity: Severity = Severity.LOW      # drop anything below this from the output
    extra_placeholder_patterns: Iterable[str] = field(default_factory=tuple)

    # Off by default and it has to stay that way: turning this on sends every
    # candidate secret to the provider it belongs to, over the network.
    verify_live: bool = False
