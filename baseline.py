"""
baseline.py
-----------
Roadmap #4: a baseline (allowlist) of already-accepted findings.

The problem it solves: --fail-on is unusable on any repo that already has
findings. Every real codebase has some -- a test fixture with a fabricated key,
a committed .env.sample whose placeholder dodges the filter. Without a way to
say "these N are known, fail only on anything NEW", the CI gate can only ever
be turned on for a repo that is already at zero, which is almost none of them.

Fingerprint design (the part worth defending in a code review):

    sha256(file_path + detector_type + redacted)

- `redacted`, not the plaintext secret. ScoredFinding never carries the raw
  value, and a baseline file lives in the scanned repo and gets committed, so
  writing real secrets into it would be a self-inflicted leak. The masked form
  keeps a prefix plus a length, which is enough to distinguish two different
  secrets in the same file and place without disclosing either.
- NOT line_number. This is the same reasoning dedup.py uses for matching across
  commits: an unrelated edit two lines above shifts every line number below it,
  and a baseline that breaks on every edit is a baseline nobody keeps.
- file_path is normalized to forward slashes, so a baseline written on Windows
  still matches on Linux CI.

The file format mirrors .sentryignore deliberately -- newline-delimited, '#'
comments, blank lines ignored -- so there is one convention to learn, not two.
"""

from __future__ import annotations

import hashlib
import os
from typing import Iterable, List, Optional, Set, Tuple

from models import ScoredFinding

DEFAULT_BASELINE_NAME = ".sentrybaseline"

_HEADER = (
    "# Galicious Scanner baseline -- accepted findings.\n"
    "# Findings whose fingerprint is listed here are suppressed from reports\n"
    "# and ignored by --fail-on. Regenerate with: cli.py <target> --update-baseline\n"
    "# Format: <sha256>  # <file>:<line> <TYPE> <SEVERITY>\n"
)


def _norm_path(path: str) -> str:
    """Match dedup.py's normalization so both agree on what one file is."""
    return (path or "").replace("\\", "/")


def fingerprint(finding: ScoredFinding) -> str:
    """
    Stable identity for a finding, independent of its line number.

    NUL-separated so the parts can't run together: without a separator,
    ("ab", "c") and ("a", "bc") would hash identically.
    """
    material = "\0".join((
        _norm_path(finding.file_path),
        finding.detector_type,
        finding.redacted,
    ))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def default_path(target: str) -> str:
    """Where the baseline lives for a given scan target: in the scanned repo."""
    return os.path.join(target, DEFAULT_BASELINE_NAME)


def load(path: str) -> Set[str]:
    """
    Read fingerprints from a baseline file. A missing file is an empty
    baseline, not an error -- that is the normal state before the first
    --update-baseline, and failing there would make the flag hard to adopt.
    """
    fingerprints: Set[str] = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    fingerprints.add(line)
    except FileNotFoundError:
        return fingerprints
    except OSError as e:
        raise OSError(f"could not read baseline {path}: {e}") from e
    return fingerprints


def apply(
    scored: Iterable[ScoredFinding],
    fingerprints: Set[str],
) -> Tuple[List[ScoredFinding], int]:
    """
    Drop baselined findings.

    Returns (kept, suppressed_count). Suppression is total, not a downgrade:
    a baselined finding is one a human already looked at and accepted, so
    leaving it in the report at LOW would just re-create the noise the
    baseline exists to remove. The count is still reported so the suppression
    is visible rather than silent.
    """
    kept: List[ScoredFinding] = []
    suppressed = 0
    for s in scored:
        if fingerprint(s) in fingerprints:
            suppressed += 1
        else:
            kept.append(s)
    return kept, suppressed


def save(path: str, scored: Iterable[ScoredFinding]) -> int:
    """
    Write the current findings' fingerprints as the new baseline, replacing
    whatever was there.

    Replacing rather than appending is what makes a fixed finding fall out of
    the baseline instead of lingering as a dead entry forever -- the
    "--prune-baseline" behavior the roadmap asks for, achieved by not needing
    a prune step at all.

    The trailing comment on each line is for the human reading the diff; load()
    strips everything from '#' onward, so it never affects matching.
    """
    listed = list(scored)
    lines = [_HEADER]
    for s in sorted(listed, key=lambda x: (_norm_path(x.file_path), x.detector_type)):
        lines.append(
            f"{fingerprint(s)}  # {_norm_path(s.file_path)}:{s.line_number} "
            f"{s.detector_type} {s.severity.label}\n"
        )
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.writelines(lines)
    return len(listed)