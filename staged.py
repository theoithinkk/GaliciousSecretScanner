"""
staged.py
---------
Roadmap #3: scanning only what is staged for commit.

Why this exists as its own module rather than a flag on walker.walk():
walker answers "what is in this tree / what was ever in this history". This
answers a third question -- "what is about to be committed right now" -- which
is neither. Keeping it separate also keeps walker.py (Person 1's module)
untouched while reusing the diff parser it already has.

The scan surface is deliberately narrow: only lines ADDED by the staged diff.
Scanning the whole file would flag a secret that was already there before this
commit, which fails the commit for something the author didn't do and trains
them to pass --no-verify. Only the new lines are this commit's responsibility.

Reuse note: walker.parseGitLogOutput already parses exactly this diff shape
(`diff --git` headers, `@@` hunks, `+` lines). The only mismatch is that it
expects `git log` output, so it ignores everything until it has seen a
`commit <sha>` header. We prepend a synthetic one, then null the commit_hash
back out on the way through -- staged content is not in any commit yet, and
leaving a fake sha on it would make the scorer apply its "history-only,
already removed" discount to a secret that is seconds away from being live.
"""

from __future__ import annotations

import subprocess
from typing import Iterable, Iterator, List, Optional

from walker import (
    Finding,
    WalkerError,
    buildIgnoreSpec,
    parseGitLogOutput,
)

# parseGitLogOutput ignores everything before its first `commit <sha>` line.
# A staged diff has no such header, so we synthesize one; _strip_commit() below
# takes the resulting placeholder hash back off.
_SYNTHETIC_COMMIT_HEADER = "commit " + "0" * 40


def repo_root(path: str = ".") -> str:
    """
    Absolute path of the git repo containing `path`.

    A pre-commit hook is invoked with the repo root as cwd, but a developer
    running `cli.py --staged` by hand could be several directories down, and
    every git command below needs to agree on where the repo starts.
    """
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=path, check=True, capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError as e:
        raise WalkerError("git isn't installed / not on PATH") from e
    except subprocess.CalledProcessError as e:
        raise WalkerError(
            f"not inside a git repository: {e.stderr.strip() if e.stderr else path}"
        ) from e
    except subprocess.TimeoutExpired as e:
        raise WalkerError("timed out locating the git repository") from e
    return proc.stdout.strip()


def staged_diff(root: str) -> str:
    """
    The staged diff, in the same textual shape parseGitLogOutput expects.

    -U0            no context lines, so every `+` line is genuinely new
    --diff-filter=ACM  added/copied/modified only; a staged DELETION removes a
                   secret rather than introducing one, and blocking that would
                   be exactly backwards
    """
    cmd = [
        "git", "diff", "--cached", "-U0", "--no-color",
        "--diff-filter=ACM", "--no-ext-diff",
    ]
    try:
        proc = subprocess.run(
            cmd, cwd=root, check=True, capture_output=True,
            text=True, errors="ignore", timeout=300,
        )
    except subprocess.CalledProcessError as e:
        raise WalkerError(
            f"git diff --cached failed: {e.stderr.strip() if e.stderr else e}"
        ) from e
    except subprocess.TimeoutExpired as e:
        raise WalkerError("timed out reading the staged diff") from e
    return proc.stdout


def _strip_commit(findings: Iterable[Finding]) -> Iterator[Finding]:
    """
    Drop the synthetic commit hash.

    commit_hash=None is what the rest of the pipeline reads as "this is in the
    working tree", which is the correct reading for staged content: it is not
    in history, and it is about to be live.
    """
    for f in findings:
        yield Finding(
            file_path=f.file_path,
            commit_hash=None,
            line_number=f.line_number,
            line_content=f.line_content,
        )


def walk_staged(
    path: str = ".",
    ignore_rules: Optional[Iterable[str]] = None,
    use_default_ignores: bool = True,
) -> Iterator[Finding]:
    """
    Yield a Finding for every line the staged diff ADDS.

    Same output contract as walker.walk(), so the detectors and the scorer
    downstream cannot tell the difference and need no special case.
    """
    root = repo_root(path)
    spec = buildIgnoreSpec(root, ignore_rules, use_default_ignores=use_default_ignores)

    diff = staged_diff(root)
    if not diff.strip():
        return  # nothing staged -- an empty scan, not an error

    yield from _strip_commit(
        parseGitLogOutput(_SYNTHETIC_COMMIT_HEADER + "\n" + diff, spec)
    )


def staged_paths(path: str = ".") -> List[str]:
    """Staged file paths (added/copied/modified). Used for hook output only."""
    root = repo_root(path)
    try:
        proc = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            cwd=root, check=True, capture_output=True, text=True,
            errors="ignore", timeout=60,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return []
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]