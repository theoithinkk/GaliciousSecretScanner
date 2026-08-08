from __future__ import annotations

import json
import atexit
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import namedtuple
from typing import Iterable, Iterator, List, Optional

try:
    import pathspec
    hasPathspec = True
except ImportError:
    hasPathspec = False


Finding = namedtuple("Finding", ["file_path", "commit_hash", "line_number", "line_content"])

GITHUB_URL_RE = re.compile(r"^(https?://|git@).*github\.com[/:]", re.IGNORECASE)
BINARY_SNIFF_BYTES = 8192


class WalkerError(Exception):
    """Expected failure conditions (bad path, bad URL, no git, etc)."""


# Temp clones, drained once at exit. walk() removes each one in its `finally`,
# but a caller that abandons the generator never gets there, so this is the
# backstop. One handler, not one per clone, so the list can't grow forever.
_TEMP_CLONES = set()


def _dropTempClones() -> None:
    for path in list(_TEMP_CLONES):
        shutil.rmtree(path, ignore_errors=True)
    _TEMP_CLONES.clear()


atexit.register(_dropTempClones)

def walk(
    path_or_url: str,
    ignore_rules: Optional[Iterable[str]] = None,
    history: bool = False,
    max_commits: Optional[int] = None,
    use_default_ignores: bool = True,
) -> Iterator[Finding]:
    """
    Walk path_or_url and yield a Finding for every line worth scanning. history=True also digs through 'git log -p --all'

    and yields lines that were ever added, even if they got deleted later.

    use_default_ignores=False skips config/default_ignores.json (and its
    binary/vendor/build noise) entirely -- used for a "full scan" where
    nothing should be left out. .sentryignore and any explicit ignore_rules
    still apply either way.
    """
    
    repoPath, isTempClone = resolveTarget(path_or_url)

    try:
        spec = buildIgnoreSpec(repoPath, ignore_rules, use_default_ignores=use_default_ignores)

        yield from walkWorkingTree(repoPath, spec)

        if history:
            hasGit = os.path.isdir(os.path.join(repoPath, ".git"))
            if not hasGit:
                # local folder, no git repo — nothing to walk, not an error
                return
            yield from walkHistory(repoPath, spec, max_commits)
    finally:
        if isTempClone:
            shutil.rmtree(repoPath, ignore_errors=True)
            _TEMP_CLONES.discard(repoPath)


# resolving input: local path vs github url
def resolveTarget(pathOrUrl: str) -> "tuple[str, bool]":
    # Returns (local path on disk, whether we cloned it to a temp dir)
    if looksLikeGithubUrl(pathOrUrl):
        return cloneToTemp(pathOrUrl), True

    if not os.path.exists(pathOrUrl):
        raise WalkerError(f"Path does not exist: {pathOrUrl}")
    if not os.path.isdir(pathOrUrl):
        raise WalkerError(f"Not a directory: {pathOrUrl}")
    return os.path.abspath(pathOrUrl), False


def looksLikeGithubUrl(s: str) -> bool:
    return bool(GITHUB_URL_RE.match(s.strip()))


def cloneToTemp(url: str) -> str:
    if shutil.which("git") is None:
        raise WalkerError("git isn't installed / not on PATH, can't clone a GitHub URL")

    tmpDir = tempfile.mkdtemp(prefix="secretsentry_")
    _TEMP_CLONES.add(tmpDir)

    try:
        subprocess.run(
            ["git", "clone", "--quiet", url, tmpDir],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.CalledProcessError as e:
        shutil.rmtree(tmpDir, ignore_errors=True)
        raise WalkerError(f"Failed to clone {url!r}: {e.stderr.strip() if e.stderr else e}") from e
    except subprocess.TimeoutExpired as e:
        shutil.rmtree(tmpDir, ignore_errors=True)
        raise WalkerError(f"Timed out cloning {url!r}") from e

    return tmpDir

# load ignores
def loadDefaultIgnores() -> List[str]:
    jsonPath = os.path.join(
        os.path.dirname(__file__),
        "config",
        "default_ignores.json"
    )

    try:
        with open(jsonPath, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

# .sentryignore handling
def buildIgnoreSpec(
    repoPath: str,
    extraRules: Optional[Iterable[str]],
    use_default_ignores: bool = True,
):
    patterns: List[str] = loadDefaultIgnores() if use_default_ignores else []

    sentryIgnorePath = os.path.join(repoPath, ".sentryignore")
    if os.path.isfile(sentryIgnorePath):
        with open(sentryIgnorePath, "r", encoding="utf-8", errors="ignore") as f:
            patterns.extend(
                line.rstrip("\n") for line in f
                if line.strip() and not line.strip().startswith("#")
            )

    if extraRules:
        patterns.extend(extraRules)

    if hasPathspec:
        return pathspec.PathSpec.from_lines("gitignore", patterns)

    # The fallback can't do negation (!keep-this) or ** globs, so this machine
    # scans different files than one with pathspec. Say so rather than differ
    # silently.
    print("warning: pathspec is not installed, so ignore rules are matched with "
          "a reduced matcher that cannot handle negation (!) or ** patterns -- "
          "results WILL differ from a normal install. Fix with: "
          "pip install -r requirements.txt", file=sys.stderr)
    return FnmatchFallbackSpec(patterns)


class FnmatchFallbackSpec:
    def __init__(self, patterns: List[str]):
        import fnmatch
        self.fnmatch = fnmatch
        self.patterns = [p for p in patterns if p]

    def match_file(self, relPath: str) -> bool:
        # Backslash, not os.sep. On Windows the two are the same thing, but on
        # Linux os.sep is "/" and a Windows-style path passes through
        # unnormalised, so "node_modules\pkg\index.js" dodges every directory
        # pattern in the ignore list.
        norm = relPath.replace("\\", "/")
        for pat in self.patterns:
            patNorm = pat.rstrip("/")
            if self.fnmatch.fnmatch(norm, patNorm) or self.fnmatch.fnmatch(norm, f"*/{patNorm}"):
                return True
            if pat.endswith("/") and (norm.startswith(patNorm + "/") or f"/{patNorm}/" in norm):
                return True
        return False


def isIgnored(spec, repoPath: str, absPath: str) -> bool:
    rel = os.path.relpath(absPath, repoPath)
    return spec.match_file(rel)


# binary detection
def isBinaryFile(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            chunk = f.read(BINARY_SNIFF_BYTES)
    except (OSError, IOError):
        return True  # cant read it, just skip it

    if b"\x00" in chunk:
        return True

    # if most of the file isn't printable-ish text, call it binary
    textChars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
    nonText = sum(byte not in textChars for byte in chunk)
    return bool(chunk) and (nonText / len(chunk) > 0.30)


# working tree walk
def walkWorkingTree(repoPath: str, spec) -> Iterator[Finding]:
    for root, dirNames, fileNames in os.walk(repoPath):
        # prune ignored dirs so we don't even descend into node_modules etc
        dirNames[:] = [
            d for d in dirNames
            if not isIgnored(spec, repoPath, os.path.join(root, d))
        ]

        for fname in fileNames:
            absPath = os.path.join(root, fname)
            if isIgnored(spec, repoPath, absPath):
                continue
            if isBinaryFile(absPath):
                continue

            try:
                with open(absPath, "r", encoding="utf-8", errors="ignore") as f:
                    for lineNumber, lineContent in enumerate(f, start=1):
                        yield Finding(
                            file_path=os.path.relpath(absPath, repoPath),
                            commit_hash=None,
                            line_number=lineNumber,
                            line_content=lineContent.rstrip("\n"),
                        )
            except (OSError, IOError):
                # one unreadable file shouldn't kill the whole scan
                continue


# git history walk
DIFF_HEADER_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")
COMMIT_HEADER_RE = re.compile(r"^commit ([0-9a-f]{7,40})")


def walkHistory(repoPath: str, spec, maxCommits: Optional[int]) -> Iterator[Finding]:
    cmd = ["git", "log", "-p", "--all", "--no-color", "--unified=0"]
    if maxCommits:
        cmd.extend(["-n", str(maxCommits)])

    try:
        proc = subprocess.run(
            cmd, cwd=repoPath, check=True, capture_output=True, text=True,
            errors="ignore", timeout=600,
        )
    except subprocess.CalledProcessError as e:
        raise WalkerError(f"git log failed: {e.stderr.strip() if e.stderr else e}") from e
    except subprocess.TimeoutExpired as e:
        raise WalkerError("Timed out walking git history, try a smaller --max-commits") from e

    yield from parseGitLogOutput(proc.stdout, spec)


def parseGitLogOutput(logText: str, spec) -> Iterator[Finding]:
    currentCommit: Optional[str] = None
    currentFile: Optional[str] = None
    newLineNumber = 0

    hunkHeaderRe = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

    for rawLine in logText.splitlines():
        commitMatch = COMMIT_HEADER_RE.match(rawLine)
        if commitMatch:
            currentCommit = commitMatch.group(1)[:12]
            currentFile = None
            continue

        diffMatch = DIFF_HEADER_RE.match(rawLine)
        if diffMatch:
            currentFile = diffMatch.group(2)
            continue

        if currentFile is None or currentCommit is None:
            continue

        if isIgnored(spec, "", currentFile):
            # paths from diff headers are already repo-relative, so "" as
            # the base is fine here
            continue

        hunkMatch = hunkHeaderRe.match(rawLine)
        if hunkMatch:
            newLineNumber = int(hunkMatch.group(1))
            continue

        if rawLine.startswith("+++") or rawLine.startswith("---"):
            continue

        if rawLine.startswith("+"):
            yield Finding(
                file_path=currentFile,
                commit_hash=currentCommit,
                line_number=newLineNumber,
                line_content=rawLine[1:],
            )
            newLineNumber += 1
        elif rawLine.startswith("-"):
            pass  # removed lines don't map to a line number in the new file
        else:
            newLineNumber += 1


# quick manual test, not the real CLI - for testing only
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python walker.py <path-or-url> [--history]")
        sys.exit(1)

    target = sys.argv[1]
    doHistory = "--history" in sys.argv[2:]

    count = 0
    for finding in walk(target, history=doHistory):
        count += 1
        tag = finding.commit_hash or "WORKING"
        print(f"[{tag}] {finding.file_path}:{finding.line_number}: {finding.line_content[:100]}")
    print(f"\n{count} lines yielded.")