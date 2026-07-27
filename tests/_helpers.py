"""
tests/_helpers.py
-----------------
Shared test plumbing. Import this first from every test module -- it puts the
repo root on sys.path so `import walker` etc. work whether the suite is run as

    py -m unittest discover -s tests -v
    py -m pytest tests

from the repo root, or with the tests directory as the working directory.

Also provides TempRepo, which builds a throwaway git repo on disk. The walker
shells out to real git, so the history tests need a real repo rather than a
mock -- stubbing subprocess here would only test our own stub.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


# Pinned identity + config so commits don't depend on the machine's git setup
# (a CI runner usually has no user.name/user.email at all).
_GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "SecretSentry Tests",
    "GIT_AUTHOR_EMAIL": "tests@example.invalid",
    "GIT_COMMITTER_NAME": "SecretSentry Tests",
    "GIT_COMMITTER_EMAIL": "tests@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
}


def git_available() -> bool:
    return shutil.which("git") is not None


class TempRepo:
    """
    A throwaway directory, optionally a git repo, for walker/orchestrator tests.

    Usage:
        with TempRepo() as repo:
            repo.write(".env", 'AWS_KEY=AKIA...')
            repo.commit("add config")
            ...scan repo.path...
    """

    def __init__(self, git: bool = True):
        self.path = tempfile.mkdtemp(prefix="sentrytest_")
        self.is_git = False
        if git:
            self._git("init", "-q")
            self.is_git = True

    # context manager plumbing
    def __enter__(self) -> "TempRepo":
        return self

    def __exit__(self, *exc) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        # ignore_errors because git marks objects read-only on Windows, which
        # makes an unguarded rmtree fail on a perfectly healthy repo.
        shutil.rmtree(self.path, ignore_errors=True)

    # file helpers
    def abs(self, rel: str) -> str:
        return os.path.join(self.path, rel.replace("/", os.sep))

    def write(self, rel: str, content: str) -> str:
        target = self.abs(rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="\n") as f:
            f.write(content if content.endswith("\n") else content + "\n")
        return target

    def write_bytes(self, rel: str, data: bytes) -> str:
        target = self.abs(rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as f:
            f.write(data)
        return target

    def remove(self, rel: str) -> None:
        os.remove(self.abs(rel))

    # git helpers
    def _git(self, *args: str) -> str:
        proc = subprocess.run(
            ["git", *args],
            cwd=self.path,
            check=True,
            capture_output=True,
            text=True,
            errors="ignore",
            env=_GIT_ENV,
        )
        return proc.stdout

    def commit(self, message: str = "wip") -> str:
        """Stage everything and commit. Returns the short commit hash."""
        self._git("add", "-A")
        self._git("commit", "-q", "--allow-empty", "-m", message)
        return self._git("rev-parse", "--short=12", "HEAD").strip()
