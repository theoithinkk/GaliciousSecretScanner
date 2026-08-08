"""
fixer.py
--------
One-click remediation for a working-tree finding.

What a fix does, in this order (the order matters):

    1. Make sure .gitignore covers .env  -- FIRST, so step 3 never writes a
       plaintext secret into a file git is already tracking.
    2. Rewrite the source line so the literal becomes an environment lookup.
    3. Append the real value to .env.

What a fix does NOT do, and cannot:

    Un-leak the credential. If the secret was ever committed, pushed, or shared,
    it is compromised, and the only real remediation is to ROTATE it at the
    provider. Every result from this module carries that warning, and findings
    that are in git history carry a second one saying that editing the working
    tree leaves the blob reachable in history. A "fix" that silently drove the
    report to zero while a live key stayed valid would be worse than no fix at
    all, so nothing here is allowed to look like it finished the job.

The plaintext secret is never taken from the caller. ScoredFinding deliberately
doesn't carry it, so apply_fix() re-reads the file and re-runs the detectors to
locate the secret itself. That re-verifies rather than trusting stale state: if
the file changed since the scan, the fix refuses instead of corrupting it.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import entropy_detector
import pattern_detector


class FixError(Exception):
    """Expected, reportable failure -- shown to the user, never a traceback."""


# How to reference an env var, per language. Anything not listed here has no
# safe automatic rewrite, so the fix is refused rather than guessed at.
_ENV_REF = {
    ".py": 'os.environ["{name}"]',
    ".js": "process.env.{name}",
    ".jsx": "process.env.{name}",
    ".ts": "process.env.{name}",
    ".tsx": "process.env.{name}",
    ".mjs": "process.env.{name}",
    ".cjs": "process.env.{name}",
    ".rb": 'ENV["{name}"]',
    ".php": 'getenv("{name}")',
    ".go": 'os.Getenv("{name}")',
    ".sh": "${{{name}}}",
    ".bash": "${{{name}}}",
    ".yml": "${{{name}}}",
    ".yaml": "${{{name}}}",
    ".tf": "var.{name}",
}

# Env-style files hold secrets by design; the fix there is to stop tracking the
# file, not to rewrite its contents.
_ENV_FILE_KINDS = {"env"}

_ASSIGN_NAME_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.\-]*)\s*[:=]\s*['\"]?\s*$")


@dataclass
class FixResult:
    ok: bool
    kind: str                                  # env_var | gitignore | none
    steps: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None
    env_var: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ok": self.ok, "kind": self.kind, "steps": self.steps,
            "warnings": self.warnings, "error": self.error, "env_var": self.env_var,
        }


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

def resolve_inside(root: str, relative: str) -> str:
    """
    Resolve `relative` against `root`, refusing anything that escapes it.

    The fix endpoint writes to disk based on a path that arrived over HTTP, so
    this is the guard that keeps `../../.ssh/authorized_keys` from being a valid
    target. Symlinks are resolved before the check, not after.
    """
    root_real = os.path.realpath(root)
    # Treat a backslash as a separator on every platform. This path arrives
    # over HTTP from a client that need not be running the same OS as the
    # server, and on Linux a backslash is an ordinary filename character, so
    # "..\..\etc\passwd" would sail past this check as one odd filename
    # instead of being recognised as the traversal attempt it is.
    relative = relative.replace("\\", os.sep)
    target = os.path.realpath(os.path.join(root_real, relative))
    if target != root_real and not target.startswith(root_real + os.sep):
        raise FixError("refusing to touch a path outside the scanned directory")
    return target


# ---------------------------------------------------------------------------
# Locating the secret
# ---------------------------------------------------------------------------

def _read_lines(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore", newline="") as f:
            return f.read().splitlines(keepends=True)
    except OSError as e:
        raise FixError(f"can't read {os.path.basename(path)}: {e}") from e


def locate_secret(line: str, detector_type: str) -> Tuple[str, int, int]:
    """
    Re-run the detectors on a single line and return (secret, start, end) for
    the hit matching detector_type.

    Raises FixError when it isn't there any more, which is the signal that the
    file changed after the scan and the fix must not proceed.
    """
    hits = list(pattern_detector.detect(line)) + list(entropy_detector.detect(line))
    for hit in hits:
        if hit.type == detector_type and hit.start_col is not None:
            return hit.matched_string, hit.start_col, hit.end_col
    raise FixError(
        f"no {detector_type} found on that line any more -- "
        "the file changed since the scan, re-run it"
    )


def derive_env_name(line: str, start: int, detector_type: str) -> str:
    """
    Name the env var after the variable the secret was assigned to, falling
    back to the detector type. `stripe.api_key = "..."` -> STRIPE_API_KEY.
    """
    match = _ASSIGN_NAME_RE.search(line[:start])
    raw = match.group(1) if match else detector_type
    name = re.sub(r"[^A-Za-z0-9]+", "_", raw).strip("_").upper()
    if not name or name[0].isdigit():
        name = "SECRET_" + name if name else detector_type.upper()
    return name


# ---------------------------------------------------------------------------
# The individual edits
# ---------------------------------------------------------------------------

def _ensure_gitignore(root: str, entry: str = ".env") -> Optional[str]:
    """Add `entry` to .gitignore if absent. Returns a step description, or None."""
    path = os.path.join(root, ".gitignore")
    existing: List[str] = []
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            existing = [ln.strip() for ln in f]
        if entry in existing:
            return None

    with open(path, "a", encoding="utf-8", newline="\n") as f:
        if existing and existing[-1] != "":
            f.write("\n")
        f.write(f"# added by Galicious Scanner\n{entry}\n")
    return f"added {entry} to .gitignore"


def _append_env(root: str, name: str, value: str) -> str:
    """Append NAME=value to .env, or report that the name is already set."""
    path = os.path.join(root, ".env")
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                if ln.split("=", 1)[0].strip() == name:
                    return f"{name} already present in .env, left as-is"
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(f"{name}={value}\n")
    return f"wrote {name} to .env"


def _ensure_import_os(lines: List[str]) -> Optional[int]:
    """
    Index at which to insert `import os` in a Python file, or None if it's
    already imported.

    Skips past a shebang, an encoding declaration, and a module docstring --
    inserting above a docstring would silently demote it to a plain expression.
    """
    for ln in lines:
        if re.match(r"\s*(import\s+os\b|from\s+os\s+import\b)", ln):
            return None

    i = 0
    n = len(lines)
    if i < n and lines[i].startswith("#!"):
        i += 1
    if i < n and re.match(r"\s*#.*coding[:=]", lines[i]):
        i += 1
    while i < n and not lines[i].strip():
        i += 1
    # Module docstring: skip to the line after it closes.
    if i < n:
        stripped = lines[i].lstrip()
        for quote in ('"""', "'''"):
            if stripped.startswith(quote):
                rest = stripped[3:]
                if quote in rest:          # single-line docstring
                    return i + 1
                for j in range(i + 1, n):
                    if quote in lines[j]:
                        return j + 1
                return i + 1
    return i


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def describe(file_path: str, file_class: str, exposure: str) -> Tuple[bool, str]:
    """
    Whether a finding is automatically fixable, and why not when it isn't.
    Used by the renderer to decide if the fix button should be live.
    """
    if exposure != "working_tree":
        return False, "history-only finding, there is no working-tree file to edit"
    if file_class in _ENV_FILE_KINDS:
        return True, ""
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".pem" or ext == ".key":
        return False, "key files must be deleted and regenerated, not rewritten"
    if ext not in _ENV_REF:
        return False, f"no safe rewrite defined for {ext or 'this file type'}"
    return True, ""


def apply_fix(root: str, file_path: str, line_number: int,
              detector_type: str, in_history: bool = False) -> FixResult:
    """
    Apply the fix for one finding. Returns a FixResult either way -- callers
    render `error` rather than catching exceptions.
    """
    try:
        return _apply(root, file_path, line_number, detector_type, in_history)
    except FixError as e:
        return FixResult(ok=False, kind="none", error=str(e))
    except OSError as e:
        return FixResult(ok=False, kind="none", error=f"filesystem error: {e}")


def _apply(root: str, file_path: str, line_number: int,
           detector_type: str, in_history: bool) -> FixResult:
    if not os.path.isdir(root):
        raise FixError("the scanned directory is gone -- re-run the scan")

    abs_path = resolve_inside(root, file_path)
    if not os.path.isfile(abs_path):
        raise FixError(f"{file_path} no longer exists")

    lines = _read_lines(abs_path)
    if not 1 <= line_number <= len(lines):
        raise FixError(f"{file_path} has no line {line_number} any more")

    raw = lines[line_number - 1]
    newline = "\r\n" if raw.endswith("\r\n") else ("\n" if raw.endswith("\n") else "")
    line = raw[: len(raw) - len(newline)] if newline else raw

    secret, start, end = locate_secret(line, detector_type)

    warnings = [
        "ROTATE this credential at the provider. Editing code does not "
        "un-leak a secret that has already been exposed."
    ]
    if in_history:
        warnings.append(
            "This secret is in git history. The working tree is now clean but "
            "the blob is still reachable -- purge it with git-filter-repo."
        )

    base = os.path.basename(file_path).lower()
    ext = os.path.splitext(base)[1].lower()

    # .env files: the secret belongs there. Stop tracking the file instead.
    if base == ".env" or base.startswith(".env"):
        steps = []
        added = _ensure_gitignore(root, base)
        steps.append(added or f"{base} is already in .gitignore")
        warnings.append(
            f"If {base} was ever committed, `git rm --cached {base}` and commit "
            "that -- .gitignore alone does not untrack an existing file."
        )
        return FixResult(ok=True, kind="gitignore", steps=steps, warnings=warnings)

    template = _ENV_REF.get(ext)
    if template is None:
        raise FixError(f"no safe rewrite defined for {ext or 'this file type'}")

    env_name = derive_env_name(line, start, detector_type)
    steps: List[str] = []

    # .gitignore FIRST: never write a plaintext secret into a tracked .env.
    added = _ensure_gitignore(root, ".env")
    if added:
        steps.append(added)

    # Rewrite the source line. Only the detected span is touched, so quotes and
    # surrounding syntax outside the secret are preserved exactly.
    replacement = template.format(name=env_name)
    before, after = line[:start], line[end:]
    # Drop the quotes the literal was wrapped in -- the env lookup is an
    # expression, not a string.
    if before.endswith(("'", '"')) and after.startswith(("'", '"')):
        before, after = before[:-1], after[1:]
    lines[line_number - 1] = before + replacement + after + newline

    if ext == ".py":
        at = _ensure_import_os(lines)
        if at is not None:
            lines.insert(at, "import os\n")
            steps.append("added `import os`")

    with open(abs_path, "w", encoding="utf-8", newline="") as f:
        f.writelines(lines)
    steps.append(f"rewrote {file_path}:{line_number} to use {replacement}")

    steps.append(_append_env(root, env_name, secret))
    return FixResult(ok=True, kind="env_var", steps=steps,
                     warnings=warnings, env_var=env_name)
