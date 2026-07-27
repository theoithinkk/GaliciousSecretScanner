#!/usr/bin/env python3
"""
scripts/make_test_repo.py
-------------------------
Builds a deliberately vulnerable git repository to scan SecretSentry against,
then optionally verifies that a scan of it produces the expected results.

    py scripts/make_test_repo.py                 # build ./test-repo
    py scripts/make_test_repo.py --verify         # build it, then check the scan
    py scripts/make_test_repo.py --out /tmp/vuln  # somewhere else

EVERY SECRET IN THIS FILE IS FABRICATED. They are format-valid so the detectors
recognise them, but none authenticate against anything -- they were typed by
hand, not issued by AWS/Stripe/GitHub/etc. This is the same approach gitleaks
and trufflehog use for their own fixtures. The generated repo is written to
test-repo/, which .gitignore already excludes, and this script is listed in the
project's .sentryignore so SecretSentry doesn't flag its own test data.

What the fixture covers, and why each case is here:

  detector coverage    one planted secret per type in config/patterns.json,
                       plus a high-entropy value no regex can match
  file classes         .env / config / source / test / docs, so the scoring
                       rubric's +15/+10/+5/-20/-25 modifiers are all exercised
  exposure             live-only (never committed), live-and-committed, and
                       history-only (added then deleted)
  suppression          placeholders that must be dropped, a clean file, a
                       binary, a .sentryignore'd file, and a vendor directory
                       the default ignore list skips
  dedup                the same secret committed across several commits, which
                       is what used to inflate one leak into four findings

--verify asserts all of the above, so it doubles as an end-to-end smoke test of
the pipeline against a realistic tree rather than the synthetic repos in tests/.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


# ---------------------------------------------------------------------------
# Fabricated secrets. Format-valid, non-functional.
# ---------------------------------------------------------------------------
# Deliberately avoids the canonical vendor sample values (AKIAIOSFODNN7EXAMPLE
# and friends): those contain "EXAMPLE", so the placeholder filter would --
# correctly -- suppress them, and nothing would be detected.

AWS_KEY = "AKIA3RJQ7KZ2NDLPWXYZ"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ4hTgLm2N"
STRIPE_LIVE = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
STRIPE_LEGACY = "sk_live_9bQ72KpXmZ4tRwYn6Vc3Ld8f"      # the deleted one
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
GOOGLE_KEY = "AIzaSyD-abcdefghijklmnopqrstuvwxyz12345"
SLACK_TOKEN = "xoxb-2938471056-4827focUsGrPqTvXnLmZ"
SLACK_HOOK = ("https://hooks.slack.com/services/"
              "T02KM4Q9Z/B03JX7L2WQ/9fQ2mLp8XzT4vRb6Yk1Wc3Nd")
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiI0NzExIiwicm9sZSI6ImFkbWluIn0."
       "Kx7mQ2vZ9tLpR4wN8bYc3JdF6hSa0eUg")
DB_URL = "postgres://svc_admin:S3cretPa55w0rd@db.internal:5432/prod"
API_KEY = "8f14e45fceea167a5a36dedd4bea2543aabbccdd"
ACCESS_TOKEN = "9fQ2mLp8XzT4vRb6Yk1Wc3Nd7Hs0Ae5G"
DB_PASSWORD = "Tr0ub4dor&3xKq"
ENTROPY_BLOB = "Zx9Qk2LpN8vRt5Wm3Yb7Jc1Fd6Hs4Ae0"
ENTROPY_BLOB_2 = "kP3xM8vZ2qL9wR5tY7bN4cF1dH6sA0eU"

# Detector types GitHub's own push protection validates and blocks on, even
# for values we fabricated ourselves (see --exclude below). AWS/GitHub/Google
# are NOT in this set: GitHub checks those live against the provider and lets
# our made-up values through, since they don't authenticate against anything.
GITHUB_FLAGGED = frozenset({"STRIPE_KEY", "SLACK_TOKEN", "SLACK_WEBHOOK"})

FAKE_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C4xF2rQ8HmVdKpLnB3wYzTgEjRs6NvXcQ1a
Kb9tPmWzL4hNdY7fRxJs2ZgVuBt5CmEq0oXpAiNlUwHkD8vSjT3rGbMcFyPnZ4Xd
NOTE: truncated, non-functional, and not a real key.
-----END RSA PRIVATE KEY-----
"""


# ---------------------------------------------------------------------------
# Repository layout, expressed as the commits that build it.
# ---------------------------------------------------------------------------
# Each step is (commit message, {path: content}, [paths to delete]). Splitting
# the tree across commits is the point: it's what produces the history-only and
# live-and-committed exposure cases.

Step = Tuple[str, Dict[str, str], List[str]]

STEPS: List[Step] = [
    # ---- 1. a clean skeleton, so "before the leak" exists in history --------
    ("initial project skeleton", {
        "README.md":
            "# Payments Service\n\n"
            "Set `api_key` in your environment before running.\n"
            "Do not commit real credentials.\n",
        "requirements.txt": "flask>=3.0\nrequests>=2.31\n",
        "src/__init__.py": "",
        "src/clean.py":
            "def add(a, b):\n"
            "    return a + b\n\n\n"
            "def slugify(text):\n"
            "    return text.strip().lower().replace(' ', '-')\n",
        "docs/setup.md":
            "# Setup\n\n"
            "Copy `.env.sample` to `.env` and fill in the blanks:\n\n"
            "```\n"
            "AWS_ACCESS_KEY_ID=YOUR_API_KEY_HERE\n"
            "STRIPE_KEY=<insert-your-stripe-key>\n"
            "SLACK_TOKEN={{ slack_token }}\n"
            "DB_PASSWORD=changeme\n"
            "SESSION_SECRET=xxxxxxxxxxxx\n"
            "```\n",
    }, []),

    # ---- 2. plant a secret that will later be "cleaned up" ------------------
    ("add legacy auth module", {
        "src/legacy_auth.py":
            "# Legacy billing integration, to be replaced.\n"
            f'STRIPE_SECRET = "{STRIPE_LEGACY}"\n\n'
            "def charge(amount):\n"
            "    raise NotImplementedError\n",
    }, []),

    # ---- 3. delete it -- the classic "we removed it, we're fine" mistake ----
    # The blob stays reachable in history, so --history must still find it
    # while a working-tree-only scan must not.
    ("drop the legacy auth module", {}, ["src/legacy_auth.py"]),

    # ---- 4. the real leak: production config committed -------------------
    ("wire up production configuration", {
        ".env":
            "# Production environment. Should never have been committed.\n"
            f"AWS_ACCESS_KEY_ID={AWS_KEY}\n"
            f"DATABASE_URL={DB_URL}\n"
            # Unquoted, so no regex pattern can match it -- only the entropy
            # detector catches this one.
            f"CUSTOM_CREDENTIAL_BLOB={ENTROPY_BLOB_2}\n"
            "DEBUG=false\n",

        "config/settings.yml":
            "region: eu-west-1\n"
            f'aws_secret_access_key: "{AWS_SECRET}"\n'
            "timeout: 30\n",

        "config/ci.yml":
            "stages:\n"
            "  - deploy\n"
            f'db_password: "{DB_PASSWORD}"\n',

        "src/config.py":
            "import os\n\n"
            f'api_key = "{API_KEY}"\n'
            f'access_token = "{ACCESS_TOKEN}"\n'
            'endpoint = os.environ.get("ENDPOINT", "https://api.internal")\n',

        "src/payments.py":
            "import stripe\n\n"
            f'stripe.api_key = "{STRIPE_LIVE}"\n\n'
            "def charge(amount_cents):\n"
            "    return stripe.Charge.create(amount=amount_cents)\n",

        "src/session.py":
            "# 'AUTH' is not one of the regex library's keywords, so this is\n"
            "# reachable only through entropy analysis.\n"
            f'SESSION_AUTH_BLOB = "{ENTROPY_BLOB}"\n',

        "src/notify.py":
            f'SLACK_TOKEN = "{SLACK_TOKEN}"\n'
            f'SLACK_WEBHOOK = "{SLACK_HOOK}"\n',

        "src/auth.py":
            f'SERVICE_JWT = "{JWT}"\n'
            f'GITHUB_PAT = "{GITHUB_TOKEN}"\n',

        "src/google_client.py":
            f'MAPS_KEY = "{GOOGLE_KEY}"\n',

        "keys/deploy_key.pem": FAKE_PEM,

        # Same key as .env, in a test path: must be found but scored lower.
        "tests/test_auth.py":
            "import unittest\n\n\n"
            "class TestAuth(unittest.TestCase):\n"
            "    def test_signing(self):\n"
            f'        key = "{AWS_KEY}"\n'
            "        self.assertTrue(key)\n",

        # Same key again, in docs: the biggest discount in the rubric. Doubles
        # as the repo's own README, since this fixture is meant to be publishable
        # as a standalone target (see --into).
        "README.md":
            "# Payments Service (deliberately vulnerable fixture)\n\n"
            "This repository is a **test target for the SecretSentry secret "
            "scanner**. It is not a real service.\n\n"
            "> Every credential in this repository is **fabricated and "
            "non-functional**. The values are format-valid so that scanners "
            "recognise them, but none of them authenticate against anything. "
            "Do not report them as leaked credentials.\n\n"
            "## What is planted here\n\n"
            "- One secret per detector type: AWS, Stripe, GitHub, Google, "
            "Slack, JWT, Postgres URL, PEM private key, generic api_key / "
            "token / password\n"
            "- A high-entropy value no regex matches, for the entropy detector\n"
            "- The same key in `.env`, `tests/` and this README, so file-class "
            "scoring can be compared\n"
            "- A secret committed then deleted (`src/legacy_auth.py`), "
            "reachable only via `git log`\n"
            "- An uncommitted `.env.local`, live but never committed\n"
            "- Decoys that must NOT be reported: placeholders in `docs/`, a "
            "binary, a `.sentryignore`d file, and `node_modules/`\n\n"
            "## Scanning it\n\n"
            "```\n"
            "python cli.py https://github.com/theoithinkk/VulnRepo --history\n"
            "```\n\n"
            "## Example of what gets flagged\n\n"
            "```\n"
            f"AWS_ACCESS_KEY_ID={AWS_KEY}\n"
            "```\n\n"
            "Regenerate with `scripts/make_test_repo.py` in the scanner repo.\n",

        # Skipped by config/default_ignores.json on a quick scan; a full scan
        # must find it.
        "node_modules/leaky-pkg/index.js":
            f'module.exports = {{ stripe: "{STRIPE_LIVE}" }};\n',

        # Skipped because of .sentryignore, in both scan modes.
        ".sentryignore":
            "# Known-bad archive, already rotated -- don't report it again.\n"
            "vendor/legacy_dump.txt\n",
        "vendor/legacy_dump.txt":
            f"old_aws_key={AWS_KEY}\nold_stripe={STRIPE_LIVE}\n",
    }, []),
]


def _sanitized_steps(exclude: frozenset) -> List[Step]:
    """
    A copy of STEPS with GITHUB_FLAGGED detector types stripped out before
    anything is ever written to disk or committed.

    This can't be done as a post-hoc cleanup commit: GitHub's push protection
    scans every commit being pushed, not just the tip, so a value that was
    ever committed still blocks the push even if a later commit deletes it.
    The values have to never exist in a commit in the first place.

    STEPS itself is untouched -- callers that want the full 14-type fixture
    (the local test-repo/, the test suite) keep using it directly.
    """
    if not exclude:
        return STEPS

    import copy
    steps = copy.deepcopy(STEPS)

    if "STRIPE_KEY" in exclude:
        # Step 1: the secret that gets committed then deleted. Keep the
        # commit (so history shape / commit count stay stable) but drop the
        # secret from it.
        msg, files, deletions = steps[1]
        files["src/legacy_auth.py"] = (
            "# Legacy billing integration, to be replaced.\n"
            "# (The original credential here has been rotated and this\n"
            "# public fixture no longer carries it.)\n\n"
            "def charge(amount):\n"
            "    raise NotImplementedError\n"
        )

        # Step 3: the main leak commit.
        msg, files, deletions = steps[3]
        files["src/payments.py"] = (
            "import os\nimport stripe\n\n"
            'stripe.api_key = os.environ["STRIPE_SECRET_KEY"]\n\n'
            "def charge(amount_cents):\n"
            "    return stripe.Charge.create(amount=amount_cents)\n"
        )
        files.pop("node_modules/leaky-pkg/index.js", None)
        files["vendor/legacy_dump.txt"] = f"old_aws_key={AWS_KEY}\n"

    if "SLACK_TOKEN" in exclude or "SLACK_WEBHOOK" in exclude:
        _, files, _ = steps[3]
        files.pop("src/notify.py", None)

    return steps

# Written after the final commit, so it is in the working tree but has never
# been committed -- the "live only, not in history" exposure case.
UNCOMMITTED: Dict[str, str] = {
    ".env.local":
        "# Local overrides, never committed.\n"
        f"GITHUB_TOKEN={GITHUB_TOKEN}\n",
}

# A binary file: the walker must skip it even though it contains a secret.
BINARY_FILES: Dict[str, bytes] = {
    "assets/logo.bin": (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        + AWS_KEY.encode()
        + b"\x00\x01\x02\x03\xff\xfe\xfd"
    ),
}


# ---------------------------------------------------------------------------
# Expectations, checked by --verify
# ---------------------------------------------------------------------------

# (path, detector_type, exposure) that a `--history` scan must report.
EXPECT_FOUND: List[Tuple[str, str, str]] = [
    (".env", "AWS_ACCESS_KEY", "working_tree"),
    (".env", "DB_CONNECTION_STRING", "working_tree"),
    (".env", "HIGH_ENTROPY", "working_tree"),
    (".env.local", "GITHUB_TOKEN", "working_tree"),
    ("config/settings.yml", "AWS_SECRET_KEY", "working_tree"),
    ("config/ci.yml", "GENERIC_PASSWORD", "working_tree"),
    ("src/config.py", "GENERIC_API_KEY", "working_tree"),
    ("src/config.py", "GENERIC_SECRET", "working_tree"),
    ("src/payments.py", "STRIPE_KEY", "working_tree"),
    ("src/session.py", "HIGH_ENTROPY", "working_tree"),
    ("src/notify.py", "SLACK_TOKEN", "working_tree"),
    ("src/notify.py", "SLACK_WEBHOOK", "working_tree"),
    ("src/auth.py", "JWT", "working_tree"),
    ("src/auth.py", "GITHUB_TOKEN", "working_tree"),
    ("src/google_client.py", "GOOGLE_API_KEY", "working_tree"),
    ("keys/deploy_key.pem", "PRIVATE_KEY_HEADER", "working_tree"),
    ("tests/test_auth.py", "AWS_ACCESS_KEY", "working_tree"),
    ("README.md", "AWS_ACCESS_KEY", "working_tree"),
    # Deleted in step 3, so reachable only through git history.
    ("src/legacy_auth.py", "STRIPE_KEY", "history_only"),
]

# Paths that must produce NO findings at all on a default (quick) scan.
EXPECT_SILENT: List[Tuple[str, str]] = [
    ("src/clean.py", "no secrets in it"),
    ("docs/setup.md", "placeholders only -- must be suppressed"),
    ("assets/logo.bin", "binary -- must be skipped"),
    ("vendor/legacy_dump.txt", "excluded by .sentryignore"),
    ("node_modules/leaky-pkg/index.js", "excluded by the default ignore list"),
    ("requirements.txt", "no secrets in it"),
]

# Secrets that must never appear verbatim in any rendered report.
MUST_NOT_LEAK = [
    AWS_KEY, AWS_SECRET, STRIPE_LIVE, STRIPE_LEGACY, GITHUB_TOKEN,
    GOOGLE_KEY, SLACK_TOKEN, JWT, API_KEY, ACCESS_TOKEN,
    ENTROPY_BLOB, ENTROPY_BLOB_2,
]


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------

_GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "Test Fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "Test Fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
}


def _git(cwd: str, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True,
        text=True, errors="ignore", env=_GIT_ENV,
    )
    return proc.stdout


def _write(root: str, rel: str, content: str) -> None:
    path = os.path.join(root, rel.replace("/", os.sep))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)


def build(out_dir: str, force: bool = False, into_existing: bool = False,
          exclude: frozenset = frozenset()) -> str:
    """
    Build the fixture at out_dir.

    into_existing=True layers the fixture commits on top of a git repo that is
    already there (e.g. a clone of a repo you want to publish the fixture to)
    instead of starting from scratch. Nothing is deleted -- the existing history
    is preserved underneath.

    exclude drops detector types out of every commit before it's made, not just
    out of the final tree -- see _sanitized_steps(). Use this when publishing to
    a host whose own secret scanner blocks the push (GITHUB_FLAGGED covers the
    types GitHub's push protection validates and rejects even for fabricated
    values, e.g. `--exclude STRIPE_KEY,SLACK_TOKEN,SLACK_WEBHOOK`).
    """
    if shutil.which("git") is None:
        raise SystemExit("error: git is not on PATH, can't build the history cases")

    if into_existing:
        if not os.path.isdir(os.path.join(out_dir, ".git")):
            raise SystemExit(f"error: {out_dir} is not a git repository")
    else:
        if os.path.exists(out_dir):
            if not force:
                raise SystemExit(
                    f"error: {out_dir} already exists (pass --force to replace it)"
                )
            shutil.rmtree(out_dir, ignore_errors=True)
        os.makedirs(out_dir)
        _git(out_dir, "init", "-q")

    steps = _sanitized_steps(exclude)
    for index, (message, files, deletions) in enumerate(steps):
        for rel, content in files.items():
            _write(out_dir, rel, content)
        for rel in deletions:
            target = os.path.join(out_dir, rel.replace("/", os.sep))
            if os.path.exists(target):
                os.remove(target)

        if index == len(steps) - 1:
            # Binaries go INTO the final commit, not after it, so that cloning
            # this fixture from a remote still exercises the binary-skip path.
            for rel, data in BINARY_FILES.items():
                path = os.path.join(out_dir, rel.replace("/", os.sep))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as f:
                    f.write(data)

        _git(out_dir, "add", "-A")
        _git(out_dir, "commit", "-q", "--allow-empty", "-m", message)

    # Written last, deliberately never committed: the "live but not in history"
    # case. This one cannot survive a clone -- see the note in the README.
    for rel, content in UNCOMMITTED.items():
        _write(out_dir, rel, content)

    return out_dir


# ---------------------------------------------------------------------------
# Verifying
# ---------------------------------------------------------------------------

class _Results:
    def __init__(self) -> None:
        self.checks: List[Tuple[bool, str]] = []

    def check(self, ok: bool, label: str) -> None:
        self.checks.append((bool(ok), label))

    @property
    def failed(self) -> List[str]:
        return [label for ok, label in self.checks if not ok]

    def report(self) -> int:
        for ok, label in self.checks:
            print(f"  {'PASS' if ok else 'FAIL'}  {label}")
        print(f"\n{len(self.checks) - len(self.failed)}/{len(self.checks)} checks passed")
        return 1 if self.failed else 0


def verify(out_dir: str, exclude: frozenset = frozenset()) -> int:
    from orchestrator import run_scan
    from scorer_reporter import generate_report

    print(f"\nscanning {out_dir} with --history ...\n")
    scored = run_scan(out_dir, history=True)
    quick = run_scan(out_dir)
    full = run_scan(out_dir, full_scan=True)

    def norm(path: str) -> str:
        return path.replace("\\", "/")

    found = {(norm(s.file_path), s.detector_type) for s in scored}
    by_path: Dict[str, list] = {}
    for s in scored:
        by_path.setdefault(norm(s.file_path), []).append(s)

    r = _Results()

    # 1. every planted secret is detected, with the right exposure
    for path, detector, exposure in EXPECT_FOUND:
        if detector in exclude:
            continue    # intentionally not planted in this build -- see --exclude
        hit = [s for s in by_path.get(path, []) if s.detector_type == detector]
        r.check(bool(hit), f"detected {detector} in {path}")
        if hit:
            actual = {s.exposure for s in hit}
            r.check(exposure in actual,
                    f"{path} {detector} exposure is {exposure} (got {sorted(actual)})")

    # 2. nothing is reported where nothing should be
    quick_paths = {norm(s.file_path) for s in quick}
    for path, why in EXPECT_SILENT:
        r.check(path not in quick_paths, f"silent: {path} ({why})")

    # 3. the file-class modifiers actually reorder the same key
    def points_for(path: str) -> Optional[int]:
        hits = [s for s in by_path.get(path, []) if s.detector_type == "AWS_ACCESS_KEY"]
        return max((s.points for s in hits), default=None)

    env_pts, test_pts, doc_pts = (points_for(".env"), points_for("tests/test_auth.py"),
                                  points_for("README.md"))
    if None not in (env_pts, test_pts, doc_pts):
        r.check(env_pts > test_pts, f".env AWS key outscores tests/ ({env_pts} > {test_pts})")
        r.check(env_pts > doc_pts, f".env AWS key outscores README ({env_pts} > {doc_pts})")

    # 4. dedup: the same secret in the same file appears exactly once
    seen: Dict[Tuple[str, str], int] = {}
    for s in scored:
        key = (norm(s.file_path), s.redacted)
        seen[key] = seen.get(key, 0) + 1
    dupes = {k: n for k, n in seen.items() if n > 1}
    r.check(not dupes, f"no duplicate findings (offenders: {dupes or 'none'})")

    # 5. a live secret that is also committed is labelled as both
    env_aws = [s for s in by_path.get(".env", []) if s.detector_type == "AWS_ACCESS_KEY"]
    if env_aws:
        r.check(env_aws[0].in_history,
                ".env AWS key is flagged as committed to history as well as live")
    local = by_path.get(".env.local", [])
    if local:
        r.check(not local[0].in_history,
                ".env.local was never committed, so carries no history commits")

    # 6. full scan reaches what the quick scan skips
    full_paths = {norm(s.file_path) for s in full}
    if "STRIPE_KEY" not in exclude:
        r.check("node_modules/leaky-pkg/index.js" in full_paths,
                "full scan finds the secret in node_modules/")
    r.check("vendor/legacy_dump.txt" not in full_paths,
            ".sentryignore is honoured even during a full scan")

    # 7. no renderer leaks a plaintext secret
    for fmt in ("terminal", "json", "html"):
        rendered = generate_report(scored, fmt, use_color=False)
        leaked = [s for s in MUST_NOT_LEAK if s in rendered]
        r.check(not leaked, f"{fmt} report leaks nothing (leaked: {leaked or 'none'})")

    print(f"findings: {len(scored)} with history, {len(quick)} quick, {len(full)} full\n")
    return r.report()


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="make_test_repo",
        description="Build a deliberately vulnerable repo to scan SecretSentry against.",
    )
    p.add_argument("--out", default=os.path.join(REPO_ROOT, "test-repo"),
                   help="where to build it (default: ./test-repo, already gitignored)")
    p.add_argument("--into", metavar="EXISTING_REPO",
                   help="layer the fixture commits onto an existing git repo "
                        "(e.g. a clone you intend to push), preserving its history")
    p.add_argument("--force", action="store_true",
                   help="replace the directory if it already exists")
    p.add_argument("--verify", action="store_true",
                   help="scan the fixture afterwards and check the expectations")
    p.add_argument("--exclude", metavar="TYPE,TYPE,...",
                   help="detector types to leave out of every commit (not just the "
                        "final tree), for hosts whose own scanner blocks these "
                        "fabricated values on push. --exclude github lets GitHub's "
                        "push protection reject: %s" % ",".join(sorted(GITHUB_FLAGGED)))
    args = p.parse_args(argv)

    if args.exclude in (None, ""):
        exclude = frozenset()
    elif args.exclude.strip().lower() == "github":
        exclude = GITHUB_FLAGGED
    else:
        exclude = frozenset(t.strip().upper() for t in args.exclude.split(","))

    out_dir = os.path.abspath(args.into or args.out)
    build(out_dir, force=args.force, into_existing=bool(args.into), exclude=exclude)

    steps = _sanitized_steps(exclude)
    committed = sum(len(files) for _, files, _ in steps)
    print(f"built {out_dir}")
    print(f"  {len(steps)} commits, ~{committed} file writes, "
          f"{len(UNCOMMITTED)} uncommitted, {len(BINARY_FILES)} binary")
    if exclude:
        print(f"  excluded from every commit: {', '.join(sorted(exclude))}")
    print(f"\n  py cli.py {out_dir} --history")
    print(f"  py cli.py {out_dir} --history --format html -o report.html")
    print(f"  py cli.py {out_dir} --fail-on high      # CI gate behaviour")

    if args.verify:
        return verify(out_dir, exclude=exclude)
    return 0


if __name__ == "__main__":
    sys.exit(main())
