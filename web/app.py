"""
web/app.py
----------
Flask front end. Kept intentionally thin -- all it does is take the form
submission, hand it to orchestrator.run_scan() (the exact same pipeline
cli.py uses), and render the result.

On a successful scan we return the full themed HTML report straight from
scorer_reporter/web.html_report (the matrix-style page with severity tiles,
sort, filter) instead of the old plain table, since that report is already a
complete standalone page. On error, we fall back to the form page with an
error message.

Every scan knob the CLI exposes and a browser can sensibly drive is on the
form: scan mode, git history (with a commit cap), live verification, minimum
severity, and baseline suppression. The two the CLI keeps to itself are
--staged (a pre-commit concern, and there is no commit in progress here) and
--fail-on (a process exit code, which a web page has no use for).

This file lives under web/ rather than the repo root, so the root directory
shows only the detection/scoring engine (walker, pattern_detector,
entropy_detector, scorer_reporter, ...) plus the CLI that drives it directly.
Because of that, the imports below need the repo root on sys.path before they
run -- see the block right after this docstring.
"""

from __future__ import annotations

import os
import sys
import traceback

# Repo root (parent of this file's directory), so `import orchestrator` etc.
# resolve regardless of whether this is launched as `py web/app.py` or
# `py -m web.app`. Must run before any of the imports below.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from flask import Flask, jsonify, render_template, request, Response

import baseline
from orchestrator import run_scan
from walker import WalkerError, looksLikeGithubUrl
from models import ScanContext, Severity
from scorer_reporter import generate_report
from web import fixer
from web.report_assets import BASE_CSS, BASE_JS

app = Flask(__name__)

# The most recent scan, so the exports and the accept-all button have something
# to act on without re-walking the tree. Redacted findings only, never a
# plaintext secret. One slot is enough because the tool runs locally for one
# person against one repo; sharing it would mean keying this by session.
_LAST_SCAN = {"scored": [], "target": "", "suppressed": 0}

# Ceiling for /api/browse. Without one the endpoint lists any directory on the
# machine. Home covers where repos live; GALICIOUS_BROWSE_ROOT widens it.
_BROWSE_ROOT = os.path.realpath(
    os.environ.get("GALICIOUS_BROWSE_ROOT") or os.path.expanduser("~"))

_DOWNLOAD_TYPES = {
    "json": "application/json",
    "sarif": "application/json",
    "html": "text/html",
}


def _form_page(error=None):
    """The scan form. Shares its chrome with the report page (report_assets)."""
    return render_template("index.html", error=error,
                           base_css=BASE_CSS, base_js=BASE_JS)


def _max_commits(raw):
    """
    Parse the history commit cap. Blank means no cap.

    A cap matters more here than on the CLI: a --history walk of a large repo
    can run for minutes behind a spinner with no way to interrupt it, and the
    walker already accepts the limit -- it just had no way in from the browser.
    """
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"Commit limit must be a whole number, got {raw!r}.")
    if value < 1:
        raise ValueError("Commit limit must be 1 or more.")
    return value


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method != "POST":
        return _form_page()

    target = (request.form.get("target") or "").strip()
    history = "history" in request.form
    full_scan = request.form.get("scan_mode") == "full"
    use_baseline = "use_baseline" in request.form
    # Unticked by default, and it needs to stay that way -- this is the one
    # option that puts candidate secrets on the network. See live_check.py.
    verify_live = "verify_live" in request.form

    if not target:
        return _form_page("Please enter a repository path or GitHub URL.")

    try:
        min_severity = Severity.from_name(request.form.get("min_severity") or "low")
        max_commits = _max_commits(request.form.get("max_commits"))
    except ValueError as e:
        return _form_page(str(e))

    try:
        scored = run_scan(
            target,
            history=history,
            max_commits=max_commits,
            full_scan=full_scan,
            context=ScanContext(verify_live=verify_live, min_severity=min_severity),
        )
    except WalkerError as e:
        # Expected failure conditions from the walker (bad path, bad URL,
        # git missing, clone failed, etc) -- show the message, don't 500.
        return _form_page(str(e))
    except Exception:  # last-resort guard so a bug doesn't crash the demo
        # No exception text in the page: those strings carry absolute paths and
        # sometimes file content. The traceback goes to the server console.
        traceback.print_exc()
        return _form_page("Unexpected error during the scan. The traceback is "
                          "in the console running this server.")

    # The one-click fix edits files in the scanned directory, so it only makes
    # sense for a local path. A GitHub URL is cloned to a temp dir that the
    # walker deletes as soon as the scan finishes -- there'd be nothing left to
    # fix, so don't offer a button that can't work. A baseline needs the same
    # thing: somewhere durable to write it.
    local_target = not looksLikeGithubUrl(target) and os.path.isdir(target)

    suppressed = 0
    if use_baseline and local_target:
        try:
            known = baseline.load(baseline.default_path(target))
        except OSError as e:
            return _form_page(str(e))
        scored, suppressed = baseline.apply(scored, known)

    _LAST_SCAN.update(scored=scored, target=target, suppressed=suppressed)

    report_html = generate_report(scored, fmt="html", target=target,
                                  fix_enabled=local_target, home_url="/",
                                  suppressed=suppressed)
    return Response(report_html, mimetype="text/html")


@app.route("/report.<fmt>", methods=["GET"])
def download_report(fmt):
    """
    Re-render the last scan in another format and hand it back as a download.

    Re-rendering rather than re-scanning: the findings are already in hand, and
    a second walk of the same tree could legitimately return something
    different, which would make the JSON a user saved disagree with the page
    they saved it from.

    The saved HTML deliberately gets no home_url, so the copy on disk carries
    no export links or fix button pointing at a server that isn't there.
    """
    mimetype = _DOWNLOAD_TYPES.get(fmt)
    if mimetype is None:
        return jsonify({"error": f"unknown report format {fmt!r}"}), 404
    if not _LAST_SCAN["target"]:
        return jsonify({"error": "no scan in this session yet -- run one first"}), 404

    body = generate_report(_LAST_SCAN["scored"], fmt=fmt,
                           target=_LAST_SCAN["target"])
    return Response(body, mimetype=mimetype, headers={
        "Content-Disposition": f'attachment; filename="galicious-report.{fmt}"',
    })


@app.route("/api/baseline", methods=["POST"])
def api_baseline():
    """
    Write every finding from the last scan into the target's .sentrybaseline,
    so they are suppressed from here on. This is the "accept what is there
    today" step that makes --fail-on usable on a repo that isn't already at
    zero.

    It writes a file into the user's repo, so: the target must be the one this
    session actually scanned (not any directory a request cares to name), it
    must still be a local directory, and the browser confirms before calling.
    """
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()

    if not target or target != _LAST_SCAN["target"]:
        return jsonify({"ok": False,
                        "error": "no scan of that target in this session -- re-run it"}), 400
    if looksLikeGithubUrl(target) or not os.path.isdir(target):
        return jsonify({"ok": False,
                        "error": "a baseline can only be written into a local directory"}), 400

    path = baseline.default_path(target)
    try:
        count = baseline.save(path, _LAST_SCAN["scored"])
    except OSError as e:
        return jsonify({"ok": False, "error": f"could not write {path}: {e}"}), 400
    return jsonify({"ok": True, "count": count, "path": path})


@app.route("/api/fix", methods=["POST"])
def api_fix():
    """
    Apply the one-click fix for a single finding.

    The request carries only the finding's coordinates -- path, line, detector
    type -- never the secret itself. fixer re-reads the file and re-runs the
    detectors to find the value, so a file that changed since the scan makes
    the fix refuse rather than corrupt something.

    Same local-only posture as /api/browse: this writes to disk, so it assumes
    server and target repo are the same machine. fixer.resolve_inside() is what
    keeps a crafted file_path from escaping the scanned directory.
    """
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    file_path = (data.get("file_path") or "").strip()
    detector_type = (data.get("detector_type") or "").strip()
    line_number = data.get("line_number")

    if not (target and file_path and detector_type):
        return jsonify({"ok": False, "error": "missing target/file_path/detector_type"}), 400
    if not isinstance(line_number, int) or line_number < 1:
        return jsonify({"ok": False, "error": "line_number must be a positive integer"}), 400
    if looksLikeGithubUrl(target) or not os.path.isdir(target):
        return jsonify({"ok": False,
                        "error": "fixes only apply to a local directory that still exists"}), 400

    result = fixer.apply_fix(
        target, file_path, line_number, detector_type,
        in_history=bool(data.get("in_history")),
    )
    return jsonify(result.to_dict()), (200 if result.ok else 400)


@app.route("/api/browse", methods=["GET"])
def browse():
    """
    Lists subdirectories of a path on the machine running this Flask
    server, so the "Browse..." folder picker in index.html can hand back
    a real, full, absolute path -- something a plain <input type=file
    webkitdirectory> can never do (browsers deliberately don't expose
    real disk paths to JS). This only works because the tool is meant to
    be run locally: server and target repo are the same machine.

    Confined to _BROWSE_ROOT. Containment is fixer.resolve_inside(), reused
    rather than reimplemented -- it realpaths before comparing, so a symlink
    pointing out of the root is caught, and it treats a backslash as a
    separator on every platform.

    Query param: path (optional). Defaults to the browsable root.
    Returns JSON: { path, parent, dirs: [{name, path}], error }
    Only directories are listed -- never file contents.
    """
    requested = request.args.get("path", "").strip()
    try:
        current = (fixer.resolve_inside(_BROWSE_ROOT, requested)
                   if requested else _BROWSE_ROOT)
    except fixer.FixError:
        return jsonify({
            "path": _BROWSE_ROOT, "parent": None, "dirs": [],
            "error": f"Outside the browsable root ({_BROWSE_ROOT}). "
                     "Set GALICIOUS_BROWSE_ROOT to widen it.",
        }), 400

    if not os.path.isdir(current):
        return jsonify({
            "path": current,
            "parent": None,
            "dirs": [],
            "error": f"Not a directory: {current}",
        }), 400

    dirs = []
    try:
        with os.scandir(current) as it:
            for entry in it:
                try:
                    if entry.is_dir(follow_symlinks=False) and not entry.name.startswith("."):
                        dirs.append({"name": entry.name, "path": os.path.join(current, entry.name)})
                except OSError:
                    continue  # unreadable entry (permissions, broken symlink, etc) -- skip it
    except OSError as e:
        return jsonify({
            "path": current,
            "parent": os.path.dirname(current.rstrip(os.sep)) or None,
            "dirs": [],
            "error": f"Can't read {current}: {e.strerror or e}",
        }), 400

    dirs.sort(key=lambda d: d["name"].lower())

    # No way up and out: at the root there is no parent to offer.
    parent = os.path.dirname(current.rstrip(os.sep))
    if parent == current or os.path.realpath(current) == _BROWSE_ROOT:
        parent = None

    return jsonify({"path": current, "parent": parent, "dirs": dirs, "error": None})


if __name__ == "__main__":
    # debug=False on purpose: the Werkzeug debugger is an interactive Python
    # console served to the browser on any unhandled exception. Bound to
    # loopback explicitly for the same reason -- /api/fix and /api/baseline
    # write files, and nothing here authenticates a caller.
    app.run(host="127.0.0.1", port=5000, debug=False)
