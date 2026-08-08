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

This file lives under web/ rather than the repo root, so the root directory
shows only the detection/scoring engine (walker, pattern_detector,
entropy_detector, scorer_reporter, ...) plus the CLI that drives it directly.
Because of that, the imports below need the repo root on sys.path before they
run -- see the block right after this docstring.
"""

from __future__ import annotations

import os
import sys

# Repo root (parent of this file's directory), so `import orchestrator` etc.
# resolve regardless of whether this is launched as `py web/app.py` or
# `py -m web.app`. Must run before any of the imports below.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from flask import Flask, jsonify, render_template, request, Response

from orchestrator import run_scan
from walker import WalkerError, looksLikeGithubUrl
from models import ScanContext
from scorer_reporter import generate_report
from web import fixer

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method != "POST":
        return render_template("index.html", error=None)

    target = (request.form.get("target") or "").strip()
    history = "history" in request.form
    full_scan = request.form.get("scan_mode") == "full"
    # Unticked by default, and it needs to stay that way -- this is the one
    # option that puts candidate secrets on the network. See live_check.py.
    verify_live = "verify_live" in request.form

    if not target:
        return render_template(
            "index.html",
            error="Please enter a repository path or GitHub URL.",
        )

    try:
        scored = run_scan(target, history=history, full_scan=full_scan,
                          context=ScanContext(verify_live=verify_live))
    except WalkerError as e:
        # Expected failure conditions from the walker (bad path, bad URL,
        # git missing, clone failed, etc) -- show the message, don't 500.
        return render_template("index.html", error=str(e))
    except Exception as e:  # last-resort guard so a bug doesn't crash the demo
        return render_template("index.html", error=f"Unexpected error: {e}")

    # The one-click fix edits files in the scanned directory, so it only makes
    # sense for a local path. A GitHub URL is cloned to a temp dir that the
    # walker deletes as soon as the scan finishes -- there'd be nothing left to
    # fix, so don't offer a button that can't work.
    fixable_target = bool(target) and not looksLikeGithubUrl(target) and os.path.isdir(target)

    report_html = generate_report(scored, fmt="html", target=target,
                                  fix_enabled=fixable_target, home_url="/")
    return Response(report_html, mimetype="text/html")


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

    Query param: path (optional). Defaults to the user's home directory.
    Returns JSON: { path, parent, dirs: [{name, path}], error }
    Only directories are listed -- never file contents.
    """
    requested = request.args.get("path", "").strip()
    current = os.path.abspath(requested) if requested else os.path.expanduser("~")

    if not os.path.isdir(current):
        return jsonify({
            "path": current,
            "parent": os.path.dirname(current.rstrip(os.sep)) or None,
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

    parent = os.path.dirname(current.rstrip(os.sep))
    if parent == current:  # already at filesystem root
        parent = None

    return jsonify({"path": current, "parent": parent, "dirs": dirs, "error": None})


if __name__ == "__main__":
    app.run(debug=True)