"""
app.py
------
Flask front end. Kept intentionally thin -- all it does is take the form
submission, hand it to orchestrator.run_scan() (the exact same pipeline
cli.py uses), and render the result.

On a successful scan we return the full themed HTML report straight from
scorer_reporter/reporters (the matrix-style page with severity tiles, sort,
filter) instead of the old plain table, since that report is already a
complete standalone page. On error, we fall back to the form page with an
error message.
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request, Response

from orchestrator import run_scan
from walker import WalkerError
from scorer_reporter import generate_report

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method != "POST":
        return render_template("index.html", error=None)

    target = (request.form.get("target") or "").strip()
    history = "history" in request.form
    full_scan = request.form.get("scan_mode") == "full"

    if not target:
        return render_template(
            "index.html",
            error="Please enter a repository path or GitHub URL.",
        )

    try:
        scored = run_scan(target, history=history, full_scan=full_scan)
    except WalkerError as e:
        # Expected failure conditions from the walker (bad path, bad URL,
        # git missing, clone failed, etc) -- show the message, don't 500.
        return render_template("index.html", error=str(e))
    except Exception as e:  # last-resort guard so a bug doesn't crash the demo
        return render_template("index.html", error=f"Unexpected error: {e}")

    report_html = generate_report(scored, fmt="html", target=target)
    return Response(report_html, mimetype="text/html")


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