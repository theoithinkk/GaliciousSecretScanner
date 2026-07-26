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

from flask import Flask, render_template, request, Response

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

    if not target:
        return render_template(
            "index.html",
            error="Please enter a repository path or GitHub URL.",
        )

    try:
        scored = run_scan(target, history=history)
    except WalkerError as e:
        # Expected failure conditions from the walker (bad path, bad URL,
        # git missing, clone failed, etc) -- show the message, don't 500.
        return render_template("index.html", error=str(e))
    except Exception as e:  # last-resort guard so a bug doesn't crash the demo
        return render_template("index.html", error=f"Unexpected error: {e}")

    report_html = generate_report(scored, fmt="html")
    return Response(report_html, mimetype="text/html")


if __name__ == "__main__":
    app.run(debug=True)