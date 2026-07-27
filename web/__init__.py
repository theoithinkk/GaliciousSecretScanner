"""
web/
----
The browser-facing layer: the Flask app, the scan-form page, the fix
endpoint, and the HTML report's rendering + assets.

Nothing under this package is required to detect or score a secret -- that
logic lives at the repo root (walker.py, pattern_detector.py,
entropy_detector.py, dedup.py, scorer_reporter.py) and is what cli.py drives
directly. This package is one more consumer of that engine, the same way
cli.py is; it just happens to expose it over HTTP with a themed UI on top.

Modules here import root-level modules with plain absolute imports (e.g.
`import walker`), which only resolve when the repo root is on sys.path.
web/app.py adds it explicitly at the top, before any such import runs, so it
works whether it's launched as `py web/app.py` or `py -m web.app` from the
repo root. Every other entry point that reaches into this package
(scorer_reporter.py's lazy import of web.html_report, the test suite) already
runs with the repo root on sys.path.
"""
