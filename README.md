# Galicious Scanner

Scans a local folder or a GitHub repo for exposed secrets. Two detection
engines feed one scoring/report pipeline: a regex signature library for
known formats (AWS, Stripe, GitHub, Slack, JWTs, ...) and a Shannon-entropy
fallback for custom tokens that don't match any known shape. Every finding
is scored, redacted, and comes with a plain-language reason -- no output
ever contains a full secret.

## Usage

```bash
pip install -r requirements.txt

# command line
python cli.py <path-or-url> [--history] [--format terminal|json|html]

# web UI (themed report, clickable findings, one-click fix)
python web/app.py
```

## Layout

The repo root holds only the detection/scoring engine and the CLI that
drives it directly:

```
walker.py            file + git-history walking
pattern_detector.py   regex signature library (config/patterns.json)
entropy_detector.py   Shannon-entropy fallback for custom secrets
dedup.py              collapses duplicate raw hits into one leak
scorer_reporter.py    placeholder filtering, scoring rubric, report dispatch
reporters.py          terminal + json renderers
models.py             shared data shapes
orchestrator.py       wires the above into run_scan()
cli.py                command-line entry point
```

The browser-facing layer -- Flask app, the scan-form page, the fix
endpoint, and the themed HTML report -- lives under `web/`, and only
`scorer_reporter.py` reaches into it, lazily, when `fmt="html"` is
requested. Nothing at the root has a hard dependency on it (or on Flask).

```
web/app.py            Flask routes: /, /api/fix, /api/browse
web/fixer.py           one-click fix engine
web/html_report.py     the themed report page (severity tiles, terminal panel)
web/report_assets.py   report page CSS/JS
web/terminal_assets.py finding-detail terminal panel CSS/JS
web/templates/         the scan-form page
```

Tests live in `tests/` (263 tests, offline, no network). `scripts/` holds
`make_test_repo.py`, which builds a deliberately vulnerable fixture repo to
scan against -- see its `--help` and `docs/ROADMAP.md`'s "One-click fix"
entry for how it's used.

## What's left to do

Full detail, effort estimates, and exact files to touch for each item are
in **[docs/ROADMAP.md](docs/ROADMAP.md)**. Short version:

| # | Feature | What / how |
|---|---|---|
| 0 | One-click fix | **Done** -- `web/fixer.py` rewrites the source line to an env lookup and moves the secret to `.env` |
| 1 | Verified-live checking (3-4 providers) | Call each provider's own API (AWS STS, GitHub `/user`, Stripe `/v1/account`, Slack `auth.test`) to confirm a candidate secret is actually live, not just format-shaped |
| 2 | SARIF output | New `render_sarif()` in `reporters.py`, mapping findings to SARIF 2.1.0 so they upload to GitHub Code Scanning |
| 3 | Pre-commit hook + `--staged` | `cli.py --staged` scans only the staged git diff; ship as a `.pre-commit-hooks.yaml` entry |
| 4 | Baseline / allowlist file | Fingerprint each finding (`sha256(file + type + redacted)`), store accepted ones in `.sentrybaseline`, skip matches on future scans |
| 5 | Remediation guidance per finding | A per-detector-type lookup table of remediation steps on `ScoredFinding`, shown in all three report formats |

Each entry in the roadmap is written as a standalone template: pick one,
open a PR against just that feature.
