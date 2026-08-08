# GaliciousSecretScanner

## Tool Name
**GaliciousSecretScanner**

## Description
<p align="justify">
GaliciousSecretScanner scans a local folder or a GitHub repo for exposed secrets. Two detection engines feed a single scoring and reporting pipeline: a regex signature library for known formats (AWS, Stripe, GitHub, Slack, JWTs, private keys, database connection strings, ...) and a Shannon-entropy fallback for custom tokens that don't match any known shape. Every finding is deduplicated, scored, redacted, and shipped with a plain-language reason — no output, in any format, ever contains a full secret.
</p>

## Purpose
<p align="justify">
The tool answers one concrete question for a developer or auditor: *did we leave any secrets sitting in this codebase, including ones that were deleted from the latest commit but are still recoverable from history?* Specifically, it is built to detect:

- Hardcoded API keys (AWS-style access keys, Stripe, GitHub, Slack tokens, and other vendor formats)
- Passwords embedded directly in source or configuration files
- Session and authentication tokens (including JWTs)
- Database connection strings and credentials
- Other secret-like values in configuration files (`.env`, `config.php`, `database.sql`, etc.)
- Secrets that once existed in a repository's Git history but were later removed from the working files

The tool is scoped to detection and reporting, not exploitation. With `--verify-live` it will ask a provider whether a credential still authenticates — an unprivileged "who am I" call such as `sts:GetCallerIdentity` — but it never reads, writes, or acts on anything with a credential it finds, and that check stays off unless it is explicitly requested.
</p>

## Features

- **Regex-based detection** — signature library (`config/patterns.json`) covering AWS, Stripe, GitHub, Slack, JWTs, private-key headers, and DB connection strings
- **Entropy-based detection** — Shannon-entropy fallback that flags high-randomness strings next to suspicious variable names (`key`, `token`, `secret`, `password`), catching custom tokens no regex recognizes
- **Deduplication** — collapses duplicate raw hits (e.g. the same secret caught by both engines) into a single leak entry
- **Context-aware severity scoring** — Low/Medium/High/Critical, weighted by file type, test/example-folder location, placeholder-pattern matching, and whether the file is tracked by Git
- **Redaction by default** — every value shown (e.g. `AKIA****************`) is partially masked
- **Git history scanning** (`--history`) — walks `git log -p --all` to catch secrets committed and later deleted from the working tree
- **`.sentryignore` support** — exclude known-safe paths, file types, or test fixtures
- **Placeholder suppression** — filters out boilerplate values like `YOUR_API_KEY_HERE`
- **Verified-live checking** (`--verify-live`) — asks the provider itself whether a candidate secret still works: AWS (`sts:GetCallerIdentity`, signed with a hand-rolled SigV4), GitHub (`GET /user`), Stripe (`GET /v1/account`), Slack (`auth.test`). A confirmed-live key is promoted to Critical wherever it sits; a confirmed-dead one drops to Low. Off by default, because it puts the candidate secret on the network
- **Multiple report formats** — terminal, JSON, SARIF 2.1.0, and a themed HTML report
- **GitHub Code Scanning integration** — `--format sarif` uploads through `github/codeql-action/upload-sarif`, so findings land in the repo's Security tab next to CodeQL (see `.github/workflows/secret-scan.yml`)
- **Web UI** — a Flask app (`web/app.py`) with a scan form, a clickable themed report, and a **one-click fix** that rewrites the offending source line to an environment-variable lookup and moves the secret into `.env`


## System Requirements
- Python 3.9 or later, on the system `PATH`
- Git, if Git history scanning will be used (the tool shells out to `git log -p`)
- Flask (installed via `requirements.txt`), only needed if you run the web UI
- A local folder, local Git repo, or a GitHub repo URL you have permission to scan
- No internet access is required for local scans — it's only needed if you point the tool at a remote repo URL you're authorized to clone

## Installation
```bash
# (recommended) create and activate a virtual environment first
pip install -r requirements.txt

# confirm the install
python cli.py --help
```
If it prints the list of available options instead of an error, installation succeeded.

## Usage
```bash
# command line
python cli.py <path-or-url> [--history] [--format terminal|json|sarif|html] [--verify-live]

# web UI (themed report, clickable findings, one-click fix)
python web/app.py
```
- `<path-or-url>` — a local folder or a GitHub repo URL
- `--history` — also scans the full commit history (`git log -p --all`) for secrets that were later removed from the working files
- `--format` — choose `terminal` (default), `json`, `sarif`, or `html` for the report
- `--verify-live` — check each AWS/GitHub/Stripe/Slack candidate against its provider. This sends the candidate secret to that provider, so it is off unless you ask for it

Producing a SARIF file for GitHub Code Scanning:
```bash
python cli.py . --format sarif -o results.sarif
```

## Layout
The repo root holds only the detection/scoring engine and the CLI that drives it directly:
```
walker.py             file + git-history walking
pattern_detector.py   regex signature library (config/patterns.json)
entropy_detector.py   Shannon-entropy fallback for custom secrets
live_check.py         asks AWS/GitHub/Stripe/Slack if a secret is still live
dedup.py               collapses duplicate raw hits into one leak
scorer_reporter.py    placeholder filtering, scoring rubric, report dispatch
reporters.py           terminal + json renderers
models.py               shared data shapes
orchestrator.py         wires the above into run_scan()
cli.py                  command-line entry point
```
The browser-facing layer lives under `web/` and is only reached lazily by `scorer_reporter.py` when `fmt="html"` is requested — nothing at the root has a hard dependency on it or on Flask:
```
web/app.py             Flask routes: /, /api/fix, /api/browse
web/fixer.py            one-click fix engine
web/html_report.py      themed report page (severity tiles, terminal panel)
web/report_assets.py    report page CSS/JS
web/terminal_assets.py  finding-detail terminal panel CSS/JS
web/templates/           the scan-form page
```
Tests live in `tests/` (316 tests, offline — the provider checks are exercised against a patched HTTP layer, so the suite never opens a socket). `scripts/make_test_repo.py` builds a deliberately vulnerable fixture repo to scan against.

## Testing Environment
In keeping with this course's ethical requirements, Galicious Scanner should only ever be run against:
- Local folders on a personal machine
- Intentionally vulnerable lab repositories set up for this course
- Seeded demo repositories created specifically to showcase detection (see `scripts/make_test_repo.py`, which builds a deliberately vulnerable fixture repo for this purpose)
- Controlled local Git repositories the group created for testing

It must **never** be run against real, live websites; school systems or infrastructure; production systems belonging to any organization; or unauthorized public codebases the group does not have explicit permission to scan.

## Sample Output
A terminal finding shows severity, secret type, and file first, then the rationale, then the redacted value:
```
HIGH  AWS_ACCESS_KEY in .env
Reason: AWS-format key in a tracked .env file, not a placeholder
Value: AKIA***************
```
The HTML report renders the same finding with the file path, line number, a color-coded severity badge, and the rationale, so a large set of findings can be scanned quickly or attached to a security-audit handoff. The `--format json` output carries the same fields for programmatic consumption (e.g. a CI pipeline step).

## Limitations
- Ships with a fixed regex signature library, so brand-new or highly unusual secret formats rely on the entropy fallback only
- Accuracy depends on contextual filtering; projects with unusual folder structures may need custom `.sentryignore` rules for clean results
- Verified-live checking covers four providers. Everything else (JWTs, private keys, DB connection strings, entropy hits) has no API to ask, and is reported as unverified rather than guessed at
- An AWS access key can only be verified when its matching secret access key is found in the same file — signing an STS request needs both halves. A lone `AKIA...` comes back unverified
- Built and intended for controlled educational use, not as a hardened, production-grade secret-scanning solution

## Future Improvements
Full detail and exact files to touch for each item are in [`docs/ROADMAP.md`](docs/ROADMAP.md).

| # | Feature | What / how |
|---|---|---|
| 0 | One-click fix | **Done** — `web/fixer.py` rewrites the source line to an env lookup and moves the secret to `.env` |
| 1 | Verified-live checking (3–4 providers) | **Done** — `live_check.py` calls AWS STS, GitHub `/user`, Stripe `/v1/account` and Slack `auth.test` behind `--verify-live` |
| 2 | SARIF output | **Done** — `render_sarif()` in `reporters.py` emits SARIF 2.1.0; `.github/workflows/secret-scan.yml` uploads it to Code Scanning |
| 3 | Pre-commit hook + `--staged` | `cli.py --staged` scans only the staged git diff; ship as a `.pre-commit-hooks.yaml` entry |
| 4 | Baseline / allowlist file | Fingerprint each finding (`sha256(file + type + redacted)`), store accepted ones in `.sentrybaseline`, skip matches on future scans |
| 5 | Remediation guidance per finding | A per-detector-type lookup table of remediation steps on `ScoredFinding`, shown in all three report formats |

## Ethical Disclaimer
<p align="justify">
This tool was developed for educational purposes only. It must only be used in authorized and controlled testing environments. Unauthorized testing against real systems, public websites, or third-party services is strictly prohibited.

It was built as part of the NSSECU2 (Advanced and Offensive Security) mini-project. Concretely, Galicious Scanner should only be pointed at repositories and folders that you own, have written permission to inspect, or created intentionally for coursework and demonstration. It should not be used against live production systems, school infrastructure, or any environment outside the scope of authorized testing.

One note on `--verify-live`: it is the only option that sends anything off the machine, because it transmits the candidate secret to the provider it appears to belong to. Use it only on credentials you own or are authorized to test.
</p>

## Group Members and Roles
| Name | Role |
|---|---|
| Galicia, Lance Krystofer | CLI & Orchestration, Auto-Fix Feature |
| Garcia, Theodore Rodolfo III | Filter, Score, and Report, Auto-Fix Feature |
| Ke, Xan Luo | Repository and History Walker, Auto-Fix Feature |
| Mojica, Maurienne Marie | Entropy Detector, Auto-Fix Feature |
| Yamsuan, Rhian Claire | Pattern Entropy, Auto-Fix Feature |

## Original Contribution
<p align="justify">
Galicious Scanner is not a single-technique scanner — it combines a known-format regex library with an entropy-based fallback so that both recognizable and custom/internal secrets are caught by the same pass, then deduplicates hits from the two engines into one finding rather than reporting the same leak twice. Its severity scoring is context-aware rather than a flat match/no-match result: it factors in whether a file is a live config vs. a test fixture, whether the surrounding folder is a test/example directory, whether the value matches a known placeholder, and whether the file is actually tracked by Git — so the report tells the user which findings genuinely matter rather than just where a pattern matched. On top of the CLI, the team built a web UI with a one-click fix that automatically remediates a finding by moving the secret into `.env` and rewriting the source line to reference it, closing the loop from detection to remediation rather than stopping at reporting.
</p>


