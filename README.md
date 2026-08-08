<p align="center">
<img src="images/dlsu_logo.png" alt="De La Salle University Logo" width="150"/>
</p>

# Galicious Secret Scanner - README

### Mini Project: Hacking Tool Creation

**Submitted by Group 7 [S01]:**

- GALICIA, Lance Krystofer
- GARCIA, Theodore Rodolfo III
- KE, Xan Luo
- MOJICA, Maurienne Marie
- YAMSUAN, Rhian Claire

*August 10, 2026*

---

## Description
<p align="justify">
Galicious Secret Scanner scans a local folder or a GitHub repo for exposed secrets. Two detection engines feed a single scoring and reporting pipeline. The first is a regex signature library for known formats such as AWS, Stripe, GitHub, Slack, JWTs, private keys and database connection strings. The second is a Shannon-entropy fallback for custom tokens that don't match any known shape. Every finding is deduplicated, scored, redacted, and given a plain-language reason. No output, in any format, ever contains a full secret.
</p>

## Purpose
The tool answers one concrete question for a developer or auditor: *did we leave any secrets sitting in this codebase, including ones that were deleted from the latest commit but are still recoverable from history?* Specifically, it is built to detect:

- Hardcoded API keys (AWS-style access keys, Stripe, GitHub, Slack tokens, and other vendor formats)
- Passwords embedded directly in source or configuration files
- Session and authentication tokens (including JWTs)
- Database connection strings and credentials
- Other secret-like values in configuration files (`.env`, `config.php`, `database.sql`, etc.)
- Secrets that once existed in a repository's Git history but were later removed from the working files

The tool is scoped to detection and reporting, not exploitation. With `--verify-live` it asks a provider whether a credential still authenticates, using an unprivileged "who am I" call such as `sts:GetCallerIdentity`. It never reads, writes, or changes anything using a credential it finds, and that check stays off unless it is explicitly requested.

## Features

- **Regex-based detection**: signature library (`config/patterns.json`) covering AWS, Stripe, GitHub, Slack, JWTs, private-key headers, and DB connection strings
- **Entropy-based detection**: Shannon-entropy fallback that flags high-randomness strings next to suspicious variable names (`key`, `token`, `secret`, `password`), catching custom tokens no regex recognizes
- **Deduplication**: collapses duplicate raw hits, such as the same secret caught by both engines, into a single leak entry
- **Context-aware severity scoring**: Low/Medium/High/Critical, weighted by file type, test or example folder location, placeholder-pattern matching, and whether the file is tracked by Git
- **Redaction by default**: every value shown, such as `AKIA****************`, is partially masked
- **Git history scanning** (`--history`): walks `git log -p --all` to catch secrets committed and later deleted from the working tree
- **`.sentryignore` support**: exclude known-safe paths, file types, or test fixtures
- **Placeholder suppression**: filters out boilerplate values like `YOUR_API_KEY_HERE`
- **Verified-live checking** (`--verify-live`): asks the provider itself whether a candidate secret still works. AWS uses `sts:GetCallerIdentity` signed with a hand-rolled SigV4, GitHub uses `GET /user`, Stripe uses `GET /v1/account`, and Slack uses `auth.test`. A confirmed-live key is promoted to Critical wherever it sits, and a confirmed-dead one drops to Low. It is off by default because it puts the candidate secret on the network
- **Multiple report formats**: terminal, JSON, SARIF 2.1.0, and a themed HTML report
- **GitHub Code Scanning integration**: `--format sarif` uploads through `github/codeql-action/upload-sarif`, so findings land in the repo's Security tab next to CodeQL. See `.github/workflows/secret-scan.yml`
- **Staged-only scanning** (`--staged`): scans just the lines a commit adds, so a pre-existing secret elsewhere in the file doesn't fail a commit that didn't introduce it. Ships as a `.pre-commit-hooks.yaml` entry
- **Baseline / allowlist** (`--baseline`, `--update-baseline`): fingerprints accepted findings into `.sentrybaseline` so `--fail-on` is usable on a repo that already has findings. The fingerprint is `sha256(file + type + redacted)`, which survives line-number drift
- **Remediation guidance**: every detector type carries ordered, plain-language steps (rotate first, then the code edit), plus git-history purge steps when the secret was ever committed. Shown in the terminal report, the JSON output, and the HTML report's detail panel (SARIF carries the finding, not the advice)
- **Web UI**: a Flask app (`web/app.py`) with a scan form, a clickable themed report, downloadable JSON/SARIF/HTML, and a **one-click fix** that rewrites the offending source line to an environment-variable lookup and moves the secret into `.env`

## System Requirements
- Python 3.9 or later, on the system `PATH`
- Git, if Git history scanning will be used (the tool shells out to `git log -p`)
- Flask (installed via `requirements.txt`), only needed if you run the web UI
- A local folder, local Git repo, or a GitHub repo URL you have permission to scan
- No internet access is required for local scans. It is only needed if you point the tool at a remote repo URL you are authorized to clone

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
python cli.py <path-or-url> [--history | --staged] [--full-scan] [--verify-live]
                            [--format terminal|json|sarif|html] [-o OUTPUT]
                            [--min-severity low|medium|high|critical]
                            [--baseline [PATH]] [--update-baseline [PATH]]
                            [--fail-on none|low|medium|high|critical]

# web UI (themed report, clickable findings, one-click fix, downloads)
python web/app.py        # then open http://127.0.0.1:5000
```
- `<path-or-url>`: a local folder or a GitHub repo URL (default: the current directory)
- `--history`: also scans the full commit history (`git log -p --all`) for secrets that were later removed from the working files. `--max-commits N` caps how far back it walks
- `--staged`: scans only the lines staged for commit. This is the pre-commit case, and it is mutually exclusive with `--history`
- `--full-scan`: skips the default ignore list (binaries, `node_modules/`, build output) so nothing is left out
- `--format`: choose `terminal` (default), `json`, `sarif`, or `html` for the report; `-o` writes it to a file
- `--min-severity`: drop anything below this band from the report
- `--verify-live`: check each AWS, GitHub, Stripe or Slack candidate against its provider. This sends the candidate secret to that provider, so it is off unless you ask for it
- `--baseline` / `--update-baseline`: suppress findings already accepted in `.sentrybaseline`, or write the current findings into it
- `--fail-on`: exit 1 if any finding reaches this severity, for use as a CI or pre-commit gate

Using it as a pre-commit hook, in another repo's `.pre-commit-config.yaml`:
```bash
python cli.py --staged --baseline --fail-on high
```

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
dedup.py              collapses duplicate raw hits into one leak
staged.py             scans only the lines the staged diff adds (--staged)
baseline.py           fingerprints accepted findings into .sentrybaseline
remediation.py        per-detector-type "what to do about it" steps
scorer_reporter.py    placeholder filtering, scoring rubric, report dispatch
reporters.py          terminal, json and sarif renderers
models.py             shared data shapes
orchestrator.py       wires the above into run_scan()
cli.py                command-line entry point
```
The browser-facing layer lives under `web/`. It is only reached lazily by `scorer_reporter.py` when `fmt="html"` is requested, so nothing at the root has a hard dependency on it or on Flask:
```
web/app.py             Flask routes: /, /api/fix, /api/browse
web/fixer.py           one-click fix engine
web/html_report.py     themed report page (severity tiles, terminal panel)
web/report_assets.py   shared page chrome (BASE_CSS/BASE_JS) + report page CSS/JS
web/terminal_assets.py finding-detail terminal panel CSS/JS
web/templates/         the scan-form page
```
The scan form and the report page pull their palette, matrix backdrop and
scanline chrome from the same `BASE_CSS`/`BASE_JS` constants, so the two
cannot drift apart.
Tests live in `tests/` and there are 341 of them. They run offline, because the provider checks are exercised against a patched HTTP layer and the suite never opens a socket. `scripts/make_test_repo.py` builds a deliberately vulnerable fixture repo to scan against.

## Testing Environment
In keeping with this course's ethical requirements, Galicious Secret Scanner should only ever be run against:
- Local folders on a personal machine
- Intentionally vulnerable lab repositories set up for this course
- Seeded demo repositories created specifically to showcase detection (see `scripts/make_test_repo.py`, which builds a deliberately vulnerable fixture repo for this purpose)
- Controlled local Git repositories the group created for testing

It must **never** be run against real live websites, school systems or infrastructure, production systems belonging to any organization, or public codebases the group does not have explicit permission to scan.

## Sample Output
A terminal finding shows severity, secret type, and file first, then the rationale, then the redacted value:
```
HIGH  AWS_ACCESS_KEY in .env
Reason: AWS-format key in a tracked .env file, not a placeholder
Value: AKIA***************
```
The HTML report renders the same finding with the file path, line number, a color-coded severity badge, and the rationale. That makes a large set of findings quick to read through, or to attach to a security-audit handoff. The `--format json` output carries the same fields for programmatic use, such as a step in a CI pipeline.

## Limitations
- Ships with a fixed regex signature library, so brand-new or highly unusual secret formats rely on the entropy fallback only
- Accuracy depends on contextual filtering. Projects with unusual folder structures may need custom `.sentryignore` rules for clean results
- Verified-live checking covers four providers. Everything else, including JWTs, private keys, DB connection strings and entropy hits, has no API to ask, and is reported as unverified rather than guessed at
- An AWS access key can only be verified when its matching secret access key is found in the same file, because signing an STS request needs both halves. A lone `AKIA...` comes back unverified
- Built and intended for controlled educational use, not as a hardened, production-grade secret-scanning solution

## Future Improvements
Every item on the original roadmap has shipped. [`docs/ROADMAP.md`](docs/ROADMAP.md)
keeps the reasoning behind each one. What is still open:

| Feature | What / how |
|---|---|
| Concurrent live verification | `--verify-live` checks findings one at a time and caches nothing, so the same key in ten files is ten requests |
| Cross-file AWS key pairing | An `AKIA...` is only verifiable when its secret half sits in the same file; pairing across files or against `~/.aws/credentials` isn't attempted |
| Multi-line secret rewrite | The one-click fix is line-based, like the detectors it reuses, so a PEM block can't be relocated automatically |
| Batch fix | A "fix every auto-fixable finding on this page" button, and an undo within the same session |

## Ethical Disclaimer
<p align="justify">
This tool was developed for educational purposes only. It must only be used in authorized and controlled testing environments. Unauthorized testing against real systems, public websites, or third-party services is strictly prohibited.

It was built as part of the NSSECU2 (Advanced and Offensive Security) mini-project. Galicious Secret Scanner should only be pointed at repositories and folders that you own, have written permission to inspect, or created intentionally for coursework and demonstration. It should not be used against live production systems, school infrastructure, or any environment outside the scope of authorized testing.

One note on `--verify-live`. It is the only option that sends anything off the machine, because it transmits the candidate secret to the provider it appears to belong to. Use it only on credentials you own or are authorized to test.
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
Galicious Secret Scanner is not a single-technique scanner. It combines a known-format regex library with an entropy-based fallback, so both recognizable and custom internal secrets are caught in the same pass. Hits from the two engines are then deduplicated into one finding rather than reported as the same leak twice.

Its severity scoring is context-aware rather than a flat match or no-match result. It factors in whether a file is a live config or a test fixture, whether the surrounding folder is a test or example directory, whether the value matches a known placeholder, and whether the file is actually tracked by Git. The report therefore tells the user which findings genuinely matter, instead of only where a pattern matched.

On top of the CLI, the team built a web UI with a one-click fix. It remediates a finding by moving the secret into `.env` and rewriting the source line to reference it, which closes the loop from detection to remediation instead of stopping at reporting.
</p>
