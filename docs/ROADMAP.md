# Roadmap

Features left for someone else to build. Each entry below is a template:
problem, why it matters, where it lives (or should), effort, and what "done"
looks like. Pick one, delete the rest of that entry's placeholder text as you
fill it in, and open a PR against just that feature -- these are independent
of each other.

## Status

| # | Feature | Status |
|---|---|---|
| 0 | One-click fix | **Done** -- see below |
| 1 | Verified-live checking (3-4 providers) | Not started |
| 2 | SARIF output | Not started |
| 3 | Pre-commit hook + `--staged` | Not started |
| 4 | Baseline / allowlist file | Not started |
| 5 | Remediation guidance per finding | Not started |

---

## 0. One-click fix -- DONE

**Why it existed:** the report told you where a secret was and how bad it
was, but not what to do about it beyond a rotation warning. This closes that
gap for the mechanical part (get the secret out of source) without touching
the part only a human can do (rotate the credential).

**Where it lives:**
- [`web/fixer.py`](../web/fixer.py) -- the engine. `apply_fix()` re-reads the
  file and re-runs the detectors to relocate the secret (never trusts a
  plaintext value sent from the browser), gitignores `.env` *before* writing
  to it, rewrites the source line to an environment lookup
  (`_ENV_REF` covers Python/JS/Ruby/PHP/Go/shell/YAML/Terraform), and refuses
  rather than guessing when the file changed since the scan or the rewrite
  has no safe template for that file type.
- [`web/app.py`](../web/app.py) -- `POST /api/fix`, the route the button
  calls. Takes only file path + line + detector type, never the secret
  itself.
- [`web/terminal_assets.py`](../web/terminal_assets.py) -- the button's JS
  (`applyFix()`), and the copy explaining why the button is disabled or
  hidden for a given finding.
- [`tests/test_fixer.py`](../tests/test_fixer.py) -- path-traversal guards,
  ordering (`.gitignore` before `.env`), per-language rewrites, and the
  refusal cases.

**Ideas for extending it** (none of these are started; each is its own
mini-feature):
- Batch mode: a "fix all auto-fixable findings on this page" button.
- Multi-line secret rewrite (currently line-based, like the detectors it
  reuses -- a PEM block or a multi-line JSON value can't be relocated today).
- An undo: the fix already knows the original line; a "revert" button could
  restore it and remove the `.env` entry within the same session.
- Detect whether `.env` is *already* tracked by git before claiming success --
  right now the fix gitignores it going forward but doesn't check history.
  (This is actually a special case of Feature 5 below.)

---

## 1. Verified-live checking for 3-4 providers

**Why:** this is the honest answer to "how is this not redundant with
GitHub's own secret scanning." GitHub's push protection let every fabricated
AWS/GitHub/Google key in this repo's own test fixture through untouched,
because it checks the key against the provider and finds nothing live there.
It blocked the fabricated Slack and Stripe keys for the same reason, in
reverse. This scanner currently has no equivalent: every finding says "looks
like an AWS key," never "is a live AWS key." That distinction is the single
biggest thing separating a real secret-scanning tool from a regex script.

**Where to put it:**
- New module at the repo root, e.g. `live_check.py` -- it belongs alongside
  the detection engine (walker/pattern_detector/entropy_detector/dedup), not
  under `web/`, since the CLI should get it too.
- One function per provider, each taking a candidate secret string and
  returning `True` (confirmed live) / `False` (confirmed dead) / `None`
  (couldn't check -- rate limited, network error, etc). Start with:
  - **AWS**: `sts:GetCallerIdentity` using the candidate as credentials.
  - **GitHub**: `GET https://api.github.com/user` with
    `Authorization: token <candidate>`.
  - **Stripe**: `GET https://api.stripe.com/v1/account` with the candidate as
    the bearer token.
  - **Slack**: `POST https://slack.com/api/auth.test` with the candidate.
- `models.ScoredFinding` needs a new field, e.g. `verified: Optional[bool]`
  (default `None` = not checked).
- `scorer_reporter.filter_and_score` needs an opt-in flag on `ScanContext`
  (e.g. `verify_live: bool = False`) -- this makes outbound network requests
  per finding, so it must never run by default. Wire it to a new
  `--verify-live` flag on `cli.py` and (optionally) a checkbox on the web
  form.
- Feed `verified` into the scoring rubric: a confirmed-live finding should
  outrank an unconfirmed one at the same base severity, and a
  confirmed-dead one should be discounted hard (it may still be worth a LOW
  finding to prompt cleanup, but it is not urgent).

**Security note:** this sends the candidate secret to a third party (the
provider itself) over the network. That's the whole point, but it means:
never log the request/response bodies, never write the raw secret to
disk or to a report, and make sure the opt-in is genuinely opt-in.

**Definition of done:**
- Unit tests mock the HTTP layer (no real network calls in the test suite).
- `--verify-live` off by default; scanning behavior is unchanged without it.
- A finding's rationale states plainly whether it was verified, and how.

---

## 2. SARIF output

**Why:** SARIF (Static Analysis Results Interchange Format) is what GitHub
Code Scanning ingests. A finding uploaded in this format shows up in the
repo's own Security tab, next to CodeQL results, with zero extra
infrastructure. This is the best effort-to-payoff item on this list.

**Where to put it:**
- `reporters.py`, alongside `render_terminal` / `render_json` -- SARIF is a
  format cli.py should be able to produce standalone, no server involved,
  so it belongs at the root with the other two, not under `web/`.
- Add `render_sarif(scored: List[ScoredFinding]) -> str` returning
  `json.dumps(...)` of a SARIF 2.1.0 `sarifLog` object. Reference:
  <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>. The
  shape you need is small:
  - one `run`, one `tool.driver` (name: this scanner, version, and a `rules`
    array built from `config/patterns.json`'s `type`/`description` fields
    plus `HIGH_ENTROPY`)
  - one `result` per finding: `ruleId` = `detector_type`, `level` mapped from
    `Severity` (`error` for CRITICAL/HIGH, `warning` for MEDIUM, `note` for
    LOW), `message.text` = the existing `rationale`, and one
    `physicalLocation` built from `file_path` + `line_number`.
- `scorer_reporter.generate_report` needs a new `fmt == "sarif"` branch.
- `cli.py`'s `--format` choices need `"sarif"` added.

**Definition of done:**
- Output validates against the SARIF 2.1.0 schema (there are online
  validators and Python libraries for this -- don't hand-verify).
- `cli.py <target> --format sarif -o results.sarif` works, and that file
  uploads successfully via `github/codeql-action/upload-sarif` in a test
  workflow.

---

## 3. Pre-commit hook + `--staged`

**Why:** this is the other half of "how is this not redundant." GitHub's
push protection is prevention (the secret never reaches the remote); this
tool is currently detection-only (it tells you after the secret is already
committed). A pre-commit hook that only looks at staged changes closes that
gap, and it works even when the target repo has no relationship to GitHub at
all.

**Where to put it:**
- `cli.py` needs a `--staged` flag: when set, restrict the scan to files
  listed by `git diff --cached --name-only --diff-filter=ACM`, and only the
  *added* lines within them (`git diff --cached -U0` per file, same
  add/remove parsing `walker.py`'s `parseGitLogOutput` already does for
  history -- that parser is reusable here almost as-is).
- A new `.pre-commit-hooks.yaml` at the repo root, so this project is
  installable as a normal entry in someone else's
  `.pre-commit-config.yaml`:
  ```yaml
  - id: galicious-scanner
    name: Galicious Scanner (secrets)
    entry: python cli.py --staged --fail-on high
    language: python
    pass_filenames: false
  ```
- Exit code is already right for this (`exit_code()` / `--fail-on` exist and
  are tested) -- this feature is mostly about the staged-diff plumbing, not
  new scoring logic.

**Definition of done:**
- `git add` a file containing a fabricated AKIA-shaped key, commit, and
  confirm the hook blocks it with `--fail-on high` while an unrelated staged
  change is untouched.
- Works with no `--staged` (full-tree scan) and with it (staged-only), so
  existing CLI behavior doesn't regress.

---

## 4. Baseline / allowlist file

**Why:** `--fail-on` cannot currently be turned on for any repo that already
has existing findings -- there's no way to say "these N are accepted, fail
only on anything new." Every real codebase this tool would be pointed at has
some baseline noise (test fixtures with fake keys, an intentionally-committed
`.env.sample` with a placeholder that dodges the placeholder filter, etc).
Without this, the CI-gate feature that already exists is not usable in
practice.

**Where to put it:**
- New module `baseline.py` at the repo root (pairs naturally with
  `scorer_reporter.py`, no web dependency).
- A finding's identity for baselining purposes should be a stable fingerprint
  that survives line-number drift, the same reasoning `dedup.py` already
  uses for cross-commit matching: `sha256(file_path + detector_type +
  redacted)`. (Don't fingerprint on `line_number` -- it's the first thing
  that changes on an unrelated edit two lines above.)
- File format: newline-delimited fingerprints in `.sentrybaseline`
  (gitignore-adjacent, lives in the scanned repo, not this one), one per
  line, `#`-comments allowed -- mirror `.sentryignore`'s existing format for
  consistency.
- `filter_and_score` (or a thin wrapper in `cli.py`) drops any `ScoredFinding`
  whose fingerprint is in the loaded baseline before scoring/exit-code
  logic runs.
- `cli.py` needs `--baseline PATH` (load and filter) and
  `--update-baseline` (write the current findings' fingerprints to the file,
  the "accept everything found today" workflow).

**Definition of done:**
- A finding present in the baseline is fully suppressed from the report, not
  just downgraded.
- `--fail-on` + `--baseline` together only fail on findings NOT in the
  baseline.
- Regenerating the baseline after a legitimate fix shrinks it (i.e. fixed
  findings fall out rather than lingering as dead entries forever -- worth a
  `--prune-baseline` companion, or at least a warning listing stale entries).

---

## 5. Remediation guidance per finding

**Why:** the report already explains *why* a finding scored what it did
(`rationale`). It does not explain *what to do* beyond a generic "rotate
this" -- one-click fix (#0) covers the mechanical relocation for a handful of
languages, but plenty of findings aren't auto-fixable (history-only, `.pem`
files, unsupported languages) and get no guidance at all beyond that. This
is the highest-value-per-hour item on this list precisely because it's
mostly writing down what a human reviewer already knows, once, so nobody has
to re-derive it per finding.

**Where to put it:**
- `models.ScoredFinding` gets a new field, e.g.
  `remediation_steps: List[str]`.
- `scorer_reporter.py` gets a small lookup table keyed by `detector_type`
  (same shape as `_BASE_POINTS`), each entry a short ordered list of plain-
  language steps. Concrete starting content:
  - `AWS_ACCESS_KEY` / `AWS_SECRET_KEY`: deactivate in IAM -> issue a new key
    pair -> update the secret store -> confirm the old key shows zero usage
    in CloudTrail before deleting it.
  - `GITHUB_TOKEN`: revoke at github.com/settings/tokens -> reissue with the
    narrowest scopes that still work.
  - `STRIPE_KEY`: roll the key from the Stripe dashboard (does not require
    contacting support) -> update webhooks if the webhook secret was also
    exposed.
  - `SLACK_TOKEN` / `SLACK_WEBHOOK`: regenerate from the Slack app config
    page -> note that a webhook URL alone can post to the channel, so
    treat it as sensitive even though it isn't a token.
  - `PRIVATE_KEY_HEADER`: the key must be regenerated, not rotated -- a
    private key can't be partially invalidated. Reissue the certificate/key
    pair and redistribute the new public half.
  - `DB_CONNECTION_STRING`: rotate the DB user's password at the database,
    not just in config -- the connection string is only half the leak.
  - Generic fallback for anything else: rotate at the source, then confirm
    via `#3`/history-purge guidance if `in_history` is set.
- Render it in all three formats: a new line or two in `render_terminal`,
  a `remediation_steps` key in `render_json`'s dict output (already free,
  since `ScoredFinding.to_dict()` will pick it up), and a new section in the
  terminal detail panel (`web/terminal_assets.py`'s `open()` already has a
  `[!] remediation` header with just the rotation warning -- this is where
  the per-type steps would slot in, ahead of the existing rotation/history
  warnings).

**Definition of done:**
- Every detector type in `config/patterns.json` (plus `HIGH_ENTROPY` and the
  three `GENERIC_*` types) has at least one specific remediation line, not
  just the generic fallback.
- The existing rotation warning and (when `in_history`) the history-purge
  warning still appear -- this is additive, not a replacement.
