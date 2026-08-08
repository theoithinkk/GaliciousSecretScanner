"""
remediation.py
--------------
Roadmap #5: per-finding remediation guidance.

The report already says WHY a finding scored what it did (`rationale`). It did
not say WHAT TO DO about it beyond a generic "rotate this". The one-click fix
(web/fixer.py) covers the mechanical half for a handful of languages, but
plenty of findings aren't auto-fixable -- history-only ones, .pem files,
unsupported file types -- and those got no guidance at all.

Kept as its own module, and applied as a post-pass over the scored list rather
than inside filter_and_score(), for two reasons:

1. It is reference content, not scoring policy. Nothing here reads or changes a
   severity; mixing a lookup table of prose into the rubric would make the
   rubric harder to defend out loud, which is the one thing scorer_reporter.py
   is explicit about protecting.
2. A post-pass means scorer_reporter.py needs no edit at all. orchestrator.py
   calls annotate() once, so both entry points get it and neither can drift.

Steps are ordered: do them top to bottom. The rotation step comes first
everywhere it applies, because the code edit is the part that feels like
progress and the rotation is the part that actually ends the exposure.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Sequence

from models import ScoredFinding

# Keyed by detector_type. Every type in config/patterns.json is present, plus
# HIGH_ENTROPY, so nothing falls through to the generic advice unless a new
# pattern is added without a matching entry here.
_STEPS: Dict[str, Sequence[str]] = {
    "AWS_ACCESS_KEY": (
        "Deactivate this key in the IAM console (Users -> Security credentials).",
        "Issue a replacement key pair and update whatever consumes it.",
        "Check CloudTrail shows zero usage on the old key, THEN delete it.",
    ),
    "AWS_SECRET_KEY": (
        "Deactivate the matching access key in IAM -- the secret half is "
        "useless alone, but the pair is what leaked.",
        "Issue a replacement key pair and update whatever consumes it.",
        "Check CloudTrail shows zero usage on the old key, THEN delete it.",
    ),
    "GITHUB_TOKEN": (
        "Revoke the token at github.com/settings/tokens.",
        "Reissue it with the narrowest scopes that still work -- a leaked "
        "token is a good moment to notice it had more access than it needed.",
    ),
    "GOOGLE_API_KEY": (
        "Regenerate the key in the Google Cloud console (APIs & Services -> "
        "Credentials).",
        "Add an application restriction (HTTP referrer, IP, or app) and an API "
        "restriction, so the next leak is worth less than this one.",
    ),
    "STRIPE_KEY": (
        "Roll the key from the Stripe dashboard (Developers -> API keys). "
        "This does not require contacting support.",
        "If the webhook signing secret was in the same file, roll that too -- "
        "it is a separate credential and rolling the API key does not touch it.",
    ),
    "SLACK_TOKEN": (
        "Regenerate the token from the Slack app configuration page "
        "(OAuth & Permissions).",
        "Reinstall the app to the workspace so the old token is invalidated.",
    ),
    "SLACK_WEBHOOK": (
        "Regenerate the webhook URL from the Slack app configuration page.",
        "Treat the URL itself as the credential: anyone holding it can post to "
        "that channel, even though it isn't a token.",
    ),
    "PRIVATE_KEY_HEADER": (
        "Regenerate the key pair. A private key cannot be rotated in place or "
        "partially invalidated -- the old one is compromised permanently.",
        "Reissue any certificate signed with it and redistribute the new "
        "public half to everything that trusted the old one.",
        "Revoke the old certificate so a holder of the leaked key can't keep "
        "presenting it.",
    ),
    "DB_CONNECTION_STRING": (
        "Change the database user's password AT THE DATABASE, not just in "
        "config -- the connection string is only half the leak.",
        "Move the new credentials into environment variables or a secret store.",
        "If the host is reachable from outside, check access logs for "
        "connections you don't recognize.",
    ),
    "JWT": (
        "If this is a signed token, it stays valid until it expires -- rotate "
        "the SIGNING KEY so every token minted with it is invalidated.",
        "Shorten the token lifetime if it was long-lived; a leaked short-lived "
        "token is a much smaller problem.",
    ),
    "GENERIC_API_KEY": (
        "Identify which service this key belongs to, then revoke and reissue "
        "it there.",
        "Move the replacement into an environment variable or secret store "
        "rather than back into source.",
    ),
    "GENERIC_SECRET": (
        "Identify what this value authenticates, then rotate it at the source.",
        "Move the replacement into an environment variable or secret store "
        "rather than back into source.",
    ),
    "GENERIC_PASSWORD": (
        "Change the password on the account it belongs to.",
        "If this password was reused anywhere else, change it there too -- a "
        "hardcoded password is usually not unique.",
        "Move the replacement into an environment variable or secret store.",
    ),
    "HIGH_ENTROPY": (
        "Confirm this is actually a credential -- the entropy detector flags "
        "randomness, not a known format, so this may be a hash or an ID.",
        "If it is a credential, rotate it at whatever issued it.",
        "If it is NOT, add it to .sentrybaseline (--update-baseline) or "
        ".sentryignore so it stops appearing.",
    ),
}

_GENERIC: Sequence[str] = (
    "Rotate this credential at whatever issued it.",
    "Move the replacement into an environment variable or secret store "
    "rather than back into source.",
)

# Appended when the secret is reachable from git history. Editing the working
# tree does not remove a blob from history, and this is the single most common
# misunderstanding the tool exists to correct -- so it is stated as a step,
# not left as a warning somewhere else in the UI.
_HISTORY_STEPS: Sequence[str] = (
    "Purge the value from git history (git-filter-repo, or the BFG). Deleting "
    "the line in a new commit does NOT remove it -- the old blob stays "
    "reachable to anyone who clones.",
    "After rewriting history, everyone with a clone must re-clone: their local "
    "copies still contain the secret.",
)


def steps_for(detector_type: str, in_history: bool = False) -> List[str]:
    """
    Remediation steps for one finding, most important first.

    in_history adds the history-purge steps. It should be driven by
    ScoredFinding.in_history (does it exist in history at all), NOT by
    exposure == "history_only" -- a secret that is live AND committed needs
    the purge just as much as one that was deleted.
    """
    steps = list(_STEPS.get(detector_type, _GENERIC))
    if in_history:
        steps.extend(_HISTORY_STEPS)
    return steps


def annotate(scored: Iterable[ScoredFinding]) -> List[ScoredFinding]:
    """
    Fill in remediation_steps on each finding, in place, and return the list.

    Mutates rather than rebuilding because ScoredFinding is passed around by
    reference to the renderers; returning a copy would leave a caller holding
    the un-annotated originals.
    """
    listed = list(scored)
    for s in listed:
        s.remediation_steps = steps_for(s.detector_type, s.in_history)
    return listed