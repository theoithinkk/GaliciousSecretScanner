"""
web/html_report.py
-------------------
Renders the standalone HTML report page: the themed report with severity
tiles, sort/filter, and the clickable finding-detail terminal panel.

Split out of the root's reporters.py (which keeps only the terminal/json
renderers cli.py needs directly) so the repo root shows just the detection
engine and its CLI, with the browser-facing rendering tucked under web/.
scorer_reporter.generate_report() reaches in here with a lazy import only when
fmt="html" is requested, so nothing at the root has a hard dependency on this
module.

No output ever contains a full secret -- ScoredFinding only carries the
masked forms.
"""

from __future__ import annotations

import html
import json
from typing import List, Optional

from models import Severity, ScoredFinding
from web.report_assets import BASE_CSS, BASE_JS, REPORT_CSS, REPORT_JS
from web.terminal_assets import TERMINAL_CSS, TERMINAL_JS

try:
    from web.fixer import describe as _describe_fix
except ImportError:  # fixer is optional; the report still renders without it
    def _describe_fix(file_path, file_class, exposure):
        return False, "fixer module unavailable"


def _json_for_script(obj) -> str:
    """
    JSON safe to embed inside a <script> block.

    json.dumps escapes quotes and backslashes -- enough for a Windows path --
    but leaves `<` alone, so a target containing `</script>` would close the
    block early and everything after it would be parsed as HTML. Escaping the
    three HTML-significant characters as \\uXXXX keeps the value identical to
    JavaScript while making it inert to the HTML parser.
    """
    return (json.dumps(obj)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026"))


def _exposure_text(s: ScoredFinding) -> str:
    """Plain-language exposure, for the detail panel."""
    if s.exposure == "working_tree":
        if s.in_history:
            return (f"live in working tree, and in {len(s.history_commits)} "
                    f"commit(s) (from {s.history_commits[0]})")
        return "live in working tree, never committed"
    if len(s.history_commits) > 1:
        return f"git history only, {len(s.history_commits)} commits"
    return f"git history only (commit {s.commit_hash})"


def _finding_card(index: int, s: ScoredFinding, fix_enabled: bool) -> str:
    sev = s.severity.label.lower()
    live = s.exposure == "working_tree"
    exp_cls, exp_txt = ("live", "LIVE") if live else ("history", "HISTORY")
    ent_tag = ("" if s.entropy_score is None
               else f'<span class="ftag">entropy {s.entropy_score}</span>')
    # A live secret that is ALSO committed needs the history purged, not
    # just the line deleted -- call that out next to the LIVE tag.
    hist_tag = ('<span class="ftag history">+ in history</span>'
                if live and s.in_history else "")
    seen_tag = (f'<span class="ftag">x{s.occurrences}</span>'
                if s.occurrences > 1 else "")

    fixable, fix_reason = _describe_fix(s.file_path, s.file_class, s.exposure)

    return (
        f'<article class="finding {sev}" data-sev="{int(s.severity)}" '
        f'data-file="{html.escape(s.file_path, quote=True)}" '
        f'data-line="{s.line_number}" '
        f'data-type="{html.escape(s.detector_type, quote=True)}" '
        f'data-sevlabel="{s.severity.label}" data-points="{s.points}" '
        f'data-fileclass="{html.escape(s.file_class, quote=True)}" '
        f'data-exposure="{s.exposure}" '
        f'data-exposuretext="{html.escape(_exposure_text(s), quote=True)}" '
        f'data-redacted="{html.escape(s.redacted, quote=True)}" '
        f'data-context="{html.escape(s.redacted_context, quote=True)}" '
        f'data-rationale="{html.escape(s.rationale, quote=True)}" '
        f'data-entropy="{s.entropy_score or 0}" '
        f'data-inhistory="{"1" if s.in_history else "0"}" '
        f'data-fixable="{"1" if (fixable and fix_enabled) else "0"}" '
        f'data-fixreason="{html.escape(fix_reason, quote=True)}" '
        # remediation.annotate()'s steps, carried to the detail panel as-is so
        # the page can't disagree with the terminal and JSON reports.
        f'data-remediation="{html.escape(json.dumps(s.remediation_steps), quote=True)}" '
        f'data-ent="{s.entropy_score or 0}" '
        # Capped: uncapped, a 40-finding report animated for two seconds.
        f'style="animation-delay:{min(index, 10) * 0.03:.2f}s">'
        f'<div class="fhead">'
        f'<span class="badge {sev}">{s.severity.label.upper()}</span>'
        f'<span class="floc">{html.escape(s.file_path)}:{s.line_number}</span>'
        f'<span class="ftag {exp_cls}">{exp_txt}</span>'
        f'{hist_tag}{seen_tag}{ent_tag}'
        f'</div>'
        f'<div class="fbody">'
        f'<span class="fkey">secret</span>'
        f'<span class="fval secret">{html.escape(s.redacted)}</span>'
        f'<span class="fkey">type</span>'
        f'<span class="fval">{html.escape(s.detector_type)}</span>'
        f'<span class="fkey">context</span>'
        f'<span class="fval secret">{html.escape(s.redacted_context)}</span>'
        f'<span class="fkey">why</span>'
        f'<span class="fval why">{html.escape(s.rationale)}</span>'
        f'</div>'
        f'<span class="inspect">[ inspect ]</span>'
        f'</article>'
    )


def render_html(scored: List[ScoredFinding], target: str = "",
                fix_enabled: bool = False, fix_api: str = "/api/fix",
                home_url: Optional[str] = None, suppressed: int = 0) -> str:
    """
    Render the standalone report page.

    fix_enabled turns on the one-click fix in the detail panel. web/app.py
    passes True; cli.py leaves it False, because a report written to a file
    has no server behind it and a button that always failed would be worse
    than a button that explains why it isn't there.

    home_url adds a "new scan" link back to the form. It doubles as the
    "is a server behind this page" flag, which is what gates the export links
    and the accept-all button too -- both are HTTP calls, and a report opened
    from disk has nothing to call. It is kept separate from fix_enabled
    because web/app.py disables the fix for a GitHub-URL scan while still
    wanting the link.

    suppressed is how many findings a baseline dropped before rendering. It is
    stated on the page rather than left implicit: a scan that silently hides
    findings is exactly how a baseline masks a real regression.
    """
    served = home_url is not None
    counts = {sev: 0 for sev in Severity}
    for s in scored:
        counts[s.severity] += 1
    order = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)

    # Only real numbers here. Faking progress output in a security tool is a
    # habit worth not starting.
    boot_lines = [
        "> galicious :: scan complete",
        f"> {len(scored)} finding(s)  "
        f"[ {counts[Severity.CRITICAL]} CRIT / {counts[Severity.HIGH]} HIGH / "
        f"{counts[Severity.MEDIUM]} MED / {counts[Severity.LOW]} LOW ]",
        "> secrets: MASKED // rotate before you clean up",
    ]
    boot_html = "".join(
        f'<div class="ln" style="--w:{len(t)}ch;animation-delay:{i * 0.45:.2f}s">'
        f'{html.escape(t)}</div>'
        for i, t in enumerate(boot_lines)
    )

    cards = "".join(
        f'<div class="card {sev.label.lower()}" data-filter="{sev.label.lower()}">'
        f'<div class="n" data-target="{counts[sev]}">0</div>'
        f'<div class="l">{sev.label}</div></div>'
        for sev in order
    )

    findings_html = ("\n".join(_finding_card(i, s, fix_enabled)
                               for i, s in enumerate(scored))
                     or '<div class="empty">no secrets found // all clear '
                        '<span class="cursor"></span></div>')

    config = _json_for_script({"api": fix_api, "baselineApi": "/api/baseline",
                               "target": target, "fixEnabled": bool(fix_enabled)})

    # Export links and the accept-all button are server-backed, so they only
    # appear on the served page. The routes are web/app.py's; a saved report
    # gets neither rather than dead buttons.
    exports = (
        '<span class="sep"></span><span class="lbl">export //</span>'
        '<a class="sortbtn" href="/report.json" download>json</a>'
        '<a class="sortbtn" href="/report.sarif" download>sarif</a>'
        '<a class="sortbtn" href="/report.html" download>html</a>'
    ) if served else ''

    # Writing a baseline needs a local directory to write it into, which is
    # the same condition the one-click fix runs under -- a cloned GitHub URL
    # is deleted the moment the scan ends.
    baseline_btn = (
        f'<span class="sep"></span>'
        f'<button class="sortbtn" id="baselineBtn" data-count="{len(scored)}"'
        f'{" disabled" if not scored else ""}>accept all</button>'
    ) if (served and fix_enabled) else ''

    terminal = (
        '<div class="term" id="term" role="dialog" aria-modal="true" '
        'aria-label="finding details">'
        '<div class="term-win" id="termWin">'
        '<div class="term-bar">'
        '<span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>'
        '<span class="term-title" id="termTitle">galicious://</span>'
        '<button class="term-x" id="termX" aria-label="close">ESC</button>'
        '</div>'
        '<div class="term-body" id="termBody"></div>'
        '<div class="term-scan"></div>'
        '</div></div>'
    )

    # Only rendered when a server is behind the page. A report written to disk
    # by `cli.py --format html` has nowhere to navigate back to.
    home_link = (f'<a class="homebtn" href="{html.escape(home_url, quote=True)}">'
                 '&larr; new scan</a>' if home_url else '')

    return (
        '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>GALICIOUS SCANNER</title>'
        '<style>' + BASE_CSS + REPORT_CSS + TERMINAL_CSS + '</style>'
        '</head><body>'
        '<canvas id="matrix"></canvas><div class="scanlines"></div>'
        '<main>'
        + home_link
        + f'<div class="boot">{boot_html}</div>'
        '<h1 class="glitch" data-text="GALICIOUS SCANNER">GALICIOUS SCANNER</h1>'
        '<div class="sub">threat scan report <span class="cursor"></span></div>'
        + (f'<div class="target-line">> target: {html.escape(target)}</div>' if target else '')
        + (f'<div class="suppressed-line">> {suppressed} finding(s) suppressed by '
           f'.sentrybaseline</div>' if suppressed else '')
        + f'<div class="cards">{cards}</div>'
        '<div class="toolbar"><span class="lbl">sort //</span>'
        '<button class="sortbtn active" data-sort="sev">severity</button>'
        '<button class="sortbtn" data-sort="file">file</button>'
        '<button class="sortbtn" data-sort="ent">entropy</button>'
        + exports + baseline_btn
        + f'<span class="count"><b id="shown">{len(scored)}</b> shown '
        '&middot; click a tile to filter &middot; click a finding to inspect</span></div>'
        f'<div class="findings" id="findings">{findings_html}</div>'
        '<footer>[ secrets masked ] rotate flagged credentials, then purge from source + history '
        '<span class="cursor"></span></footer>'
        '</main>'
        + terminal
        + f'<script>window.SENTRY={config};</script>'
        + '<script>' + BASE_JS + REPORT_JS + TERMINAL_JS + '</script>'
        '</body></html>'
    )
