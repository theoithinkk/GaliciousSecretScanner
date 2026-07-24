"""
reporters.py
takes scored findings and renders them: terminal, json, or the themed
html report. split out of scorer_reporter.py so the html/css/js all sits
in one place and the scoring logic stays readable. no output ever contains
a full secret -- ScoredFinding only carries the masked forms.
"""

from __future__ import annotations

import html
import json
import os
import sys
from typing import List, Optional

from models import Severity, ScoredFinding


# terminal renderer
_ANSI = {
    Severity.CRITICAL: "\033[1;35m",  # bold magenta
    Severity.HIGH:     "\033[1;31m",  # bold red
    Severity.MEDIUM:   "\033[1;33m",  # bold yellow
    Severity.LOW:      "\033[36m",    # cyan
}
_RESET = "\033[0m"
_DIM = "\033[2m"


def _enable_windows_ansi() -> None:
    if os.name != "nt":
        return
    try:  # turn on VT processing so ANSI colors render in cmd/PowerShell
        import ctypes
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
    except Exception:
        pass


def render_terminal(scored: List[ScoredFinding], use_color: Optional[bool]) -> str:
    if use_color is None:
        use_color = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    if use_color:
        _enable_windows_ansi()

    if not scored:
        return "No secrets found (after placeholder filtering)."

    counts = {}
    for s in scored:
        counts[s.severity] = counts.get(s.severity, 0) + 1
    summary = "  ".join(
        f"{sev.label}: {counts.get(sev, 0)}"
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    )

    lines = [f"Secret scan: {len(scored)} finding(s)", summary, ""]
    for s in scored:
        tag = f"[{s.severity.label.upper():8}]"
        if use_color:
            tag = f"{_ANSI[s.severity]}{tag}{_RESET}"
        loc = f"{s.file_path}:{s.line_number}"
        exposure = "LIVE" if s.exposure == "working_tree" else "history"
        head = f"{tag} {loc}  ({s.detector_type}, {exposure})"
        dim0 = _DIM if use_color else ""
        dim1 = _RESET if use_color else ""
        body = f"    {s.redacted}   {dim0}{s.redacted_context}{dim1}"
        why = f"    {dim0}-> {s.rationale}{dim1}"
        lines += [head, body, why, ""]
    return "\n".join(lines)


# json renderer
def render_json(scored: List[ScoredFinding]) -> str:
    return json.dumps([s.to_dict() for s in scored], indent=2)


# html renderer
# CSS/JS are plain (non-f) strings so all the braces stay literal -- only the
# rows/cards below are f-strings. Everything is inline: no CDNs, no web fonts,
# so the report opens offline from a file:// path. Animations respect
# prefers-reduced-motion.
_HTML_CSS = """<style>
  * { box-sizing: border-box; }
  :root {
    --bg:#05070a; --panel:rgba(10,16,20,.72); --grid:rgba(0,255,156,.10);
    --green:#00ff9c; --text:#9df5c4; --muted:#4d6b5c;
    --crit:#ff2d6e; --high:#ff6a3c; --med:#ffd23a; --low:#28c8ff;
    --mono: ui-monospace,'Cascadia Code','JetBrains Mono','Fira Code',Consolas,monospace;
  }
  html,body { margin:0; background:var(--bg); color:var(--text); font-family:var(--mono); }
  body { min-height:100vh; padding:1.4rem clamp(.9rem,4vw,3rem); position:relative; overflow-x:hidden; }
  #matrix { position:fixed; inset:0; z-index:0; opacity:.13; pointer-events:none; }
  .scanlines { position:fixed; inset:0; z-index:3; pointer-events:none; overflow:hidden;
    background:repeating-linear-gradient(to bottom, transparent 0 2px, rgba(0,0,0,.28) 2px 4px);
    animation:flicker 4s infinite steps(60); }
  .scanlines::after { content:''; position:absolute; left:0; right:0; height:140px; top:-140px;
    background:linear-gradient(rgba(0,255,156,0), rgba(0,255,156,.07), rgba(0,255,156,0));
    animation:scan 7s linear infinite; }
  @keyframes scan { to { top:100%; } }
  @keyframes flicker { 0%,88%,100%{opacity:1;} 89%{opacity:.72;} 91%{opacity:1;} 93%{opacity:.85;} }
  main { position:relative; z-index:1; max-width:1120px; margin:0 auto; }
  .boot { color:var(--green); font-size:.78rem; line-height:1.7; margin-bottom:1.1rem;
    text-shadow:0 0 6px rgba(0,255,156,.5); }
  .boot .ln { white-space:nowrap; overflow:hidden; width:0; max-width:100%;
    animation:type .5s steps(40,end) forwards; }
  @keyframes type { to { width:var(--w); } }
  h1 { font-size:clamp(1.5rem,5vw,2.6rem); letter-spacing:.22em; margin:.1rem 0 .1rem;
    color:var(--green); position:relative; text-shadow:0 0 14px rgba(0,255,156,.55); }
  .glitch::before, .glitch::after { content:attr(data-text); position:absolute; left:0; top:0;
    width:100%; overflow:hidden; }
  .glitch::before { color:var(--crit); animation:glitch1 2.6s infinite linear alternate-reverse; }
  .glitch::after  { color:var(--low);  animation:glitch2 3.4s infinite linear alternate-reverse; }
  @keyframes glitch1 { 0%,94%,100%{clip-path:inset(0 0 100% 0);transform:translate(0);}
    95%{clip-path:inset(10% 0 60% 0);transform:translate(-2px,-1px);}
    97%{clip-path:inset(40% 0 20% 0);transform:translate(2px,1px);} }
  @keyframes glitch2 { 0%,92%,100%{clip-path:inset(0 0 100% 0);transform:translate(0);}
    93%{clip-path:inset(70% 0 10% 0);transform:translate(2px,0);}
    96%{clip-path:inset(20% 0 55% 0);transform:translate(-2px,1px);} }
  .sub { color:var(--muted); letter-spacing:.35em; text-transform:uppercase; font-size:.72rem;
    margin-bottom:1.4rem; }
  .cursor { display:inline-block; width:.55ch; height:1em; vertical-align:-.12em;
    background:var(--green); box-shadow:0 0 8px var(--green); animation:blink 1.05s steps(1) infinite; }
  @keyframes blink { 50%{opacity:0;} }
  /* severity tiles double as clickable filters */
  .cards { display:grid; grid-template-columns:repeat(4,1fr); gap:.7rem; margin-bottom:1.4rem; }
  .card { position:relative; padding:.75rem 1.1rem; background:var(--panel); cursor:pointer;
    border:1px solid var(--grid); border-left-width:3px; backdrop-filter:blur(2px);
    user-select:none; transition:transform .12s, box-shadow .15s, opacity .15s;
    clip-path:polygon(0 0,100% 0,100% 72%,calc(100% - 12px) 100%,0 100%); }
  .card:hover { transform:translateY(-2px); }
  .card.active { box-shadow:0 0 0 1px currentColor, 0 0 16px rgba(0,255,156,.22); }
  .card.dim { opacity:.32; }
  .card .n { font-size:2rem; font-weight:700; line-height:1; text-shadow:0 0 12px currentColor; }
  .card .l { font-size:.66rem; letter-spacing:.18em; text-transform:uppercase; color:var(--muted);
    margin-top:.25rem; }
  .card.critical { border-left-color:var(--crit); } .card.critical .n { color:var(--crit); }
  .card.high { border-left-color:var(--high); } .card.high .n { color:var(--high); }
  .card.medium { border-left-color:var(--med); } .card.medium .n { color:var(--med); }
  .card.low { border-left-color:var(--low); } .card.low .n { color:var(--low); }
  /* sort / filter toolbar */
  .toolbar { display:flex; align-items:center; gap:.5rem; flex-wrap:wrap; margin-bottom:1rem;
    font-size:.7rem; color:var(--muted); letter-spacing:.1em; }
  .toolbar .lbl { text-transform:uppercase; }
  .sortbtn { font:inherit; font-size:.68rem; color:var(--muted); background:transparent;
    cursor:pointer; border:1px solid var(--grid); padding:.3rem .75rem; border-radius:2px;
    letter-spacing:.09em; text-transform:uppercase; transition:color .15s,border-color .15s,box-shadow .15s; }
  .sortbtn:hover { color:var(--text); border-color:var(--green); }
  .sortbtn.active { color:var(--green); border-color:var(--green);
    box-shadow:inset 0 0 10px rgba(0,255,156,.25); }
  .toolbar .count { margin-left:auto; text-transform:uppercase; }
  .toolbar .count b { color:var(--green); }
  /* finding cards */
  .findings { display:flex; flex-direction:column; gap:.55rem; }
  .finding { position:relative; background:var(--panel); border:1px solid var(--grid);
    border-left:3px solid var(--muted); padding:.7rem .95rem .8rem; backdrop-filter:blur(2px);
    opacity:0; transform:translateY(8px); animation:reveal .4s ease forwards; }
  @keyframes reveal { to { opacity:1; transform:translateY(0); } }
  .finding.critical { border-left-color:var(--crit); }
  .finding.high { border-left-color:var(--high); }
  .finding.medium { border-left-color:var(--med); }
  .finding.low { border-left-color:var(--low); }
  .finding:hover { border-color:rgba(0,255,156,.4); box-shadow:0 0 20px rgba(0,255,156,.07); }
  .finding.hide { display:none; }
  .fhead { display:flex; align-items:center; gap:.55rem; flex-wrap:wrap; margin-bottom:.55rem; }
  .floc { color:#e9fff4; font-weight:700; letter-spacing:.03em; }
  .ftag { font-size:.63rem; letter-spacing:.1em; text-transform:uppercase; color:var(--muted);
    border:1px solid var(--grid); padding:.08rem .45rem; border-radius:2px; }
  .ftag.live { color:var(--high); border-color:rgba(255,106,60,.4); }
  .ftag.history { color:var(--low); border-color:rgba(40,200,255,.35); }
  .fbody { display:grid; grid-template-columns:5.5rem 1fr; gap:.22rem .8rem; font-size:.8rem; }
  .fkey { color:var(--muted); text-transform:uppercase; font-size:.63rem; letter-spacing:.1em;
    padding-top:.18rem; }
  .fval { color:var(--text); word-break:break-all; }
  .fval.secret { color:#e9fff4; letter-spacing:.05em; }
  .fval.why { color:var(--muted); line-height:1.5; word-break:normal; }
  .empty { padding:2.5rem; text-align:center; color:var(--muted); letter-spacing:.1em;
    border:1px dashed var(--grid); }
  .badge { display:inline-block; padding:.12rem .55rem; font-size:.66rem; font-weight:700;
    letter-spacing:.1em; border:1px solid currentColor; border-radius:2px; }
  .badge.critical { color:var(--crit); animation:pulse 1.2s ease-in-out infinite; }
  .badge.high { color:var(--high); } .badge.medium { color:var(--med); } .badge.low { color:var(--low); }
  @keyframes pulse { 0%,100%{box-shadow:0 0 0 rgba(255,45,110,0);} 50%{box-shadow:0 0 10px rgba(255,45,110,.8);} }
  footer { margin-top:1.6rem; color:var(--muted); font-size:.72rem; letter-spacing:.06em; }
  /* smooth, themed scrolling */
  html { scroll-behavior:smooth; }
  * { scrollbar-width:thin; scrollbar-color:rgba(0,255,156,.4) transparent; }
  ::-webkit-scrollbar { width:10px; }
  ::-webkit-scrollbar-track { background:transparent; }
  ::-webkit-scrollbar-thumb { background:rgba(0,255,156,.28); border:2px solid transparent;
    background-clip:padding-box; }
  ::-webkit-scrollbar-thumb:hover { background:rgba(0,255,156,.55); background-clip:padding-box; }
  @media (max-width:560px) {
    .cards { grid-template-columns:repeat(2,1fr); }
    .fbody { grid-template-columns:1fr; gap:.05rem; } .fkey { padding-top:.4rem; }
  }
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation:none !important; scroll-behavior:auto; }
    .boot .ln { width:auto; } .finding { opacity:1; transform:none; }
  }
</style>"""

_HTML_JS = """<script>
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Matrix rain backdrop.
  (function () {
    const c = document.getElementById('matrix'); if (!c || reduce) return;
    const x = c.getContext('2d');
    const glyphs = '01ｱｲｳｴｵｶｷｸｹｺｻｼｽ<>[]{}#$%&*=+/\\\\';
    let w, h, cols, drops;
    function size() { w = c.width = innerWidth; h = c.height = innerHeight;
      cols = Math.floor(w / 14); drops = new Array(cols).fill(1); }
    size(); addEventListener('resize', size);
    setInterval(function () {
      x.fillStyle = 'rgba(5,7,10,0.09)'; x.fillRect(0, 0, w, h);
      x.fillStyle = '#00ff9c'; x.font = '13px monospace';
      for (let i = 0; i < drops.length; i++) {
        const ch = glyphs[Math.floor(Math.random() * glyphs.length)];
        x.fillText(ch, i * 14, drops[i] * 14);
        if (drops[i] * 14 > h && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      }
    }, 55);
  })();

  // Count-up on the severity tiles.
  document.querySelectorAll('.card .n').forEach(function (el) {
    const t = +el.dataset.target;
    if (reduce || !t) { el.textContent = t; return; }
    let n = 0; const step = Math.max(1, Math.ceil(t / 18));
    const id = setInterval(function () {
      n += step; if (n >= t) { n = t; clearInterval(id); } el.textContent = n;
    }, 45);
  });

  // Findings list: sort buttons + click-a-tile-to-filter.
  const list = document.getElementById('findings');
  const shownEl = document.getElementById('shown');
  const items = function () { return [...list.querySelectorAll('.finding')]; };
  function refreshCount() {
    if (shownEl) shownEl.textContent = items().filter(function (f) {
      return !f.classList.contains('hide'); }).length;
  }

  document.querySelectorAll('.sortbtn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      document.querySelectorAll('.sortbtn').forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      const key = btn.dataset.sort;
      items().sort(function (a, b) {
        if (key === 'file') return a.dataset.file.localeCompare(b.dataset.file);
        if (key === 'ent') return (+b.dataset.ent) - (+a.dataset.ent);
        return (+b.dataset.sev) - (+a.dataset.sev);   // severity, worst first
      }).forEach(function (f) { list.appendChild(f); });
    });
  });

  let active = null;
  document.querySelectorAll('.card').forEach(function (card) {
    card.addEventListener('click', function () {
      const f = card.dataset.filter;
      active = (active === f) ? null : f;
      document.querySelectorAll('.card').forEach(function (c) {
        c.classList.toggle('active', active === c.dataset.filter);
        c.classList.toggle('dim', active && active !== c.dataset.filter);
      });
      items().forEach(function (it) {
        it.classList.toggle('hide', active && !it.classList.contains(active));
      });
      refreshCount();
    });
  });
</script>"""


def render_html(scored: List[ScoredFinding]) -> str:
    counts = {sev: 0 for sev in Severity}
    for s in scored:
        counts[s.severity] += 1
    order = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)

    # boot log header, typed out line by line. char length drives the
    # per-line typing width (--w).
    boot_lines = [
        "> secretsentry :: initializing scan engine",
        "> loading signature library ............. [ OK ]",
        "> decrypting findings ................... [ OK ]",
        f"> {len(scored)} threat(s) identified  "
        f"[ {counts[Severity.CRITICAL]} CRIT / {counts[Severity.HIGH]} HIGH / "
        f"{counts[Severity.MEDIUM]} MED / {counts[Severity.LOW]} LOW ]",
        "> render: html // secrets: MASKED // status: LOCKED",
    ]
    boot_html = "".join(
        f'<div class="ln" style="--w:{len(t)}ch;animation-delay:{i * 0.45:.2f}s">'
        f'{html.escape(t)}</div>'
        for i, t in enumerate(boot_lines)
    )

    # tiles carry data-filter so a click filters the list to that severity.
    cards = "".join(
        f'<div class="card {sev.label.lower()}" data-filter="{sev.label.lower()}">'
        f'<div class="n" data-target="{counts[sev]}">0</div>'
        f'<div class="l">{sev.label}</div></div>'
        for sev in order
    )

    findings = []
    for i, s in enumerate(scored):
        sev = s.severity.label.lower()
        live = s.exposure == "working_tree"
        exp_cls, exp_txt = ("live", "LIVE") if live else ("history", "HISTORY")
        ent_tag = ("" if s.entropy_score is None
                   else f'<span class="ftag">entropy {s.entropy_score}</span>')
        findings.append(
            f'<article class="finding {sev}" data-sev="{int(s.severity)}" '
            f'data-file="{html.escape(s.file_path)}" data-ent="{s.entropy_score or 0}" '
            f'style="animation-delay:{i * 0.05:.2f}s">'
            f'<div class="fhead">'
            f'<span class="badge {sev}">{s.severity.label.upper()}</span>'
            f'<span class="floc">{html.escape(s.file_path)}:{s.line_number}</span>'
            f'<span class="ftag {exp_cls}">{exp_txt}</span>{ent_tag}'
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
            f'</div></article>'
        )
    findings_html = ("\n".join(findings)
                     or '<div class="empty">no secrets found // all clear '
                        '<span class="cursor"></span></div>')

    return (
        '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>SECRETSENTRY // scan report</title>'
        + _HTML_CSS +
        '</head><body>'
        '<canvas id="matrix"></canvas><div class="scanlines"></div>'
        '<main>'
        f'<div class="boot">{boot_html}</div>'
        '<h1 class="glitch" data-text="SECRETSENTRY">SECRETSENTRY</h1>'
        '<div class="sub">threat scan report <span class="cursor"></span></div>'
        f'<div class="cards">{cards}</div>'
        '<div class="toolbar"><span class="lbl">sort //</span>'
        '<button class="sortbtn active" data-sort="sev">severity</button>'
        '<button class="sortbtn" data-sort="file">file</button>'
        '<button class="sortbtn" data-sort="ent">entropy</button>'
        f'<span class="count"><b id="shown">{len(scored)}</b> shown '
        '&middot; click a tile to filter</span></div>'
        f'<div class="findings" id="findings">{findings_html}</div>'
        '<footer>[ secrets masked ] rotate flagged credentials, then purge from source + history '
        '<span class="cursor"></span></footer>'
        '</main>'
        + _HTML_JS +
        '</body></html>'
    )
