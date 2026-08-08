"""
report_assets.py
----------------
The CSS and JS for the browser-facing pages, split out of the renderers so
those files stay about structure rather than being 90% stylesheet.

Everything here is inline by design: no CDNs, no web fonts, no external
requests, so a saved report still opens correctly from a file:// path with no
network. Animations are all gated behind prefers-reduced-motion.

Four constants, two audiences:

    BASE_CSS / BASE_JS      the shared chrome -- colour palette, matrix-rain
                            canvas, scanline overlay, boot lines, glitch
                            title, blinking cursor, scrollbars. Used by BOTH
                            the scan form (web/templates/index.html) and the
                            report page.
    REPORT_CSS / REPORT_JS  the report page only: severity tiles, the findings
                            list, sort and filter, the back-to-form link.

The base split exists because the form page used to carry its own hand-
maintained copy of all of that, and the two had already drifted apart (title
scale, page width). One copy means the form and the report cannot end up
looking like two different products.

The finding-detail terminal panel lives in terminal_assets.py. All of these
land in one <style> block, so a rule may sit in either file -- the split is
about ownership and file length, not cascade scoping.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Shared chrome. Anything a page can't be recognisably "Galicious" without.
# ---------------------------------------------------------------------------

BASE_CSS = """
  * { box-sizing: border-box; }
  :root {
    --bg:#05070a; --panel:rgba(10,16,20,.72); --grid:rgba(0,255,156,.10);
    --green:#00ff9c; --text:#dff3e9; --muted:#a8c4b6;
    --crit:#ff2d6e; --high:#ff6a3c; --med:#ffd23a; --low:#28c8ff;
    --mono: ui-monospace,'Cascadia Code','JetBrains Mono','Fira Code',Consolas,monospace;

    /* Four type steps, nothing in between. The pages used to carry eleven
       sizes, several of them 0.02rem apart, which reads as drift rather than
       hierarchy. xs is labels and tags, sm is prose, md is controls.

       Body text is near-white rather than the old saturated mint, and not
       pure white: on a near-black background #fff blooms, and the mint was
       already 15:1 on contrast, so what hurt legibility at 12px was the
       36%% saturation, not the brightness. */
    --fs-xs:.82rem; --fs-sm:.9rem; --fs-md:1rem; --fs-lg:1.1rem;

    /* One grid gap and one box padding, shared by the form and the report so
       the two line up instead of each inventing its own spacing. */
    --gap:1rem; --pad:1.15rem;
  }
  html,body { margin:0; background:var(--bg); color:var(--text); font-family:var(--mono); }
  html { scroll-behavior:smooth; }
  body { min-height:100vh; padding:1.4rem clamp(.9rem,4vw,3rem); position:relative; overflow-x:hidden; }
  main { position:relative; z-index:1; margin:0 auto; }
  #matrix { position:fixed; inset:0; z-index:0; opacity:.13; pointer-events:none; }
  .scanlines { position:fixed; inset:0; z-index:3; pointer-events:none; overflow:hidden;
    background:repeating-linear-gradient(to bottom, transparent 0 2px, rgba(0,0,0,.28) 2px 4px);
    animation:flicker 4s infinite steps(60); }
  .scanlines::after { content:''; position:absolute; left:0; right:0; height:140px; top:-140px;
    background:linear-gradient(rgba(0,255,156,0), rgba(0,255,156,.07), rgba(0,255,156,0));
    animation:scan 7s linear infinite; }
  @keyframes scan { to { top:100%; } }
  @keyframes flicker { 0%,88%,100%{opacity:1;} 89%{opacity:.72;} 91%{opacity:1;} 93%{opacity:.85;} }

  .boot { color:var(--green); font-size:var(--fs-sm); line-height:1.7; margin-bottom:1.1rem;
    text-shadow:0 0 6px rgba(0,255,156,.5); }
  .boot .ln { white-space:nowrap; overflow:hidden; width:0; max-width:100%;
    animation:type .5s steps(40,end) forwards; }
  @keyframes type { to { width:var(--w); } }

  /* Size and letter-spacing are deliberately absent: the form's title and the
     report's are set at different scales, and each page overrides them after
     this block. */
  h1 { margin:.1rem 0 .1rem; color:var(--green); position:relative;
    text-shadow:0 0 14px rgba(0,255,156,.55); word-break:break-word; }
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
  .sub { color:var(--muted); letter-spacing:.35em; text-transform:uppercase; font-size:var(--fs-xs);
    margin-bottom:1.4rem; }
  .cursor { display:inline-block; width:.55ch; height:1em; vertical-align:-.12em;
    background:var(--green); box-shadow:0 0 8px var(--green); animation:blink 1.05s steps(1) infinite; }
  @keyframes blink { 50%{opacity:0;} }

  footer { margin-top:1.6rem; color:var(--muted); font-size:var(--fs-xs); letter-spacing:.06em; }

  * { scrollbar-width:thin; scrollbar-color:rgba(0,255,156,.4) transparent; }
  ::-webkit-scrollbar { width:10px; }
  ::-webkit-scrollbar-track { background:transparent; }
  ::-webkit-scrollbar-thumb { background:rgba(0,255,156,.28); border:2px solid transparent;
    background-clip:padding-box; }
  ::-webkit-scrollbar-thumb:hover { background:rgba(0,255,156,.55); background-clip:padding-box; }

  /* Pages add their own entries to this block for elements only they have. */
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation:none !important; scroll-behavior:auto; }
    .boot .ln { width:auto; }
  }
"""

# `reduce` is declared here and read by REPORT_JS and TERMINAL_JS, which are
# concatenated after it into the same <script> block.
BASE_JS = """
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;

  (function () {
    const c = document.getElementById('matrix'); if (!c || reduce) return;
    const x = c.getContext('2d');
    const glyphs = '01\\u30a2\\u30a4\\u30a6\\u30a8\\u30aa\\u30ab\\u30ad\\u30af<>[]{}#$%&*=+/\\\\';
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
"""


# ---------------------------------------------------------------------------
# The report page itself.
# ---------------------------------------------------------------------------

REPORT_CSS = """
  main { max-width:1120px; }
  h1 { font-size:clamp(1.5rem,5vw,2.6rem); letter-spacing:.22em; }
  /* Back to the scan form. Sticky rather than fixed so it scrolls with the
     page on small screens instead of covering the findings. */
  .homebtn { position:sticky; top:.6rem; float:right; z-index:5; display:inline-block;
    font-size:var(--fs-xs); letter-spacing:.14em; text-transform:uppercase; text-decoration:none;
    color:var(--muted); background:var(--panel); border:1px solid var(--grid);
    border-radius:2px; padding:.42rem .9rem; backdrop-filter:blur(3px);
    transition:color .15s, border-color .15s, box-shadow .15s; }
  .homebtn:hover { color:var(--green); border-color:var(--green);
    box-shadow:0 0 14px rgba(0,255,156,.22); }
  .homebtn:focus-visible { outline:1px solid var(--green); outline-offset:2px; }
  .target-line { color:var(--green); font-size:var(--fs-xs); letter-spacing:.05em; margin:-1rem 0 1.4rem;
    word-break:break-all; text-shadow:0 0 6px rgba(0,255,156,.35); }
  .suppressed-line { color:var(--muted); font-size:var(--fs-xs); letter-spacing:.06em;
    margin:-1.1rem 0 1.4rem; }
  .cards { display:grid; grid-template-columns:repeat(4,1fr); gap:var(--gap); margin-bottom:1.6rem; }
  .card { position:relative; padding:1rem var(--pad); background:var(--panel); cursor:pointer;
    border:1px solid var(--grid); border-left-width:3px; backdrop-filter:blur(2px);
    user-select:none; transition:transform .12s, box-shadow .15s, opacity .15s;
    clip-path:polygon(0 0,100% 0,100% 72%,calc(100% - 12px) 100%,0 100%); }
  .card:hover { transform:translateY(-2px); }
  .card.active { box-shadow:0 0 0 1px currentColor, 0 0 16px rgba(0,255,156,.22); }
  .card.dim { opacity:.32; }
  .card .n { font-size:2rem; font-weight:700; line-height:1; text-shadow:0 0 12px currentColor; }
  .card .l { font-size:var(--fs-xs); letter-spacing:.18em; text-transform:uppercase; color:var(--muted);
    margin-top:.25rem; }
  .card.critical { border-left-color:var(--crit); } .card.critical .n { color:var(--crit); }
  .card.high { border-left-color:var(--high); } .card.high .n { color:var(--high); }
  .card.medium { border-left-color:var(--med); } .card.medium .n { color:var(--med); }
  .card.low { border-left-color:var(--low); } .card.low .n { color:var(--low); }
  .toolbar { display:flex; align-items:center; gap:.55rem; flex-wrap:wrap; margin-bottom:1.2rem;
    font-size:var(--fs-xs); color:var(--muted); letter-spacing:.1em; }
  .toolbar .lbl { text-transform:uppercase; }
  .sortbtn { font:inherit; font-size:var(--fs-xs); color:var(--muted); background:transparent;
    cursor:pointer; border:1px solid var(--grid); padding:.4rem .9rem; border-radius:2px;
    letter-spacing:.09em; text-transform:uppercase; text-decoration:none; display:inline-block;
    transition:color .15s,border-color .15s,box-shadow .15s; }
  .sortbtn:hover { color:var(--text); border-color:var(--green); }
  .sortbtn.active { color:var(--green); border-color:var(--green);
    box-shadow:inset 0 0 10px rgba(0,255,156,.25); }
  .sortbtn:disabled { opacity:.45; cursor:default; }
  .toolbar .sep { width:1px; height:1.1rem; background:var(--grid); margin:0 .2rem; }
  .toolbar .count { margin-left:auto; text-transform:uppercase; }
  .toolbar .count b { color:var(--green); }
  .findings { display:flex; flex-direction:column; gap:.7rem; }
  .finding { position:relative; background:var(--panel); border:1px solid var(--grid);
    border-left:3px solid var(--muted); padding:1rem var(--pad) 1.1rem; backdrop-filter:blur(2px);
    opacity:0; transform:translateY(8px); animation:reveal .4s ease forwards;
    cursor:pointer; transition:border-color .15s, box-shadow .15s, transform .1s; }
  @keyframes reveal { to { opacity:1; transform:translateY(0); } }
  .finding.critical { border-left-color:var(--crit); }
  .finding.high { border-left-color:var(--high); }
  .finding.medium { border-left-color:var(--med); }
  .finding.low { border-left-color:var(--low); }
  .finding:hover { border-color:rgba(0,255,156,.4); box-shadow:0 0 20px rgba(0,255,156,.07); }
  .finding:focus-visible { outline:1px solid var(--green); outline-offset:2px; }
  .finding.hide { display:none; }
  .finding.fixed { opacity:.5; border-left-color:var(--green); }
  .finding .inspect { position:absolute; right:.8rem; bottom:.65rem; font-size:var(--fs-xs);
    letter-spacing:.14em; text-transform:uppercase; color:var(--muted); pointer-events:none; }
  .finding:hover .inspect { color:var(--green); text-shadow:0 0 8px rgba(0,255,156,.6); }
  .fhead { display:flex; align-items:center; gap:.6rem; flex-wrap:wrap; margin-bottom:.75rem; }
  .floc { color:var(--text); font-weight:700; letter-spacing:.03em; }
  .ftag { font-size:var(--fs-xs); letter-spacing:.1em; text-transform:uppercase; color:var(--muted);
    border:1px solid var(--grid); padding:.15rem .55rem; border-radius:2px; }
  .ftag.live { color:var(--high); border-color:rgba(255,106,60,.4); }
  .ftag.history { color:var(--low); border-color:rgba(40,200,255,.35); }
  .ftag.fixedtag { color:var(--green); border-color:rgba(0,255,156,.45); }
  .fbody { display:grid; grid-template-columns:6.5rem 1fr; gap:.42rem 1rem; font-size:var(--fs-sm); }
  .fkey { color:var(--muted); text-transform:uppercase; font-size:var(--fs-xs); letter-spacing:.1em;
    padding-top:.18rem; }
  .fval { color:var(--text); word-break:break-all; }
  .fval.secret { color:var(--text); letter-spacing:.05em; }
  .fval.why { color:var(--muted); line-height:1.65; word-break:normal; }
  .empty { padding:2.5rem; text-align:center; color:var(--muted); letter-spacing:.1em;
    border:1px dashed var(--grid); }
  .badge { display:inline-block; padding:.2rem .65rem; font-size:var(--fs-xs); font-weight:700;
    letter-spacing:.1em; border:1px solid currentColor; border-radius:2px; }
  .badge.critical { color:var(--crit); animation:pulse 1.2s ease-in-out infinite; }
  .badge.high { color:var(--high); } .badge.medium { color:var(--med); } .badge.low { color:var(--low); }
  @keyframes pulse { 0%,100%{box-shadow:0 0 0 rgba(255,45,110,0);} 50%{box-shadow:0 0 10px rgba(255,45,110,.8);} }
  @media (max-width:560px) {
    .cards { grid-template-columns:repeat(2,1fr); }
    .fbody { grid-template-columns:1fr; gap:.05rem; } .fkey { padding-top:.4rem; }
  }
  @media (prefers-reduced-motion: reduce) { .finding { opacity:1; transform:none; } }
"""

REPORT_JS = """
  document.querySelectorAll('.card .n').forEach(function (el) {
    const t = +el.dataset.target;
    if (reduce || !t) { el.textContent = t; return; }
    let n = 0; const step = Math.max(1, Math.ceil(t / 18));
    const id = setInterval(function () {
      n += step; if (n >= t) { n = t; clearInterval(id); } el.textContent = n;
    }, 45);
  });

  const list = document.getElementById('findings');
  const shownEl = document.getElementById('shown');
  const items = function () { return [...list.querySelectorAll('.finding')]; };
  function refreshCount() {
    if (shownEl) shownEl.textContent = items().filter(function (f) {
      return !f.classList.contains('hide'); }).length;
  }

  document.querySelectorAll('.sortbtn[data-sort]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      document.querySelectorAll('.sortbtn[data-sort]').forEach(function (b) {
        b.classList.remove('active'); });
      btn.classList.add('active');
      const key = btn.dataset.sort;
      items().sort(function (a, b) {
        if (key === 'file') return a.dataset.file.localeCompare(b.dataset.file);
        if (key === 'ent') return (+b.dataset.ent) - (+a.dataset.ent);
        return (+b.dataset.sev) - (+a.dataset.sev);
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

  // "Accept all" -> writes .sentrybaseline into the scanned repo, so every
  // finding on this page is suppressed on the next scan. It edits a file in
  // the user's tree, so it confirms first and then says what it wrote.
  (function () {
    const btn = document.getElementById('baselineBtn');
    if (!btn) return;
    const cfg = window.SENTRY || {};
    btn.addEventListener('click', async function () {
      if (!confirm('Write .sentrybaseline into ' + cfg.target + ' ?\\n\\n' +
                   'All ' + btn.dataset.count + ' finding(s) on this page will be ' +
                   'suppressed on future scans until it is regenerated.')) return;
      btn.disabled = true;
      btn.textContent = 'writing...';
      try {
        const res = await fetch(cfg.baselineApi, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: cfg.target })
        });
        const data = await res.json();
        if (data.ok) {
          btn.textContent = 'baselined (' + data.count + ')';
        } else {
          btn.textContent = 'accept all';
          btn.disabled = false;
          alert(data.error || 'could not write the baseline');
        }
      } catch (e) {
        btn.textContent = 'accept all';
        btn.disabled = false;
        alert('could not reach the scanner: ' + e.message);
      }
    });
  })();
"""
