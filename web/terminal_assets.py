"""
terminal_assets.py
------------------
CSS and JS for the finding-detail terminal panel, split out of
report_assets.py to keep both files under the project's 500-line limit.

The panel is the interactive half of the report: clicking a finding glitches
open a plain, dark terminal window that types out the finding and offers the
one-click fix. It is a flat modal on purpose -- no perspective, no float, no
pointer-tracked tilt -- just `.term` (the dimmed backdrop) and `.term-win`
(the window itself, positioned by flexbox like an ordinary dialog).

Once open it isn't static: a slow ambient glow breathes on the border/shadow
(`termAmbient`), and `.term-scan` overlays the same scanline texture the main
report page uses (reusing report_assets.py's `flicker` keyframe -- both
files' CSS land in one <style> block, so it doesn't need redefining here).
Both are decorative loops, layered onto the one-shot glitch-open burst rather
than replacing it -- see the comment on `.term.open .term-win`'s `animation`
shorthand for how two keyframe sets coexist on one element.

Everything is inline and offline-safe, and every animation here (the entrance
burst, the ambient pulse, the scanline flicker) collapses under
prefers-reduced-motion.
"""

from __future__ import annotations

TERMINAL_CSS = """
  /* Every var(--green) used below this point resolves to a slightly muted
     shade of the site-wide neon (#00ff9c) -- the full-brightness version
     read a little too hot against the panel's near-black background.
     Scoped to .term so nothing outside the panel changes. */
  .term { --green: #14b87d;
    position:fixed; inset:0; z-index:50; display:none; align-items:center;
    justify-content:center; padding:1rem; background:rgba(5,7,10,.92);
    backdrop-filter:blur(3px); }
  .term.open { display:flex; }

  /* Matches main's max-width on the report page, so the panel lines up with
     the container it opened from instead of sitting narrower than it. */
  .term-win { position:relative; width:min(1120px,100%); max-height:88vh; display:flex;
    flex-direction:column; background:var(--bg); overflow:hidden;
    border:1px solid rgba(20,184,125,.32); border-radius:3px;
    box-shadow:0 0 0 1px rgba(20,184,125,.06), 0 12px 40px -6px rgba(0,0,0,.8),
      inset 0 0 60px rgba(20,184,125,.02); }
  /* Two keyframe sets on one `animation` shorthand: termOpen is the one-shot
     glitch burst (opacity/transform/filter/clip-path), termAmbient is an
     infinite loop on a DIFFERENT property (box-shadow only), so they never
     fight -- the second starts after the first settles (.6s delay), which is
     what keeps the window from breathing mid-glitch. */
  .term.open .term-win {
    animation: termOpen .52s cubic-bezier(.2,.9,.25,1) both,
               termAmbient 6s ease-in-out .6s infinite; }
  .term.closing .term-win { animation:termClose .2s ease both; }
  @keyframes termAmbient {
    0%, 100% { box-shadow:0 0 0 1px rgba(20,184,125,.06), 0 12px 40px -6px rgba(0,0,0,.8),
                 inset 0 0 60px rgba(20,184,125,.02); }
    50%      { box-shadow:0 0 0 1px rgba(20,184,125,.13), 0 12px 44px -6px rgba(0,0,0,.8),
                 inset 0 0 85px rgba(20,184,125,.05); }
  }
  /* Same scanline texture the main report page uses behind everything --
     here it's scoped to the window itself, above the content, so the panel
     doesn't read as a flat static box even at rest. */
  .term-scan { position:absolute; inset:0; z-index:1; pointer-events:none;
    background:repeating-linear-gradient(to bottom, transparent 0 2px, rgba(0,0,0,.22) 2px 4px);
    animation:flicker 4s infinite steps(60); mix-blend-mode:multiply; }
  @keyframes termOpen {
    0%   { opacity:0; transform:scaleY(.02) scaleX(.7); filter:blur(4px) brightness(3); clip-path:inset(49% 0 49% 0); }
    14%  { opacity:1; transform:scaleY(1.06) scaleX(1.01) skewX(9deg); filter:blur(1px) brightness(1.7); clip-path:inset(22% 0 58% 0); }
    26%  { transform:translateX(-11px) skewX(-6deg); clip-path:inset(61% 0 9% 0); }
    38%  { transform:translateX(8px) skewX(3deg); clip-path:inset(7% 0 47% 0); }
    50%  { transform:translateX(-4px); clip-path:inset(34% 0 19% 0); }
    64%  { transform:none; filter:none; clip-path:inset(0 0 12% 0); }
    78%  { clip-path:inset(0 0 0 0); }
    82%  { opacity:.72; }
    100% { opacity:1; transform:none; clip-path:inset(0 0 0 0); }
  }
  @keyframes termClose { to { opacity:0; transform:scaleY(.04); filter:blur(3px); } }
  /* RGB split ghosts, only during the open burst */
  .term.open .term-win::before, .term.open .term-win::after {
    content:''; position:absolute; inset:0; pointer-events:none; mix-blend-mode:screen;
    animation:rgbSplit .52s steps(6) both; }
  .term.open .term-win::before { background:rgba(255,45,110,.5); }
  .term.open .term-win::after  { background:rgba(40,200,255,.5); animation-direction:reverse; }
  @keyframes rgbSplit {
    0%   { opacity:.5; transform:translateX(-14px); }
    40%  { opacity:.28; transform:translateX(9px); }
    70%  { opacity:.12; transform:translateX(-3px); }
    100% { opacity:0; transform:none; }
  }
  .term-bar { display:flex; align-items:center; gap:.55rem; padding:.7rem 1rem;
    background:linear-gradient(rgba(20,184,125,.07), rgba(20,184,125,.02));
    border-bottom:1px solid rgba(20,184,125,.2); flex:none; }
  .dot { width:11px; height:11px; border-radius:50%; display:inline-block; }
  .dot.r { background:#ff5f57; } .dot.y { background:#febc2e; } .dot.g { background:#28c840; }
  .term-title { margin-left:.5rem; font-size:var(--fs-xs); letter-spacing:.12em; color:var(--green);
    text-transform:lowercase; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .term-x { margin-left:auto; background:transparent; border:1px solid var(--grid); color:var(--muted);
    font:inherit; font-size:var(--fs-sm); line-height:1; padding:.15rem .5rem; cursor:pointer; border-radius:2px; }
  .term-x:hover { color:var(--crit); border-color:var(--crit); }
  .term-body { flex:1; overflow-y:auto; padding:1.15rem 1.3rem 1.3rem; font-size:var(--fs-sm);
    line-height:1.75; color:var(--text); }
  .term-body .tl { white-space:pre-wrap; word-break:break-word; }
  .term-body .tl.dim { color:var(--muted); }
  .term-body .tl.ok { color:var(--green); }
  .term-body .tl.warn { color:var(--med); }
  .term-body .tl.err { color:var(--crit); }
  .term-body .tl.head { color:var(--green); text-shadow:0 0 6px rgba(20,184,125,.35);
    margin-top:.7rem; letter-spacing:.08em; }
  .term-body .k { color:var(--muted); display:inline-block; width:12ch; }
  .term-body .v { color:var(--text); }
  .term-body .v.crit { color:var(--crit); } .term-body .v.high { color:var(--high); }
  .term-body .v.med { color:var(--med); }  .term-body .v.low { color:var(--low); }
  .term-body .v.ok { color:var(--green); }
  .term-actions { display:flex; align-items:center; gap:.6rem; flex-wrap:wrap;
    margin-top:.9rem; padding-top:.8rem; border-top:1px dashed rgba(20,184,125,.18); }
  .fixbtn { font:inherit; font-size:var(--fs-xs); letter-spacing:.12em; text-transform:uppercase;
    color:var(--bg); background:var(--green); border:none; padding:.6rem 1.25rem; cursor:pointer;
    border-radius:2px; font-weight:700; box-shadow:0 0 14px rgba(20,184,125,.35);
    transition:transform .1s, box-shadow .15s, opacity .15s; }
  .fixbtn:hover:not(:disabled) { transform:translateY(-1px); box-shadow:0 0 20px rgba(20,184,125,.5); }
  .fixbtn:disabled { opacity:.38; cursor:not-allowed; box-shadow:none; }
  .fixbtn.ghost { background:transparent; color:var(--muted); border:1px solid var(--grid);
    box-shadow:none; font-weight:400; }
  .fixbtn.ghost:hover:not(:disabled) { color:var(--green); border-color:var(--green); }
  .term-hint { font-size:var(--fs-xs); color:var(--muted); letter-spacing:.06em; }
  @media (max-width:560px) { .term-body .k { width:auto; display:block; } }
  /* The generic "kill every animation" rule lives once in report_assets.py's
     BASE_CSS; only the panel's own exceptions belong here. */
  @media (prefers-reduced-motion: reduce) {
    .term.open .term-win { opacity:1; clip-path:none; }
  }
"""

TERMINAL_JS = """
  (function () {
    const cfg = window.SENTRY || { fixEnabled: false };
    const term = document.getElementById('term');
    const body = document.getElementById('termBody');
    const title = document.getElementById('termTitle');
    if (!term || !body) return;

    let current = null;

    function line(text, cls) {
      const el = document.createElement('div');
      el.className = 'tl' + (cls ? ' ' + cls : '');
      el.innerHTML = text;
      body.appendChild(el);
      body.scrollTop = body.scrollHeight;
      return el;
    }
    function kv(k, v, cls) {
      return line('<span class="k">' + k + '</span><span class="v' +
                  (cls ? ' ' + cls : '') + '">' + v + '</span>');
    }
    function esc(s) {
      return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
      });
    }
    // remediation_steps rides on the card as a JSON array (html_report.py).
    // A malformed attribute must not take the whole detail panel down with it.
    function parseSteps(raw) {
      if (!raw) return [];
      try { const v = JSON.parse(raw); return Array.isArray(v) ? v : []; }
      catch (e) { return []; }
    }

    // Colour a few fields by what they actually mean, the same way the
    // severity tiles and finding tags already do, so the panel isn't just
    // one flat shade of green-on-black.
    function exposureColor(d) {
      if (d.exposure === 'working_tree') return d.inhistory === '1' ? 'crit' : 'high';
      return 'low';                                       // history_only: already gone from the tree
    }
    function fileClassColor(fc) {
      // Mirrors the scoring rubric's own weighting: .env (+15) and config
      // (+10) are where a real leak is most likely to be live; test/docs
      // (-20/-25) are where it's most likely a discounted fixture.
      if (fc === 'env') return 'high';
      if (fc === 'config') return 'med';
      if (fc === 'test' || fc === 'docs') return 'low';
      return '';
    }
    function entropyColor(bits) {
      const n = +bits;
      if (n >= 4.5) return 'high';   // matches the rubric's own +10 threshold
      if (n >= 4.0) return 'med';    // matches the rubric's own +5 threshold
      return '';
    }
    // Severity.label is "Critical"/"High"/"Medium"/"Low"; the CSS classes are
    // the short forms .v.crit/.v.high/.v.med/.v.low. "high" and "low" happen
    // to match after lowercasing, which is what hid this for "critical" and
    // "medium" silently rendering with no colour at all.
    function severityColor(label) {
      const l = (label || '').toLowerCase();
      if (l === 'critical') return 'crit';
      if (l === 'medium') return 'med';
      return l;   // 'high' / 'low' already match
    }

    // Reveal lines one at a time so it reads like a program producing output.
    function typeOut(steps, done) {
      if (reduce) { steps.forEach(function (fn) { fn(); }); if (done) done(); return; }
      let i = 0;
      (function next() {
        if (i >= steps.length) { if (done) done(); return; }
        steps[i++]();
        setTimeout(next, 12);   // readable as a whole, still reads as output
      })();
    }

    function open(card) {
      current = card;
      body.innerHTML = '';
      const d = card.dataset;
      if (title) title.textContent = 'galicious://' + d.file + ':' + d.line;

      const steps = [
        function () { line('$ galicious inspect --file ' + esc(d.file) + ' --line ' + esc(d.line), 'ok'); },
        function () { line('[*] resolving finding ................ OK', 'dim'); },
        function () { line('&nbsp;'); },
        function () {
          kv('SEVERITY', esc(d.sevlabel) + '  (' + esc(d.points) + ' pts)',
             severityColor(d.sevlabel)); },
        function () { kv('TYPE', esc(d.type), 'ok'); },
        function () { kv('LOCATION', esc(d.file) + ':' + esc(d.line)); },
        function () { kv('FILE CLASS', esc(d.fileclass), fileClassColor(d.fileclass)); },
        function () { kv('EXPOSURE', esc(d.exposuretext), exposureColor(d)); },
        function () { kv('SECRET', esc(d.redacted)); },
        function () { kv('CONTEXT', esc(d.context)); }
      ];
      if (d.entropy && d.entropy !== '0') {
        steps.push(function () {
          kv('ENTROPY', esc(d.entropy) + ' bits/char', entropyColor(d.entropy)); });
      }
      steps.push(function () { line('[*] why this score', 'head'); });
      steps.push(function () { line('  ' + esc(d.rationale), 'dim'); });
      steps.push(function () { line('[!] remediation', 'head'); });

      // remediation.py's steps for this finding, in its order: rotation
      // first, history purge last. Read off the card rather than rebuilt.
      const fix = parseSteps(d.remediation);
      if (fix.length) {
        fix.forEach(function (step, i) {
          // Step 1 is the rotation in every entry in the table, and it is the
          // only one that actually ends the exposure -- so it gets the warn
          // colour and the rest are ordinary output.
          steps.push(function () {
            line('  ' + (i + 1) + '. ' + esc(step), i === 0 ? 'warn' : 'dim'); });
        });
      } else {
        // A report rendered without orchestrator.run_scan() (so without
        // remediation.annotate()) still gets the one instruction that is true
        // of every finding.
        steps.push(function () {
          line('  1. ROTATE this credential now. It must be assumed compromised.', 'warn'); });
        if (d.inhistory === '1') {
          steps.push(function () {
            line('  2. It is in git history. Editing the file does NOT remove it.', 'warn'); });
        }
      }
      steps.push(function () { line('&nbsp;'); });

      typeOut(steps, function () { renderActions(card); });

      lockPage();
      term.classList.remove('closing');
      term.classList.add('open');
      const x = document.getElementById('termX');
      if (x) x.focus();
    }

    function renderActions(card) {
      const d = card.dataset;
      const wrap = document.createElement('div');
      wrap.className = 'term-actions';

      if (card.classList.contains('fixed')) {
        wrap.innerHTML = '<span class="term-hint">already fixed in this session</span>';
      } else if (!cfg.fixEnabled) {
        wrap.innerHTML = '<span class="term-hint">one-click fix needs the web UI ' +
          '(python web/app.py) &mdash; a saved report has no server to apply it</span>';
      } else if (d.fixable !== '1') {
        wrap.innerHTML = '<span class="term-hint">no automatic fix for this finding: ' +
          esc(d.fixreason || 'unsupported') + '</span>';
      } else {
        const btn = document.createElement('button');
        btn.className = 'fixbtn';
        btn.textContent = '[ apply fix ]';
        btn.addEventListener('click', function () { applyFix(card, btn); });
        wrap.appendChild(btn);
        const hint = document.createElement('span');
        hint.className = 'term-hint';
        hint.textContent = 'moves the secret to .env, gitignores it, rewrites the source';
        wrap.appendChild(hint);
      }
      body.appendChild(wrap);
      body.scrollTop = body.scrollHeight;
    }

    async function applyFix(card, btn) {
      const d = card.dataset;
      btn.disabled = true;
      line('&nbsp;');
      line('$ galicious fix --apply --file ' + esc(d.file) + ' --line ' + esc(d.line), 'ok');
      const spin = line('[*] applying ...', 'dim');
      try {
        const res = await fetch(cfg.api, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target: cfg.target, file_path: d.file,
            line_number: +d.line, detector_type: d.type,
            // Without this the fix reports success on a committed secret
            // without ever saying the blob is still reachable in history.
            in_history: d.inhistory === '1'
          })
        });
        const data = await res.json();
        spin.remove();
        if (!data.ok) {
          line('[x] ' + esc(data.error || 'fix failed'), 'err');
          btn.disabled = false;
          return;
        }
        (data.steps || []).forEach(function (s) { line('  ' + esc(s), 'ok'); });
        (data.warnings || []).forEach(function (w) { line('  ! ' + esc(w), 'warn'); });
        line('[+] fix applied', 'ok');
        card.classList.add('fixed');
        const head = card.querySelector('.fhead');
        if (head && !head.querySelector('.fixedtag')) {
          const t = document.createElement('span');
          t.className = 'ftag fixedtag';
          t.textContent = 'FIXED';
          head.appendChild(t);
        }
        btn.remove();
      } catch (e) {
        spin.remove();
        line('[x] could not reach the scanner: ' + esc(e.message), 'err');
        btn.disabled = false;
      }
    }

    // A position:fixed overlay sizes to the DOCUMENT's client width, which
    // excludes the browser's own scrollbar. So with the panel open the page's
    // scrollbar sat beside it as a bare dark strip the panel background could
    // never reach. Locking the page while the panel is open removes it. The
    // padding replaces exactly the width the scrollbar was occupying, so the
    // page behind does not jump sideways as it appears and disappears.
    function lockPage() {
      const bar = window.innerWidth - document.documentElement.clientWidth;
      if (bar > 0) document.body.style.paddingRight = bar + 'px';
      document.documentElement.style.overflow = 'hidden';
    }

    function unlockPage() {
      document.documentElement.style.overflow = '';
      document.body.style.paddingRight = '';
    }

    function close() {
      term.classList.add('closing');
      setTimeout(function () {
        term.classList.remove('open', 'closing');
        unlockPage();
        if (current) { current.focus(); current = null; }
      }, reduce ? 0 : 190);
    }

    document.querySelectorAll('.finding').forEach(function (card) {
      card.setAttribute('tabindex', '0');
      card.addEventListener('click', function () { open(card); });
      card.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(card); }
      });
    });
    const x = document.getElementById('termX');
    if (x) x.addEventListener('click', close);
    term.addEventListener('click', function (e) { if (e.target === term) close(); });
    addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && term.classList.contains('open')) close();
    });
  })();
"""
