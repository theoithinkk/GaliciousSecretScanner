"""
reporters.py
takes scored findings and renders them: terminal or json. no output ever
contains a full secret -- ScoredFinding only carries the masked forms.

This is the rendering cli.py needs directly, so it stays at the repo root
alongside the detection engine, with no dependency on Flask or anything
browser-facing. The themed HTML report (severity tiles, clickable findings,
the terminal detail panel, one-click fix) lives in web/html_report.py --
scorer_reporter.generate_report() reaches it with a lazy import only when
fmt="html" is requested, so importing this module (or scorer_reporter, or
cli.py) never requires the web/ package to be present.
"""

from __future__ import annotations

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
        if s.exposure == "working_tree":
            exposure = "LIVE +history" if s.in_history else "LIVE"
        else:
            exposure = "history"
        seen = f", x{s.occurrences}" if s.occurrences > 1 else ""
        head = f"{tag} {loc}  ({s.detector_type}, {exposure}{seen})"
        dim0 = _DIM if use_color else ""
        dim1 = _RESET if use_color else ""
        body = f"    {s.redacted}   {dim0}{s.redacted_context}{dim1}"
        why = f"    {dim0}-> {s.rationale}{dim1}"
        lines += [head, body, why, ""]

        # Added this -Lance
        # Remediation steps, when remediation.annotate() has filled them in.
        # Guarded rather than assumed so a caller that scores findings without
        # going through orchestrator.run_scan() still renders cleanly.
        if s.remediation_steps:
            lines.append(f"    {dim0}fix:{dim1}")
            for i, step in enumerate(s.remediation_steps, 1):
                lines.append(f"      {dim0}{i}. {step}{dim1}")
        lines.append("")

    return "\n".join(lines)


# json renderer
def render_json(scored: List[ScoredFinding]) -> str:
    return json.dumps([s.to_dict() for s in scored], indent=2)
