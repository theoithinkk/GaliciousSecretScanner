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

import hashlib
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


# sarif renderer
#
# SARIF 2.1.0 is what GitHub Code Scanning ingests, so a report in this shape
# lands in a repo's Security tab next to CodeQL with no extra infrastructure:
#     python cli.py . --format sarif -o results.sarif
#     - uses: github/codeql-action/upload-sarif@v3
#       with: {sarif_file: results.sarif}
#
# Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

TOOL_NAME = "GaliciousSecretScanner"
TOOL_VERSION = "1.0.0"
TOOL_URI = "https://github.com/theoithinkk/GaliciousSecretScanner"

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

# GitHub ignores our severity band and reads `security-severity` off the rule,
# bucketing it on the CVSS scale (>=9 critical, >=7 high, >=4 medium). These
# numbers exist so that bucketing agrees with the band we already assigned.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
}

# Detector types with no entry in config/patterns.json.
_EXTRA_RULE_DESCRIPTIONS = {
    "HIGH_ENTROPY": "High-entropy string in a credential-shaped assignment",
}


def _sarif_uri(file_path: str) -> str:
    """
    SARIF artifact URIs are repo-relative and forward-slashed. Paths arrive
    with backslashes whenever the scan ran on Windows, and Code Scanning fails
    to match those against the repo tree without saying why.
    """
    return file_path.replace("\\", "/").lstrip("/")


def _sarif_rules(scored: List[ScoredFinding]) -> List[dict]:
    """
    One rule per detector type, descriptions reused from the signature library
    so they can't drift from what the detector actually matches.

    pattern_detector is imported lazily because it compiles every pattern at
    import time, and terminal/json rendering has no use for that.
    """
    from pattern_detector import load_patterns, PatternDetectorError

    descriptions = dict(_EXTRA_RULE_DESCRIPTIONS)
    try:
        for pat in load_patterns():
            descriptions[pat.type] = pat.description or pat.type
    except PatternDetectorError:
        # A broken pattern config shouldn't cost us the report -- the findings
        # are already in hand by the time we get here.
        pass

    # Every ruleId a result references has to resolve to a rule, including
    # detector types that came from somewhere other than patterns.json.
    worst = {}
    for s in scored:
        descriptions.setdefault(s.detector_type, s.detector_type)
        if s.severity > worst.get(s.detector_type, Severity.LOW):
            worst[s.detector_type] = s.severity

    rules = []
    for rule_id in sorted(descriptions):
        # Rules with no hits this run still get listed, at the middle band --
        # nothing was observed that would rank them.
        sev = worst.get(rule_id, Severity.MEDIUM)
        rules.append({
            "id": rule_id,
            "name": rule_id.title().replace("_", ""),
            "shortDescription": {"text": descriptions[rule_id]},
            "fullDescription": {
                "text": f"{descriptions[rule_id]}. Reported by {TOOL_NAME}.",
            },
            "defaultConfiguration": {"level": _SARIF_LEVEL[sev]},
            "properties": {
                "tags": ["security", "secret"],
                "security-severity": _SECURITY_SEVERITY[sev],
            },
        })
    return rules


def _sarif_result(s: ScoredFinding) -> dict:
    result = {
        "ruleId": s.detector_type,
        "level": _SARIF_LEVEL[s.severity],
        "message": {"text": s.rationale},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": _sarif_uri(s.file_path)},
                # SARIF regions are 1-based and a 0 is rejected outright.
                "region": {"startLine": max(1, s.line_number)},
            },
        }],
        # Lets Code Scanning follow one alert across runs instead of closing
        # and reopening it every time the line number shifts. Hashes the
        # redacted value, never the secret.
        "partialFingerprints": {
            "secretHash/v1": hashlib.sha256(
                f"{_sarif_uri(s.file_path)}|{s.detector_type}|{s.redacted}".encode()
            ).hexdigest(),
        },
        "properties": {
            "points": s.points,
            "severity": s.severity.label,
            "exposure": s.exposure,
            "fileClass": s.file_class,
            "occurrences": s.occurrences,
        },
    }
    if s.verified is not None:
        result["properties"]["verifiedLive"] = s.verified
    if s.commit_hash:
        result["properties"]["commit"] = s.commit_hash
    return result


def render_sarif(scored: List[ScoredFinding]) -> str:
    log = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": TOOL_URI,
                "rules": _sarif_rules(scored),
            }},
            "results": [_sarif_result(s) for s in scored],
        }],
    }
    return json.dumps(log, indent=2)
