# SPDX-License-Identifier: Apache-2.0
"""Terminal summary. ASCII only (no emoji or box drawing), so it works in any console and CI log."""

from __future__ import annotations

import os
import re
import sys
from typing import List, Optional

from masaudit import __version__
from masaudit import profile as profile_mod
from masaudit.model import Rule
from masaudit.report.jsonout import counts, project_name, top_fixes

_ASCII = {
    "§": "Section ", "—": "-", "–": "-", "…": "...", "‘": "'", "’": "'", "“": '"', "”": '"',
    "→": "->", "←": "<-", "·": "-", "×": "x", "≥": ">=", "≤": "<=", "•": "*", " ": " ",
}
_RESET = "\033[0m"
_COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m",
           "info": "\033[37m", "bold": "\033[1m", "dim": "\033[2m"}


def asciify(value: str) -> str:
    s = "".join(_ASCII.get(ch, ch) for ch in str(value))
    s = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", s)
    return s.encode("ascii", "replace").decode("ascii")


def use_color(no_color: bool, stream=None) -> bool:
    stream = stream or sys.stdout
    if no_color or os.environ.get("NO_COLOR"):
        return False
    try:
        return bool(stream.isatty()) and os.environ.get("TERM") != "dumb"
    except (AttributeError, ValueError):
        return False


def _c(color: bool, key: str, s: str) -> str:
    return f"{_COLORS[key]}{s}{_RESET}" if color and key in _COLORS else s


def render(result, report_path: Optional[str] = None, color: bool = False) -> str:
    c = counts(result.findings)
    lines: List[str] = [
        _c(color, "bold", f"masaudit {__version__} (rules {result.rules_version}) - {project_name(result)}"),
        f"Platforms: {', '.join(result.project.platforms) or 'none detected'}",
        f"Profile:   {profile_mod.describe(result.profile)}",
    ]
    if result.profile.source == "default":
        lines.append("Assumed general app (MAS-L1). Set --app-type for accurate results.")
    for s in result.profile.suggestions:
        lines.append(f"Clue:      {s}")
    lines += [
        "",
        f"Fix before release: {_c(color, 'high', str(c['fix-before-release'])) if c['fix-before-release'] else 0}"
        f"   Fix soon: {c['fix-soon']}   Notes: {c['notes']}   Not needed: {c['not-needed']}"
        f"   Accepted: {c['suppressed'] + c['baselined']}",
    ]
    top = top_fixes(result.findings)
    if top:
        lines += ["", "Top fixes:"]
        for i, f in enumerate(top, 1):
            loc = f"{f.location.path}:{f.location.line}" if f.location.line else (f.location.path or "project")
            sev = _c(color, f.effective_severity, f"[{f.effective_severity}]")
            lines.append(f"  {i}. {sev} {f.rule.title} ({f.rule.id}) - {loc}")
    else:
        lines += ["", "No open findings to fix."]
    notes = list(getattr(result, "notes", []))
    for n in notes:
        lines.append(f"Note: {n}")
    if result.project.unknowns:
        lines.append(f"Couldn't decide {len(result.project.unknowns)} thing(s); see Residual risk in the report.")
    lines.append("")
    if report_path:
        lines.append(f"Report: {report_path}")
        lines.append(f"Next: open {os.path.basename(report_path)}, or run `masaudit --fix-safe` "
                     "to preview safe fixes (changes nothing).")
    else:
        lines.append("Next: run `masaudit` to write SECURITY-AUDIT.md, or `masaudit --fix-safe` "
                     "to preview safe fixes (changes nothing).")
    return asciify("\n".join(lines)) + "\n"


def explain(rule: Rule) -> str:
    lines = [
        f"{rule.id}: {rule.title}",
        f"Platform: {rule.platform}   Severity: {rule.severity}   Profiles: {', '.join('MAS-' + p for p in rule.profiles)}"
        f"   Confidence: {rule.confidence}   Effort: {rule.effort}",
    ]
    if rule.app_types is not None:
        lines.append(f"Only needed for: {', '.join(rule.app_types)}")
        if rule.not_needed_reason:
            lines.append(f"Why others don't need it: {rule.not_needed_reason}")
    lines += ["", f"Why it matters: {rule.why}", "", f"Fix: {rule.fix}"]
    if rule.fix_code and rule.fix_code.get("code"):
        lines += ["", "    " + rule.fix_code["code"].replace("\n", "\n    ")]
    lines += ["", f"How to verify: {rule.verify}", ""]
    ids = [i for i in (rule.maswe, rule.masvs) if i] + list(rule.mastg)
    if ids:
        lines.append(f"IDs: {', '.join(ids)}")
    lines.append(f"Book: {rule.book} {rule.book_url}".rstrip())
    if rule.safe_fix:
        lines.append("Safe fix: yes (masaudit --fix-safe)")
    if rule.retired:
        lines.append("This rule is retired.")
    return asciify("\n".join(lines)) + "\n"


def list_rules(rules: List[Rule]) -> str:
    lines = []
    for r in sorted(rules, key=lambda x: x.id):
        if r.retired:
            continue
        lines.append(f"{r.id:<8} {r.platform:<8} {r.severity:<9} {r.title}")
    return asciify("\n".join(lines)) + "\n"
