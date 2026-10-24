# SPDX-License-Identifier: Apache-2.0
"""Terminal summary. ASCII only (no emoji or box drawing), so it works in any console and CI log."""

from __future__ import annotations

import os
import re
import shutil
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
        lines.append("Assumed a general app (MAS-L1+P). Set --app-type for accurate results.")
    for w in result.profile.warnings:
        wl = w.lines()
        lines.append(_c(color, "high", f"WARNING: {wl[0]}"))
        lines += [f"  {x}" for x in wl[1:]]
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
        lines += ["", "No open findings to fix." + (" Check your app type first (see the warning above)."
                                                    if result.profile.warnings else "")]
    notes = list(getattr(result, "notes", []))
    for n in notes:
        lines.append(f"Note: {n}")
    if result.project.unknowns:
        n = len(result.project.unknowns)
        lines.append(f"Couldn't decide {n} {'thing' if n == 1 else 'things'}; see Residual risk in the report.")
    lines.append("")
    if report_path:
        lines.append(f"Report: {report_path}")
        lines.append(_next_step(result, report_path))
    else:
        lines.append(_next_step(result, None))
    return asciify("\n".join(lines)) + "\n"


def invocation() -> str:
    """The command that runs masaudit again the way the user just did (uvx, pipx, a .pyz, or installed)."""
    argv0 = sys.argv[0] if sys.argv else ""
    base = os.path.basename(argv0)
    if base.endswith(".pyz"):
        return f'python3 "{argv0}"' if " " in argv0 else f"python3 {argv0}"
    if base == "__main__.py":
        return "python3 -m masaudit"
    on_path = shutil.which("masaudit")
    if on_path and argv0 and os.path.realpath(on_path) == os.path.realpath(argv0):
        return "masaudit"
    where = argv0.replace("\\", "/").lower()
    if "pipx" in where:
        return "pipx run masaudit"
    if "/uv/" in where or "archive-v0" in where:
        return "uvx masaudit"
    return "masaudit"


def _next_step(result, report_path: Optional[str]) -> str:
    cmd = invocation()
    root = getattr(result, "root", None) or "."
    try:
        root = os.path.relpath(root)
    except ValueError:              # Windows: the scan root is on another drive
        pass
    target = "" if root == "." else (f' "{root}"' if " " in root else f" {root}")
    safe = any(f.rule.safe_fix and f.bucket in ("fix-before-release", "fix-soon") for f in result.findings)
    preview = f"`{cmd}{target} --fix-safe` previews the safe fixes (changes nothing)" if safe else ""
    if report_path:
        start = "start with Top fixes" if top_fixes(result.findings) else "read Residual risk"
        return f"Next: open {os.path.basename(report_path)} and {start}." + (f" {preview[0].upper()}{preview[1:]}." if preview else "")
    return f"Next: run `{cmd}{target}` to write SECURITY-AUDIT.md." + (f" {preview[0].upper()}{preview[1:]}." if preview else "")


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
        lines.append(f"Safe fix: yes ({invocation()} --fix-safe)")
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
