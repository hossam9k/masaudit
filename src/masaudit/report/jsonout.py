# SPDX-License-Identifier: Apache-2.0
"""JSON output (stable schema) and the small helpers every report shares.

A report takes a scan result with these attributes: root, project (model.Project), profile
(model.Profile), findings, rules (all loaded rules), rules_version, notes (list of str).
"""

from __future__ import annotations

import datetime
import json
import os
from typing import Dict, List

from masaudit import __version__
from masaudit import profile as profile_mod
from masaudit.model import SEVERITY_RANK, Finding
from masaudit.safety import show_invisible as _shown

SCHEMA_VERSION = 1
BUCKETS = ["fix-before-release", "fix-soon", "check-by-hand", "hardening", "notes", "not-needed"]
BUCKET_TITLES = {
    "fix-before-release": "Fix before release",
    "fix-soon": "Fix soon",
    "check-by-hand": "Check by hand",
    "hardening": "Hardening checklist",
    "notes": "Notes",
    "not-needed": "Not needed for your app (and why)",
}
EFFORT_RANK = {"minutes": 0, "hours": 1, "days": 2}
ACTIONABLE = ("fix-before-release", "fix-soon")


def report_datetime() -> datetime.datetime:
    """Now, or SOURCE_DATE_EPOCH when set (reproducible builds)."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if epoch:
        try:
            return datetime.datetime.fromtimestamp(int(epoch), tz=datetime.timezone.utc)
        except (ValueError, OverflowError, OSError):
            pass
    return datetime.datetime.now(tz=datetime.timezone.utc)


def report_date() -> str:
    return report_datetime().date().isoformat()


def project_name(result) -> str:
    return os.path.basename(os.path.abspath(result.root).rstrip(os.sep)) or "project"


def open_findings(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if f.status == "open"]


def sort_key(f: Finding):
    return (SEVERITY_RANK.get(f.effective_severity or f.rule.severity, 9),
            EFFORT_RANK.get(f.rule.effort, 9), f.rule.id, f.location.path, f.location.line)


def top_fixes(findings: List[Finding], n: int = 3) -> List[Finding]:
    """Highest severity first, then the quickest fix; one entry per rule."""
    seen = set()
    out = []
    for f in sorted((f for f in open_findings(findings) if f.bucket in ACTIONABLE), key=sort_key):
        if f.rule.id in seen:
            continue
        seen.add(f.rule.id)
        out.append(f)
        if len(out) == n:
            break
    return out


def counts(findings: List[Finding]) -> Dict[str, int]:
    out = {b: 0 for b in BUCKETS}
    out["suppressed"] = 0
    out["baselined"] = 0
    for f in findings:
        if f.status == "suppressed":
            out["suppressed"] += 1
        elif f.status == "baselined":
            out["baselined"] += 1
        elif f.bucket in out:
            out[f.bucket] += 1
    return out


MAX_LISTED_SKIPS = 1000


def excluded_count(project) -> int:
    return sum(getattr(project, "excluded", {}).values())


def excluded_line(project) -> str:
    """One plain sentence on what the `exclude` globs left out, or "" when there are none."""
    excluded = getattr(project, "excluded", {})
    if not excluded:
        return ""
    n = excluded_count(project)
    per = ", ".join(f"{g} ({c})" for g, c in excluded.items())
    stale = [g for g, c in excluded.items() if not c]
    tail = (f" {'This pattern matches' if len(stale) == 1 else 'These patterns match'} no file, so "
            f"{'it' if len(stale) == 1 else 'they'} can go: {', '.join(stale)}." if stale else "")
    return (f"Not scanned because exclude in .masaudit.ini leaves them out: {n} file{'s' if n != 1 else ''} "
            f"({per}).{tail}")


def scope_dict(project) -> dict:
    """What the scan covered: files read, files not read and why, and files the settings excluded."""
    skipped = list(getattr(project, "skipped", []))
    listed = set(project.files)
    unreadable = sum(1 for p, _why in skipped if p in listed)     # listed by the walk, then found unreadable
    return {
        "files_scanned": len(project.files) - unreadable,
        "files_not_read": len(skipped),
        "not_read": [{"path": _shown(p), "reason": why} for p, why in skipped[:MAX_LISTED_SKIPS]],
        "files_excluded": excluded_count(project),
        "excluded_by_pattern": [{"pattern": g, "files": c} for g, c in getattr(project, "excluded", {}).items()],
        "complete": not skipped,
    }


def finding_dict(f: Finding) -> dict:
    r = f.rule
    return {
        "rule_id": r.id,
        "title": _shown(r.title),
        "platform": r.platform,
        "severity": r.severity,
        "effective_severity": f.effective_severity,
        "bucket": f.bucket,
        "bucket_reason": _shown(f.bucket_reason),
        "acknowledged": f.acknowledged,
        "confidence": r.confidence,
        "kind": r.kind,
        "status": f.status,
        "suppression_reason": _shown(f.suppression_reason),
        "path": f.location.path,             # the real name, for tools: shown with markers in every report
        "line": f.location.line,
        "snippet": _shown(f.location.snippet),
        "message": _shown(f.message),
        "scope": f.scope,
        "fingerprint": f.fingerprint(),
        "why": _shown(r.why),
        "fix": _shown(r.fix),
        "verify": _shown(r.verify),
        "effort": r.effort,
        "maswe": r.maswe,
        "masvs": r.masvs,
        "mastg": list(r.mastg),
        "book": r.book,
        "book_url": r.book_url,
        "safe_fix": r.safe_fix,
        "imported": r.imported,
    }


def to_dict(result) -> dict:
    p = result.profile
    findings = sorted(result.findings, key=lambda f: (BUCKETS.index(f.bucket) if f.bucket in BUCKETS else 9,)
                      + sort_key(f))
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "masaudit", "version": __version__},
        "rules_version": result.rules_version,
        "generated": report_date(),
        "project": {"name": project_name(result), "platforms": list(result.project.platforms)},
        "profile": {
            "app_type": p.app_type,
            "mas_profiles": list(p.mas_profiles),
            "source": p.source,
            "description": profile_mod.describe(p),
            "suggestions": list(p.suggestions),
            "warnings": [w.to_dict() for w in p.warnings],
        },
        "summary": counts(result.findings),
        "scope": scope_dict(result.project),
        "baseline": result.baseline.to_dict() if getattr(result, "baseline", None) is not None else None,
        "findings": [finding_dict(f) for f in findings],
        "unknowns": [_shown(u) for u in result.project.unknowns],
        "notes": [_shown(n) for n in getattr(result, "notes", [])],
    }


def render(result) -> str:
    return json.dumps(to_dict(result), indent=2, ensure_ascii=False) + "\n"
