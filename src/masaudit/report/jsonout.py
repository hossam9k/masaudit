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

SCHEMA_VERSION = 1
BUCKETS = ["fix-before-release", "fix-soon", "notes", "not-needed"]
BUCKET_TITLES = {
    "fix-before-release": "Fix before release",
    "fix-soon": "Fix soon",
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


def finding_dict(f: Finding) -> dict:
    r = f.rule
    return {
        "rule_id": r.id,
        "title": r.title,
        "platform": r.platform,
        "severity": r.severity,
        "effective_severity": f.effective_severity,
        "bucket": f.bucket,
        "bucket_reason": f.bucket_reason,
        "acknowledged": f.acknowledged,
        "confidence": r.confidence,
        "status": f.status,
        "suppression_reason": f.suppression_reason,
        "path": f.location.path,
        "line": f.location.line,
        "snippet": f.location.snippet,
        "message": f.message,
        "scope": f.scope,
        "fingerprint": f.fingerprint(),
        "why": r.why,
        "fix": r.fix,
        "verify": r.verify,
        "effort": r.effort,
        "maswe": r.maswe,
        "masvs": r.masvs,
        "mastg": list(r.mastg),
        "book": r.book,
        "book_url": r.book_url,
        "safe_fix": r.safe_fix,
        "imported": ":" in r.id,
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
        },
        "summary": counts(result.findings),
        "findings": [finding_dict(f) for f in findings],
        "unknowns": list(result.project.unknowns),
        "notes": list(getattr(result, "notes", [])),
    }


def render(result) -> str:
    return json.dumps(to_dict(result), indent=2, ensure_ascii=False) + "\n"
