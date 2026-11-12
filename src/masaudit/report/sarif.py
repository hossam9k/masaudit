# SPDX-License-Identifier: Apache-2.0
"""SARIF 2.1.0 output for GitHub code scanning and other SARIF viewers."""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from typing import Dict, List
from urllib.parse import quote

from masaudit import REPO_URL, __version__
from masaudit.model import SEVERITY_RANK, Finding, Rule
from masaudit.report.jsonout import excluded_line, report_datetime, sort_key
from masaudit.report.markdown import prose
from masaudit.safety import show_invisible as _shown

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SECURITY_SEVERITY = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 1.0}
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def rule_name(rule: Rule) -> str:
    words = re.findall(r"[A-Za-z0-9]+", rule.title)
    name = "".join(w[:1].upper() + w[1:] for w in words)
    return name or re.sub(r"[^A-Za-z0-9]", "", rule.id)


def _uri(path: str) -> str:
    """A relative URI reference: forward slashes, and spaces, `%`, `#`, `?` and non-ASCII percent-encoded."""
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return quote(p.lstrip("/"), safe="/") or "."


def _rule_entry(rule: Rule, severity: str) -> dict:
    ids = [i for i in (rule.maswe, rule.masvs) if i]
    # An imported rule's text comes from another tool's SARIF file: its help Markdown is escaped (prose), and
    # every text field shows hidden characters, since GitHub displays them to reviewers.
    help_text = _shown(f"Why: {rule.why}\nFix: {rule.fix}\nVerify: {rule.verify}\nBook: {rule.book} {rule.book_url}".strip())
    md = [f"**Why it matters:** {prose(rule, rule.why)}", "", f"**Fix:** {prose(rule, rule.fix)}", ""]
    if rule.fix_code and rule.fix_code.get("code"):
        lang = re.sub(r"[^A-Za-z0-9_+-]", "", rule.fix_code.get("lang", ""))
        md += [f"```{lang}", rule.fix_code["code"].rstrip(), "```", ""]
    md += [f"**How to verify:** {prose(rule, rule.verify)}", ""]
    if rule.book_url:
        md.append(f"Book: [{rule.book}]({rule.book_url})")
    entry = {
        "id": rule.id,
        "name": rule_name(rule),
        "shortDescription": {"text": _shown(rule.title)},
        "fullDescription": {"text": _shown(rule.why)},
        "help": {"text": help_text, "markdown": _shown("\n".join(md))},
        "defaultConfiguration": {"level": LEVEL.get(severity, "warning")},
        "properties": {
            "tags": ["security"] + ids,
            "security-severity": f"{SECURITY_SEVERITY.get(severity, 5.0):.1f}",
            "precision": {"high": "high", "medium": "medium", "manual": "low"}.get(rule.confidence, "medium"),
        },
    }
    if rule.book_url:
        entry["helpUri"] = rule.book_url
    return entry


# Buckets that never fail CI: reported at "low" at most, so GitHub's default code scanning check (high and above)
# doesn't block a pull request on a checklist item or an unconfirmed finding either.
_SOFT_BUCKETS = ("check-by-hand", "hardening")


def _severity(f: Finding) -> str:
    sev = f.effective_severity or f.rule.severity
    if f.bucket == "not-needed":
        return "info"
    if f.bucket in _SOFT_BUCKETS and SEVERITY_RANK.get(sev, 9) < SEVERITY_RANK["low"]:
        return "low"
    return sev


def to_dict(result, include_not_needed: bool = False) -> dict:
    findings: List[Finding] = []
    for f in sorted(result.findings, key=sort_key):
        if f.bucket == "not-needed" and not include_not_needed:
            continue
        findings.append(f)

    # Rule-level security-severity: the highest effective severity among its results.
    worst: "OrderedDict[str, str]" = OrderedDict()
    rules: Dict[str, Rule] = {}
    for f in sorted(findings, key=lambda x: x.rule.id):
        sev = _severity(f)
        prev = worst.get(f.rule.id)
        if prev is None or SEVERITY_RANK.get(sev, 9) < SEVERITY_RANK.get(prev, 9):
            worst[f.rule.id] = sev
        rules[f.rule.id] = f.rule
    rule_ids = list(worst)
    index = {rid: i for i, rid in enumerate(rule_ids)}

    results = []
    for f in findings:
        sev = _severity(f)
        msg = f"{f.rule.title}."
        if f.message:
            msg += f" {f.message}"
        if f.bucket == "not-needed" and f.bucket_reason:
            msg += f" Not needed for this app: {f.bucket_reason}"
        elif f.bucket in _SOFT_BUCKETS and f.bucket_reason:
            msg += f" {f.bucket_reason}"
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": _uri(f.location.path or "."), "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, int(f.location.line or 1))},
            }
        }
        if f.location.snippet:
            location["physicalLocation"]["region"]["snippet"] = {"text": _shown(f.location.snippet)}
        res = {
            "ruleId": f.rule.id,
            "ruleIndex": index[f.rule.id],
            "level": "note" if f.bucket == "not-needed" else LEVEL.get(sev, "warning"),
            "message": {"text": _shown(msg)},
            "locations": [location],
            "partialFingerprints": {"masaudit/v1": f.fingerprint()},
            "properties": {
                "security-severity": f"{SECURITY_SEVERITY.get(sev, 5.0):.1f}",
                "bucket": f.bucket,
                "scope": f.scope,
            },
        }
        if f.status == "suppressed":
            res["suppressions"] = [{"kind": "inSource", "status": "accepted",
                                    "justification": _shown(f.suppression_reason)}]
        elif f.status == "baselined":
            res["suppressions"] = [{"kind": "external", "status": "accepted",
                                    "justification": _shown(f"Listed in the masaudit baseline file: {f.suppression_reason}"
                                                            if f.suppression_reason
                                                            else "Listed in the masaudit baseline file.")}]
        results.append(res)

    when = report_datetime().strftime("%Y-%m-%dT%H:%M:%SZ")
    invocation: dict = {"executionSuccessful": True, "endTimeUtc": when}
    config_notes = [{
        "descriptor": {"id": "masaudit/app-type"},
        "level": "warning",
        "message": {"text": w.summary()},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": _uri(w.path)}}}],
    } for w in result.profile.warnings]
    excluded = excluded_line(result.project)
    if excluded:
        config_notes.append({"descriptor": {"id": "masaudit/excluded"}, "level": "note",
                             "message": {"text": _shown(excluded)}})
    if config_notes:
        invocation["toolConfigurationNotifications"] = config_notes
    # One notification per reason a file wasn't read: an incomplete scan says so in the SARIF too.
    by_reason: "OrderedDict[str, List[str]]" = OrderedDict()
    for path, why in getattr(result.project, "skipped", []):
        by_reason.setdefault(why, []).append(path)
    if by_reason:
        invocation["toolExecutionNotifications"] = [{
            "descriptor": {"id": "masaudit/not-scanned"},
            "level": "warning",
            "message": {"text": _shown(f"Not scanned ({why}): {len(paths)} file{'s' if len(paths) != 1 else ''}, "
                                       f"such as {', '.join(paths[:3])}.")},
        } for why, paths in by_reason.items()]
    run = {
        "tool": {
            "driver": {
                "name": "masaudit",
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": REPO_URL,
                "rules": [_rule_entry(rules[rid], worst[rid]) for rid in rule_ids],
            }
        },
        "invocations": [invocation],
        "columnKind": "unicodeCodePoints",
        "results": results,
        "properties": {
            "profile": result.profile.app_type,
            "masProfiles": list(result.profile.mas_profiles),
            "rulesVersion": result.rules_version,
        },
    }
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}


def render(result, include_not_needed: bool = False) -> str:
    return json.dumps(to_dict(result, include_not_needed), indent=2, ensure_ascii=False) + "\n"
