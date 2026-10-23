# SPDX-License-Identifier: Apache-2.0
"""SARIF 2.1.0 output for GitHub code scanning and other SARIF viewers."""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from typing import Dict, List

from masaudit import REPO_URL, __version__
from masaudit.model import SEVERITY_RANK, Finding, Rule
from masaudit.report.jsonout import report_datetime, sort_key

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SECURITY_SEVERITY = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 1.0}
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def rule_name(rule: Rule) -> str:
    words = re.findall(r"[A-Za-z0-9]+", rule.title)
    name = "".join(w[:1].upper() + w[1:] for w in words)
    return name or re.sub(r"[^A-Za-z0-9]", "", rule.id)


def _uri(path: str) -> str:
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/") or "."


def _rule_entry(rule: Rule, severity: str) -> dict:
    ids = [i for i in (rule.maswe, rule.masvs) if i]
    help_text = f"Why: {rule.why}\nFix: {rule.fix}\nVerify: {rule.verify}\nBook: {rule.book} {rule.book_url}".strip()
    md = [f"**Why it matters:** {rule.why}", "", f"**Fix:** {rule.fix}", ""]
    if rule.fix_code and rule.fix_code.get("code"):
        lang = re.sub(r"[^A-Za-z0-9_+-]", "", rule.fix_code.get("lang", ""))
        md += [f"```{lang}", rule.fix_code["code"].rstrip(), "```", ""]
    md += [f"**How to verify:** {rule.verify}", ""]
    if rule.book_url:
        md.append(f"Book: [{rule.book}]({rule.book_url})")
    entry = {
        "id": rule.id,
        "name": rule_name(rule),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.why},
        "help": {"text": help_text, "markdown": "\n".join(md)},
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
        sev = f.effective_severity or f.rule.severity
        if f.bucket == "not-needed":
            sev = "info"
        prev = worst.get(f.rule.id)
        if prev is None or SEVERITY_RANK.get(sev, 9) < SEVERITY_RANK.get(prev, 9):
            worst[f.rule.id] = sev
        rules[f.rule.id] = f.rule
    rule_ids = list(worst)
    index = {rid: i for i, rid in enumerate(rule_ids)}

    results = []
    for f in findings:
        sev = "info" if f.bucket == "not-needed" else (f.effective_severity or f.rule.severity)
        msg = f"{f.rule.title}."
        if f.message:
            msg += f" {f.message}"
        if f.bucket == "not-needed" and f.bucket_reason:
            msg += f" Not needed for this app: {f.bucket_reason}"
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": _uri(f.location.path or "."), "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, int(f.location.line or 1))},
            }
        }
        if f.location.snippet:
            location["physicalLocation"]["region"]["snippet"] = {"text": f.location.snippet}
        res = {
            "ruleId": f.rule.id,
            "ruleIndex": index[f.rule.id],
            "level": "note" if f.bucket == "not-needed" else LEVEL.get(sev, "warning"),
            "message": {"text": msg},
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
                                    "justification": f.suppression_reason}]
        elif f.status == "baselined":
            res["suppressions"] = [{"kind": "external", "status": "accepted",
                                    "justification": "Listed in the masaudit baseline file."}]
        results.append(res)

    platforms = "-".join(result.project.platforms) or "none"
    when = report_datetime().strftime("%Y-%m-%dT%H:%M:%SZ")
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
        "automationDetails": {"id": f"masaudit/{platforms}"},
        "invocations": [{"executionSuccessful": True, "endTimeUtc": when}],
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
