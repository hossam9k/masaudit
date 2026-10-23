# SPDX-License-Identifier: Apache-2.0
"""Import SARIF from other scanners (Android Lint, mobsfscan, Semgrep, zizmor).

Known rule IDs map to the matching masaudit rule when one exists, so the advice, book link,
and calibration are masaudit's. Anything else becomes an "imported" finding whose severity
comes from the source tool's level; it is calibrated like every other finding. Text from the
SARIF file is untrusted: it is masked, shortened to one line, and never executed.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from masaudit import safety
from masaudit.detect import scope_of
from masaudit.model import Finding, Location, Rule

MAX_SARIF_BYTES = 50 * 1024 * 1024
MAX_RESULTS = 20000


class SarifImportError(Exception):
    pass


# external id (lowercase) -> (platform, masaudit id, title regex fallback)
# Every entry names its rule explicitly: a title regex alone once matched "backup" to the backup-pin
# rule. Tool checks with no masaudit equivalent (e.g. Lint's SetJavaScriptEnabled) stay unmapped and
# are imported as the tool's own finding.
MAPPING: Dict[str, Tuple[str, Optional[str], str]] = {
    # Android Lint
    "trustallx509trustmanager": ("android", "AND-005", r"trust ?manager"),
    "badhostnameverifier": ("android", "AND-005", r"hostname"),
    "hardcodeddebugmode": ("android", "AND-002", r"debuggable"),
    "mutableimplicitpendingintent": ("android", "AND-018", r"pending ?intent"),
    "exportedcontentprovider": ("android", "AND-015", r"exported component"),
    "exportedservice": ("android", "AND-015", r"exported component"),
    "allowbackup": ("android", "AND-021", r"^backup is on"),
    "insecurebaseconfiguration": ("android", "AND-001", r"cleartext|plain http"),
    "unsafeintentlaunch": ("android", "AND-017", r"intent it received"),
    # zizmor
    "unpinned-uses": ("ci", "CI-001", r"commit sha"),
    "excessive-permissions": ("ci", "CI-002", r"token permissions"),
    "artipacked": ("ci", "CI-005", r"token on disk"),
    "template-injection": ("ci", "CI-004", r"pasted into a run script"),
    "dangerous-triggers": ("ci", "CI-003", r"pull_request_target"),
}

LEVEL_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}

TOOL_KEYS = [
    ("android lint", "android-lint", "android"),
    ("lint", "android-lint", "android"),
    ("mobsfscan", "mobsfscan", "cross"),
    ("semgrep", "semgrep", "cross"),
    ("zizmor", "zizmor", "ci"),
]


def _one_line(text: object, limit: int = 240) -> str:
    s = str(text or "")
    s = re.sub(r"[\x00-\x1f\x7f]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return safety.mask(s)[:limit]


def _tool_of(run: dict) -> Tuple[str, str, str]:
    driver = ((run.get("tool") or {}).get("driver") or {}) if isinstance(run.get("tool"), dict) else {}
    name = str(driver.get("name") or "unknown")
    low = name.lower()
    for needle, key, platform in TOOL_KEYS:
        if needle in low:
            return name, key, platform
    key = re.sub(r"[^a-z0-9]+", "-", low).strip("-") or "unknown"
    return name, key, "cross"


def _normalize_id(rule_id: str) -> str:
    rid = rule_id.strip()
    if rid.lower().startswith("zizmor/"):
        rid = rid[len("zizmor/"):]
    return rid.lower()


def _find_rule(ext_id: str, rules: List[Rule]) -> Optional[Rule]:
    entry = MAPPING.get(_normalize_id(ext_id))
    if entry is None:
        return None
    platform, explicit, title_re = entry
    live = [r for r in rules if not r.retired and r.platform == platform]
    if explicit:
        for r in live:
            if r.id == explicit:
                return r
    pattern = re.compile(title_re, re.IGNORECASE)
    for r in live:
        if pattern.search(r.title):
            return r
    return None


def _book() -> Tuple[str, str]:
    try:
        from masaudit.engine import rules_data

        sections = json.loads(rules_data("_book_sections.json").decode("utf-8"))
        return "Chapter 23", sections.get("Chapter 23", "")
    except Exception:  # pragma: no cover - packaging problem; fall back to the book root
        from masaudit import BOOK_URL

        return "Chapter 23", BOOK_URL


def _rel_path(uri: str, base: Optional[str], root: str) -> str:
    if base and not urlparse(uri).scheme:
        uri = base.rstrip("/") + "/" + uri
    parsed = urlparse(uri)
    if parsed.scheme == "file":
        local = unquote(parsed.path)
        if os.name == "nt" and re.match(r"^/[A-Za-z]:", local):
            local = local[1:]
        root_real = os.path.realpath(root)
        local_real = os.path.realpath(local)
        if local_real == root_real or local_real.startswith(root_real + os.sep):
            return os.path.relpath(local_real, root_real).replace(os.sep, "/")
        return local.replace(os.sep, "/")
    if parsed.scheme:
        return _one_line(uri, 300)
    path = unquote(uri).replace("\\", "/")
    path = posixpath.normpath(path) if path else path
    while path.startswith("./"):
        path = path[2:]
    return _one_line(path, 300)


def _severity_from(level: str, rule_meta: dict) -> str:
    props = rule_meta.get("properties") if isinstance(rule_meta.get("properties"), dict) else {}
    sev = props.get("security-severity") if props else None
    try:
        score = float(sev) if sev is not None else None
    except (TypeError, ValueError):
        score = None
    if score is not None:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
        return "info"
    severity = LEVEL_SEVERITY.get(level, "medium")
    tags = props.get("tags") if props else None
    if isinstance(tags, list) and tags and not any("secur" in str(t).lower() for t in tags):
        return "info"      # e.g. Android Lint performance/usability checks: keep them out of the way
    return severity


def import_sarif(path: str, root: str, rules: List[Rule]) -> Tuple[List[Finding], List[str]]:
    """Read one SARIF file. Returns (findings, notes). Raises SarifImportError on bad input."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise SarifImportError(f"can't read {path}: {exc}") from exc
    if size > MAX_SARIF_BYTES:
        raise SarifImportError(f"{path} is larger than {MAX_SARIF_BYTES // (1024 * 1024)} MiB")
    try:
        with open(path, encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise SarifImportError(f"{path} is not valid SARIF JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
        raise SarifImportError(f"{path} is not SARIF (no 'runs' list)")

    book, book_url = _book()
    findings: List[Finding] = []
    notes: List[str] = []
    synthetic: Dict[str, Rule] = {}
    skipped = 0
    for run in data["runs"]:
        if not isinstance(run, dict):
            skipped += 1
            continue
        tool_name, tool_key, tool_platform = _tool_of(run)
        driver = (run.get("tool") or {}).get("driver") or {}
        meta_list = driver.get("rules") if isinstance(driver.get("rules"), list) else []
        meta_by_id = {str(m.get("id")): m for m in meta_list if isinstance(m, dict) and m.get("id")}
        bases = {}
        if isinstance(run.get("originalUriBaseIds"), dict):
            for k, v in run["originalUriBaseIds"].items():
                if isinstance(v, dict) and isinstance(v.get("uri"), str):
                    bases[k] = v["uri"]
        results = run.get("results") if isinstance(run.get("results"), list) else []
        for res in results[:MAX_RESULTS]:
            try:
                finding = _one_result(res, root, rules, tool_name, tool_key, tool_platform,
                                      meta_list, meta_by_id, bases, synthetic, book, book_url)
            except (KeyError, TypeError, ValueError, AttributeError, IndexError):
                finding = None
            if finding is None:
                skipped += 1
                continue
            findings.append(finding)
    base = os.path.basename(path)
    if skipped:
        notes.append(f"Skipped {skipped} unreadable or suppressed result(s) in {base}.")
    notes.append(f"Imported {len(findings)} result(s) from {base}.")
    return findings, notes


def _one_result(res, root, rules, tool_name, tool_key, tool_platform, meta_list, meta_by_id,
                bases, synthetic, book, book_url) -> Optional[Finding]:
    if not isinstance(res, dict):
        return None
    if res.get("suppressions"):
        return None            # already accepted in the source tool
    ext_id = res.get("ruleId")
    if not ext_id and isinstance(res.get("rule"), dict):
        ext_id = res["rule"].get("id")
    idx = res.get("ruleIndex")
    if not ext_id and isinstance(idx, int) and 0 <= idx < len(meta_list):
        ext_id = meta_list[idx].get("id")
    if not ext_id:
        return None
    ext_id = _one_line(ext_id, 120)
    meta = meta_by_id.get(ext_id) or {}
    level = res.get("level")
    if not level:
        dc = meta.get("defaultConfiguration") if isinstance(meta, dict) else None
        level = (dc or {}).get("level") if isinstance(dc, dict) else None
    level = str(level or "warning").lower()
    if level == "none" and res.get("kind") in ("pass", "notApplicable"):
        return None

    rel, line, region_snippet = "", 0, ""
    locs = res.get("locations")
    if isinstance(locs, list) and locs and isinstance(locs[0], dict):
        phys = locs[0].get("physicalLocation") or {}
        art = phys.get("artifactLocation") or {}
        uri = art.get("uri")
        if isinstance(uri, str) and uri:
            base_id = art.get("uriBaseId")
            rel = _rel_path(uri, bases.get(base_id) if base_id else None, root)
        region = phys.get("region") or {}
        start = region.get("startLine")
        if isinstance(start, int) and start > 0:
            line = start
        snip = region.get("snippet")
        if isinstance(snip, dict) and isinstance(snip.get("text"), str):
            region_snippet = snip["text"].splitlines()[0] if snip["text"] else ""

    snippet = ""
    if rel and line:
        text = safety.read_text(root, rel) if not os.path.isabs(rel) else None
        if text is not None:
            lines = text.splitlines()
            if 1 <= line <= len(lines):
                snippet = safety.mask(lines[line - 1])
    if not snippet and region_snippet:
        snippet = _one_line(region_snippet, 160)

    msg = res.get("message")
    msg_text = _one_line(msg.get("text") if isinstance(msg, dict) else msg, 240)
    detail = f"Reported by {tool_name} ({ext_id})" + (f": {msg_text}" if msg_text else ".")

    rule = _find_rule(ext_id, rules)
    if rule is None:
        key = f"{tool_key}:{ext_id}"
        rule = synthetic.get(key)
        if rule is None:
            short = meta.get("shortDescription") if isinstance(meta, dict) else None
            title = _one_line((short or {}).get("text") if isinstance(short, dict) else "", 120) or ext_id
            help_obj = meta.get("help") if isinstance(meta, dict) else None
            help_text = _one_line((help_obj or {}).get("text") if isinstance(help_obj, dict) else "", 300)
            rule = Rule(
                id=key,
                title=f"{title} (from {tool_name})",
                platform=tool_platform,
                severity=_severity_from(level, meta if isinstance(meta, dict) else {}),
                profiles=["L1"],
                why=f"{tool_name} reported this with level '{level}'. masaudit has no matching rule, "
                    "so it keeps the source tool's severity.",
                fix=help_text or f"See the {tool_name} documentation for {ext_id}.",
                verify=f"Run {tool_name} again and confirm the result is gone.",
                effort="hours",
                book=book,
                book_url=book_url,
                confidence="medium",
            )
            synthetic[key] = rule
    return Finding(rule=rule, location=Location(path=rel, line=line, snippet=snippet),
                   message=detail, scope=scope_of(rel) if rel else "main")


def is_imported(finding: Finding) -> bool:
    return ":" in finding.rule.id
