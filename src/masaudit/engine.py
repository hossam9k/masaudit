# SPDX-License-Identifier: Apache-2.0
"""Run rules against a project and calibrate the results to the app's profile.

Two kinds of rule:
  * detector rules: a Python function registered by name, e.g. @detector("android_cleartext"); used for
    structured files (manifest, plist, pbxproj, workflows) and anything needing logic.
  * pattern rules: a declarative regex in rules/*.json, run on code after comments are
    blanked by the lexer, with a cheap literal prefilter.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional

from masaudit import lexer, safety
from masaudit.detect import scope_of
from masaudit.model import SEVERITIES, SEVERITY_RANK, Finding, Location, Profile, Project, Rule


@dataclass
class Hit:
    path: str
    line: int = 0
    snippet: str = ""
    message: str = ""


DetectorFn = Callable[["Context", Rule], Iterable[Hit]]
_DETECTORS: Dict[str, DetectorFn] = {}


def detector(rule_id: str) -> Callable[[DetectorFn], DetectorFn]:
    def register(fn: DetectorFn) -> DetectorFn:
        if rule_id in _DETECTORS:
            raise ValueError(f"detector for {rule_id} registered twice")
        _DETECTORS[rule_id] = fn
        return fn

    return register


class Context:
    """What a detector can see. Caches file reads; never touches files outside the root."""

    def __init__(self, project: Project, profile: Optional[Profile] = None):
        self.project = project
        self.root = project.root
        self.profile = profile
        self.current_rule: Optional[str] = None
        self._text: Dict[str, Optional[str]] = {}
        self._stripped: Dict[tuple, str] = {}

    def files(self, *suffixes: str, name: Optional[str] = None) -> List[str]:
        out = []
        for f in self.project.files:
            base = f.rsplit("/", 1)[-1]
            if name is not None and base != name:
                continue
            if suffixes and not f.endswith(suffixes):
                continue
            out.append(f)
        return out

    def text(self, path: str) -> Optional[str]:
        if path not in self._text:
            self._text[path] = safety.read_text(self.root, path)
        return self._text[path]

    def code(self, path: str, keep_strings: bool = True) -> Optional[str]:
        """File text with comments blanked (and optionally string contents blanked)."""
        key = (path, keep_strings)
        if key not in self._stripped:
            text = self.text(path)
            if text is None:
                return None
            lang = lexer.LANG_BY_SUFFIX.get(os.path.splitext(path)[1])
            self._stripped[key] = lexer.strip(text, lang, keep_strings) if lang else text
        return self._stripped[key]

    def line_of(self, text: str, index: int) -> int:
        return text.count("\n", 0, index) + 1

    def snippet(self, path: str, line: int) -> str:
        text = self.text(path) or ""
        lines = text.splitlines()
        if 1 <= line <= len(lines):
            return safety.mask(lines[line - 1])
        return ""

    def note_unknown(self, message: str) -> None:
        """Record something the scanner couldn't decide. The current rule is then never reported
        as "checked and held"; the report lists it under residual risk instead."""
        if message not in self.project.unknowns:
            self.project.unknowns.append(message)
        if self.current_rule and self.current_rule not in self.project.undecided:
            self.project.undecided[self.current_rule] = message


# ---------------------------------------------------------------------------- rules


def rules_data(name: str) -> bytes:
    """Read a file shipped in masaudit/rules/. pkgutil works inside a zipapp on every supported
    Python; importlib.resources can't list a zip's contents on Windows before Python 3.10."""
    import pkgutil

    data = pkgutil.get_data("masaudit.rules", name)
    if data is None:
        raise FileNotFoundError(f"masaudit/rules/{name} is missing from this installation")
    return data


def load_rules() -> List[Rule]:
    """Load every rule file listed in _meta.json (works from a zipapp too)."""
    rules: List[Rule] = []
    seen = set()
    meta = json.loads(rules_data("_meta.json").decode("utf-8"))
    for name in meta["rule_files"]:
        data = json.loads(rules_data(name).decode("utf-8"))
        for raw in data.get("rules", []):
            rule = Rule(**raw)
            if rule.id in seen:
                raise ValueError(f"duplicate rule id {rule.id} in {name}")
            if rule.severity not in SEVERITIES:
                raise ValueError(f"{rule.id}: unknown severity {rule.severity}")
            seen.add(rule.id)
            rules.append(rule)
    return rules


def rules_version() -> str:
    return json.loads(rules_data("_meta.json").decode("utf-8"))["rules_version"]


# ---------------------------------------------------------------------------- running

PLATFORM_OF_RULE = {"android": "android", "ios": "ios", "kmp": "kmp", "ci": "ci"}


def run(project: Project, rules: List[Rule], profile: Optional[Profile] = None) -> List[Finding]:
    _import_detectors()
    ctx = Context(project, profile)
    findings: List[Finding] = []
    for rule in rules:
        if rule.retired:
            continue
        needed = PLATFORM_OF_RULE.get(rule.platform)
        if rule.platform == "ci":
            # Workflow rules find nothing without workflows; repo-hygiene CI rules (committed
            # signing keys, wrapper checksum, lockfiles) matter in any mobile repository.
            if not (set(project.platforms) & {"ci", "android", "ios", "kmp"}):
                continue
        elif needed and needed not in project.platforms:
            continue
        if rule.platform == "cross" and not (set(project.platforms) & {"android", "ios", "kmp"}):
            continue
        ctx.current_rule = rule.id
        if rule.detector:
            fn = _DETECTORS.get(rule.detector)
            if fn is None:
                raise ValueError(f"{rule.id}: detector '{rule.detector}' is not registered")
            hits = list(fn(ctx, rule))
        elif rule.pattern:
            hits = list(run_pattern(ctx, rule))
        else:
            continue
        for h in hits:
            findings.append(
                Finding(
                    rule=rule,
                    location=Location(path=h.path, line=h.line, snippet=h.snippet),
                    message=h.message,
                    scope=scope_of(h.path) if h.path else "main",
                )
            )
    return _dedupe(findings)


def run_pattern(ctx: Context, rule: Rule) -> Iterable[Hit]:
    """Declarative pattern: {"suffixes": [...], "regex": "...", "prefilter": "...",
    "flags": "i", "strings": "keep" | "blank", "unless_file": "regex", "message": "..."}."""
    p = rule.pattern or {}
    flags = re.IGNORECASE if "i" in p.get("flags", "") else 0
    flags |= re.MULTILINE
    regex = re.compile(p["regex"], flags)
    unless = re.compile(p["unless_file"], flags) if p.get("unless_file") else None
    prefilter = p.get("prefilter")
    keep_strings = p.get("strings", "keep") == "keep"
    for path in ctx.files(*p.get("suffixes", [])):
        raw = ctx.text(path)
        if raw is None or (prefilter and prefilter not in raw):
            continue
        code = ctx.code(path, keep_strings=keep_strings)
        if code is None or (unless and unless.search(code)):
            continue
        for m in regex.finditer(code):
            line = ctx.line_of(code, m.start())
            yield Hit(path=path, line=line, snippet=ctx.snippet(path, line), message=p.get("message", ""))


def _dedupe(findings: List[Finding]) -> List[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.rule.id, f.location.path, f.location.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


_IMPORTED = False


def _import_detectors() -> None:
    global _IMPORTED
    if _IMPORTED:
        return
    import importlib
    import pkgutil

    import masaudit.detectors as pkg

    # Listing modules can fail inside a zipapp on old Pythons, so the known modules are always
    # imported, plus anything else that's discoverable.
    names = {"android", "ios", "cross", "ci", "kmp"}
    names |= {mod.name for mod in pkgutil.iter_modules(pkg.__path__)}
    for name in sorted(names):
        importlib.import_module(f"masaudit.detectors.{name}")
    _IMPORTED = True


# ---------------------------------------------------------------------------- calibration

SCOPE_DOWNGRADE = {"main": 0, "build-script": 0, "ci": 0, "unknown": 0, "debug": 2, "test": 4}


def calibrate(findings: List[Finding], profile: Profile) -> List[Finding]:
    """Decide severity and report bucket for this app. Never drops a finding."""
    for f in findings:
        rule = f.rule
        if rule.app_types is not None and profile.app_type not in rule.app_types:
            f.effective_severity = "info"
            f.bucket = "not-needed"
            f.bucket_reason = rule.not_needed_reason or f"Not expected for a {profile.app_type} app."
            continue
        if not set(rule.profiles) & set(profile.mas_profiles):
            f.effective_severity = "info"
            f.bucket = "not-needed"
            wanted = "/".join(f"MAS-{p}" for p in rule.profiles)
            f.bucket_reason = rule.not_needed_reason or (
                f"This belongs to {wanted}, which a {profile.app_type} app doesn't need."
            )
            continue
        rank = SEVERITY_RANK[rule.severity] + SCOPE_DOWNGRADE.get(f.scope, 0)
        f.effective_severity = SEVERITIES[min(rank, len(SEVERITIES) - 1)]
        if f.effective_severity in ("critical", "high"):
            f.bucket = "fix-before-release"
        elif f.effective_severity in ("medium", "low"):
            f.bucket = "fix-soon"
        else:
            f.bucket = "notes"
        if f.scope in ("debug", "test"):
            f.bucket_reason = f"Lowered because it's in {f.scope} code."
    return findings
