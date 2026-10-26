# SPDX-License-Identifier: Apache-2.0
"""Run rules against a project and calibrate the results to the app's profile.

Two kinds of rule:
  * detector rules: a Python function registered by name, e.g. @detector("android_cleartext"); used for
    structured files (manifest, plist, pbxproj, workflows) and anything needing logic.
  * pattern rules: a declarative regex in rules/*.json, run on code after comments are
    blanked by the lexer, with a cheap literal prefilter.
"""

from __future__ import annotations

import bisect
import json
import os
import re
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from masaudit import lexer, safety
from masaudit.detect import scope_of
from masaudit.model import SEVERITIES, SEVERITY_RANK, Finding, Location, Profile, Project, Rule, a_type


@dataclass
class Hit:
    path: str
    line: int = 0
    snippet: str = ""
    message: str = ""
    scope: str = ""          # set by a detector that knows better than the path (e.g. "debug" under #if DEBUG)
    acknowledged: str = ""   # how the source marks it intentional, e.g. "tools:ignore=AcceptsUserCertificates"
    severity: str = ""       # this hit's own severity when it differs from the rule's (e.g. a same-org action)


DetectorFn = Callable[["Context", Rule], Iterable[Hit]]
_DETECTORS: Dict[str, DetectorFn] = {}


def detector(rule_id: str) -> Callable[[DetectorFn], DetectorFn]:
    def register(fn: DetectorFn) -> DetectorFn:
        if rule_id in _DETECTORS:
            raise ValueError(f"detector for {rule_id} registered twice")
        _DETECTORS[rule_id] = fn
        return fn

    return register


# Non-ASCII characters an IGNORECASE regex matches to an ASCII letter although str.lower() maps them elsewhere
# (checked over every code point on Python 3.9 and 3.14). Context.lower() folds them before lower-casing.
_FOLD_TO_ASCII = {0x130: "i", 0x131: "i", 0x17F: "s"}


class Context:
    """What a detector can see. Caches file reads; never touches files outside the root."""

    def __init__(self, project: Project, profile: Optional[Profile] = None):
        self.project = project
        self.root = project.root
        self.profile = profile
        self.current_rule: Optional[str] = None
        self._text: Dict[str, Optional[str]] = {}
        self._stripped: Dict[tuple, str] = {}
        self._previews: Dict[str, List[Tuple[int, int]]] = {}
        self._lower: Dict[str, str] = {}
        self._listing: Dict[tuple, List[str]] = {}
        self._all_names: Optional[tuple] = None
        self.names_complete = True          # set by all_names(): False when the name listing hit its cap
        self._listing_of: Optional[tuple] = None
        self._lines: Dict[str, List[str]] = {}
        # id(text) -> (text, offsets of its newlines once a second lookup asks for them); a few recent texts.
        self._newlines: "OrderedDict[int, tuple]" = OrderedDict()

    def all_names(self, links: bool = False, excluded: bool = False) -> List[str]:
        """Every file in the project, not only the scanned types: names, never contents (safety.walk_names).
        Symbolic links are left out unless `links`. The config's `exclude` globs apply unless `excluded`:
        a rule that reports a file honors them; one that only asks whether a file exists (a lockfile, a
        privacy manifest) shouldn't report it missing because its folder isn't scanned."""
        if self._all_names is None:
            from masaudit import config
            names, linked, complete = safety.walk_names(self.root)
            self.names_complete = complete
            if not complete:
                self.note_unknown(f"The file listing stopped after {safety.MAX_FILES:,} names, so rules that look "
                                  "for a file by name (keystores, keys, lockfiles, privacy manifests) saw only part "
                                  "of the project.")
            exclude = self.project.exclude
            kept = [n for n in names if not config.is_excluded(n, exclude)] if exclude else names
            self._all_names = (names, kept, linked)
        names, kept, linked = self._all_names
        out = names if excluded else kept
        return out if links else [n for n in out if n not in linked]

    def files(self, *suffixes: str, name: Optional[str] = None) -> List[str]:
        # Detectors ask for the same few listings hundreds of times; filter the project once per listing.
        # The cache is dropped if the project's file list is replaced or grows.
        files = self.project.files
        if self._listing_of != (id(files), len(files)):
            self._listing = {}
            self._listing_of = (id(files), len(files))
        key = (suffixes, name)
        cached = self._listing.get(key)
        if cached is None:
            cached = []
            for f in files:
                base = f.rsplit("/", 1)[-1]
                if name is not None and base != name:
                    continue
                if suffixes and not f.endswith(suffixes):
                    continue
                cached.append(f)
            self._listing[key] = cached
        return list(cached)

    def lower(self, path: str) -> Optional[str]:
        """The file text lower-cased for case-insensitive substring prefilters, with the three characters
        that a case-insensitive regex matches to an ASCII letter but str.lower() doesn't map to one
        (U+0130 and U+0131 match `i`, U+017F matches `s`) folded first. So a lower-case ASCII needle that
        an `(?i)` pattern's match must contain is always found in it."""
        if path not in self._lower:
            text = self.text(path)
            if text is None:
                return None
            if not text.isascii() and ("\u0130" in text or "\u0131" in text or "\u017f" in text):
                text = text.translate(_FOLD_TO_ASCII)
            self._lower[path] = text.lower()
        return self._lower[path]

    def text(self, path: str) -> Optional[str]:
        if path not in self._text:
            text = safety.read_text(self.root, path)
            # Detectors see one line ending. Files committed with CRLF (common from Windows) would
            # otherwise leave a `\r` before every `$` in a pattern.
            if text is not None and "\r" in text:
                text = text.replace("\r\n", "\n").replace("\r", "\n")
            self._text[path] = text
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
        # Counting newlines from the start is a pass over the text per call: a file with thousands of hits
        # made that quadratic. From the second call on the same long text, its newline offsets are kept
        # and a binary search gives the same count.
        if len(text) < 8192 or not 0 <= index <= len(text):
            return text.count("\n", 0, index) + 1
        key = id(text)
        entry = self._newlines.get(key)
        if entry is None or entry[0] is not text:
            self._newlines[key] = (text, None)
            if len(self._newlines) > 8:
                self._newlines.popitem(last=False)
            return text.count("\n", 0, index) + 1
        offsets = entry[1]
        if offsets is None:
            offsets = []
            i = text.find("\n")
            while i >= 0:
                offsets.append(i)
                i = text.find("\n", i + 1)
            self._newlines[key] = (text, offsets)
        self._newlines.move_to_end(key)
        return bisect.bisect_left(offsets, index) + 1

    def snippet(self, path: str, line: int) -> str:
        lines = self._lines.get(path)
        if lines is None:
            lines = self._lines[path] = safety.lines(self.text(path) or "")   # once per file, not per hit
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

PLATFORM_OF_RULE = {"android": "android", "ios": "ios", "kmp": "kmp", "ci": "ci", "flutter": "flutter",
                    "react-native": "react-native"}
# Platforms whose source code the cross-platform rules read.
CODE_PLATFORMS = {"android", "ios", "kmp", "flutter", "react-native"}


def applies_to_platforms(rule: Rule, platforms) -> bool:
    """Whether a rule can run on a project with these platforms."""
    platforms = set(platforms)
    if rule.platform == "ci":
        # Workflow rules find nothing without workflows; repo-hygiene CI rules (committed
        # signing keys, wrapper checksum, lockfiles) matter in any mobile repository.
        return bool(platforms & ({"ci"} | CODE_PLATFORMS))
    needed = PLATFORM_OF_RULE.get(rule.platform)
    if needed and needed not in platforms:
        return False
    return not (rule.platform == "cross" and not platforms & CODE_PLATFORMS)


MAX_HITS_PER_FILE = 50


def run(project: Project, rules: List[Rule], profile: Optional[Profile] = None) -> List[Finding]:
    _import_detectors()
    ctx = Context(project, profile)
    findings: List[Finding] = []
    for rule in rules:
        if rule.retired:
            continue
        if not applies_to_platforms(rule, project.platforms):
            continue
        ctx.current_rule = rule.id
        if rule.detector:
            fn = _DETECTORS.get(rule.detector)
            if fn is None:
                raise ValueError(f"{rule.id}: detector '{rule.detector}' is not registered")
            hits = fn(ctx, rule)
        elif rule.pattern:
            hits = run_pattern(ctx, rule)
        else:
            continue
        per_file: Dict[str, int] = {}
        for h in hits:
            # A crafted or generated file can repeat one weakness thousands of times; list the first
            # few so the report and the SARIF upload stay usable, and say how many there were.
            per_file[h.path] = per_file.get(h.path, 0) + 1
            if per_file[h.path] > MAX_HITS_PER_FILE:
                continue
            findings.append(
                Finding(
                    rule=rule,
                    location=Location(path=h.path, line=h.line,
                                      snippet=safety.clean_text(safety.mask_names(h.snippet)),
                                      fingerprint_text=h.snippet),
                    message=safety.clean_text(h.message),
                    scope=h.scope or (_scope_at(ctx, h.path, h.line) if h.path else "main"),
                    acknowledged=h.acknowledged,
                    severity=h.severity,
                )
            )
        for path, n in per_file.items():
            if n > MAX_HITS_PER_FILE:
                ctx.note_unknown(f"{rule.id} matched {n:,} times in {path}; the report lists the first "
                                 f"{MAX_HITS_PER_FILE}.")
    return _dedupe(findings)


# Code that only runs in the IDE's preview pane: a Jetpack Compose function annotated @Preview (or a
# multi-preview annotation such as @PreviewLightDark, @ThemePreviews), a SwiftUI #Preview block, or a
# PreviewProvider. It compiles into the app but nothing calls it.
# Bounded throughout (annotations per function, spaces, argument length), so a file of thousands of
# annotations with no function after them costs a short attempt per annotation, not a pass to the end.
_KT_PREVIEW = re.compile(r"@\w{0,60}Preview\w{0,60}(?:\s{0,40}\((?:[^()]|\([^()]{0,200}\)){0,400}\))?"
                         r"(?:\s{0,40}@\w{1,60}(?:\s{0,40}\([^()]{0,300}\))?){0,8}\s{0,40}"
                         r"(?:(?:private|internal|public)\s{1,40})?fun\s{1,40}(?:<[^<>{}]{0,200}>\s{0,40})?\w{1,200}\s{0,40}\(")
_SWIFT_PREVIEW = re.compile(r"#Preview\b(?:\s*\([^()]*\))?\s*\{|\bstruct\s+\w+\s*:[^{]{0,300}?\bPreviewProvider\b[^{]{0,300}?\{")


def _preview_spans(blank: str, kotlin: bool) -> List[Tuple[int, int]]:
    """(start, end) offsets of the preview-only blocks in a Kotlin or Swift file (strings blanked)."""
    from masaudit.textscan import bracket_match
    spans: List[Tuple[int, int]] = []
    for m in (_KT_PREVIEW if kotlin else _SWIFT_PREVIEW).finditer(blank):
        at = m.end() - 1
        if kotlin:                                   # past the parameters and the return type, to `{` or `=`
            close = bracket_match(blank, at, "(", ")")
            body = re.compile(r"\s*(?::[^{=\n]*)?\s*([{=])").match(blank, close + 1)
            if not body:
                continue
            at = body.start(1)
        if blank[at] == "{":
            end = bracket_match(blank, at, "{", "}")
        else:                                        # `fun X() = expr`: to the end of that line
            nl = blank.find("\n", at)
            end = len(blank) if nl == -1 else nl
        spans.append((m.start(), min(end, len(blank))))
    return spans


def _preview_lines(ctx: Context, path: str) -> List[Tuple[int, int]]:
    """(first, last) lines of the preview-only blocks in a Kotlin or Swift file, once per file."""
    if path not in ctx._previews:
        blank = ctx.code(path, keep_strings=False) or ""
        spans = _preview_spans(blank, path.endswith(".kt")) if "Preview" in blank else []
        ctx._previews[path] = [(ctx.line_of(blank, a), ctx.line_of(blank, max(a, b - 1))) for a, b in spans]
    return ctx._previews[path]


def _scope_at(ctx: Context, path: str, line: int) -> str:
    """scope_of(path), or "debug" for a line inside a preview-only block of production code."""
    scope = scope_of(path)
    if scope == "main" and line > 0 and path.endswith((".kt", ".swift")):
        if any(a <= line <= b for a, b in _preview_lines(ctx, path)):
            return "debug"
    return scope


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
    names = {"android", "ios", "cross", "ci", "kmp", "flutter", "reactnative", "rn_storage", "rn_network",
             "rn_webview", "rn_platform", "rn_build", "rn_expo"}
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
            f.bucket_reason = rule.not_needed_reason or f"Not expected for {a_type(profile.app_type)} app."
            continue
        if not set(rule.profiles) & set(profile.mas_profiles):
            f.effective_severity = "info"
            f.bucket = "not-needed"
            wanted = "/".join(f"MAS-{p}" for p in rule.profiles)
            f.bucket_reason = rule.not_needed_reason or (
                f"This belongs to {wanted}, which {a_type(profile.app_type)} app doesn't need."
            )
            continue
        base = f.severity if f.severity in SEVERITY_RANK else rule.severity
        rank = SEVERITY_RANK[base] + SCOPE_DOWNGRADE.get(f.scope, 0) + (1 if f.acknowledged else 0)
        f.effective_severity = SEVERITIES[min(rank, len(SEVERITIES) - 1)]
        if f.effective_severity in ("critical", "high"):
            f.bucket = "fix-before-release"
        elif f.effective_severity in ("medium", "low"):
            f.bucket = "fix-soon"
        else:
            f.bucket = "notes"
        if f.scope in ("debug", "test"):
            f.bucket_reason = f"Lowered because it's in {f.scope} code."
        elif f.acknowledged:
            f.bucket_reason = (f"Lowered one level: the source marks this as intentional ({f.acknowledged}). "
                               "Confirm the reason is written down.")
        elif base != rule.severity:
            higher = SEVERITY_RANK[base] < SEVERITY_RANK[rule.severity]
            f.bucket_reason = (f"Rated {base} for this case ({'above' if higher else 'below'} the rule's usual "
                               f"{rule.severity}); the finding says why.")
    return findings
