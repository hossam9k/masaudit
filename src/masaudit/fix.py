# SPDX-License-Identifier: Apache-2.0
"""Safe, mechanical fixes for a small set of vetted rules.

v1 has one: AND-002 (release build is debuggable). The fix removes `android:debuggable="true"`
from AndroidManifest.xml files outside src/debug with a minimal text edit: every other byte,
including CRLF line endings, indentation, and comments, is kept. The result is re-parsed;
if it doesn't parse, the file is left alone. Gradle files are never edited: those hits are
reported as suggestions.
"""

from __future__ import annotations

import difflib
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from masaudit import safety
from masaudit.model import Finding
from masaudit.parsers import xmlsafe

DEBUGGABLE_RULE = "AND-002"
SAFE_FIX_RULES = {DEBUGGABLE_RULE}

_ATTR = re.compile(r"""android:debuggable\s*=\s*(["'])\s*true\s*\1""", re.IGNORECASE)
_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_CDATA = re.compile(r"<!\[CDATA\[.*?\]\]>", re.DOTALL)


@dataclass
class FileFix:
    path: str              # repo-relative
    rule_id: str
    old: str
    new: str


@dataclass
class FixPlan:
    fixes: List[FileFix] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------- the edit


def _blocked_ranges(text: str) -> List[Tuple[int, int]]:
    return [m.span() for m in _COMMENT.finditer(text)] + [m.span() for m in _CDATA.finditer(text)]


def _in_application_tag(text: str, pos: int, blocked: List[Tuple[int, int]]) -> bool:
    """True if `pos` sits inside an `<application ...>` start tag."""
    lt = pos
    while True:
        lt = text.rfind("<", 0, lt)
        if lt == -1:
            return False
        if not any(a <= lt < b for a, b in blocked):
            break
    if text.find(">", lt, pos) != -1:
        return False
    return re.match(r"<\s*application[\s/>]", text[lt:]) is not None


def remove_debuggable(text: str) -> str:
    """Return `text` without `android:debuggable="true"` on <application>. Idempotent."""
    out = text
    while True:
        blocked = _blocked_ranges(out)
        target = None
        for m in _ATTR.finditer(out):
            if any(a <= m.start() < b for a, b in blocked):
                continue
            if not _in_application_tag(out, m.start(), blocked):
                continue
            target = m
            break
        if target is None:
            return out
        out = _cut(out, target.start(), target.end())


def _cut(text: str, start: int, end: int) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    nl = text.find("\n", end)
    line_end = len(text) if nl == -1 else nl
    if line_end > 0 and text[line_end - 1:line_end] == "\r" and nl != -1:
        line_end -= 1                                  # keep the "\r\n" pair together
    before = text[line_start:start]
    after = text[end:line_end]
    if not before.strip() and not after.strip():
        # The attribute is alone on its line: drop the line and its line ending.
        stop = len(text) if nl == -1 else nl + 1
        if nl == -1 and line_start > 0:
            # Last line without a newline: remove the preceding line ending instead.
            prev = line_start - 1
            if prev > 0 and text[prev - 1] == "\r":
                prev -= 1
            return text[:prev] + text[stop:]
        return text[:line_start] + text[stop:]
    if not before.strip():
        stripped_after = after.lstrip(" \t")
        if stripped_after.startswith((">", "/>")):
            # `android:debuggable="true">` on its own line: attach `>` to the previous line.
            ws = start
            while ws > 0 and text[ws - 1] in " \t\r\n":
                ws -= 1
            gap = text[end:end + (len(after) - len(stripped_after))]
            return text[:ws] + gap + text[end + len(gap):]
        # Other attributes follow on the same line: remove the attribute and the spaces after it.
        stop = end + (len(after) - len(stripped_after))
        return text[:start] + text[stop:]
    # Something precedes it on the line: remove the attribute and the spaces before it.
    ws = start
    while ws > line_start and text[ws - 1] in " \t":
        ws -= 1
    return text[:ws] + text[end:]


# ---------------------------------------------------------------------------- planning


def _is_debug_path(path: str) -> bool:
    return "/src/debug/" in "/" + path.replace("\\", "/")


def _read_utf8(root: str, rel: str) -> Optional[str]:
    data = safety.read_bytes(root, rel)
    if data is None:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def plan(root: str, findings: List[Finding]) -> FixPlan:
    """Work out the safe fixes for these findings. Changes nothing on disk."""
    result = FixPlan()
    manifests: Dict[str, str] = {}
    for f in findings:
        if f.rule.id not in SAFE_FIX_RULES or not f.rule.safe_fix or f.status == "suppressed":
            continue
        path = f.location.path
        where = f"{path}:{f.location.line}" if f.location.line else path
        if path.endswith((".gradle", ".gradle.kts")):
            result.suggestions.append(
                f"{where}: set `debuggable false` (Groovy) or `isDebuggable = false` (Kotlin DSL) "
                "in the release build type. masaudit never edits Gradle files."
            )
            continue
        if path.rsplit("/", 1)[-1] != "AndroidManifest.xml":
            result.suggestions.append(f"{where}: remove the debuggable flag by hand.")
            continue
        if _is_debug_path(path):
            result.skipped.append(f"{path}: left alone (debug-only manifest).")
            continue
        manifests.setdefault(path, f.rule.id)
    for path, rule_id in sorted(manifests.items()):
        old = _read_utf8(root, path)
        if old is None:
            result.skipped.append(f"{path}: couldn't read it as UTF-8, left alone.")
            continue
        parse_text = old[1:] if old.startswith("﻿") else old
        if xmlsafe.parse(parse_text) is None:
            result.skipped.append(f"{path}: couldn't parse it safely, left alone.")
            continue
        new = remove_debuggable(old)
        if new == old:
            continue
        new_parse = new[1:] if new.startswith("﻿") else new
        root_el = xmlsafe.parse(new_parse)
        if root_el is None or any(xmlsafe.is_true(a.get("android:debuggable")) for a in root_el.iter("application")):
            result.skipped.append(f"{path}: the edit didn't produce clean XML, left alone.")
            continue
        result.fixes.append(FileFix(path=path, rule_id=rule_id, old=old, new=new))
    return result


# ---------------------------------------------------------------------------- output


def unified_diff(fixes: List[FileFix]) -> str:
    chunks: List[str] = []
    for fx in fixes:
        a = fx.old.splitlines(keepends=True)
        b = fx.new.splitlines(keepends=True)
        lines = list(difflib.unified_diff(a, b, fromfile=f"a/{fx.path}", tofile=f"b/{fx.path}"))
        for line in lines:
            if line.endswith("\n"):
                chunks.append(line)
            else:
                chunks.append(line + "\n\\ No newline at end of file\n")
    return "".join(chunks)


def apply(root: str, fixes: List[FileFix]) -> List[str]:
    """Write the fixes in place. Skips a file that changed since it was read. Returns written paths."""
    written = []
    for fx in fixes:
        full = os.path.join(root, fx.path)
        if not safety.is_within(root, full) or os.path.islink(full):
            continue
        current = _read_utf8(root, fx.path)
        if current != fx.old:
            continue
        with open(full, "w", encoding="utf-8", newline="") as fh:
            fh.write(fx.new)
        written.append(fx.path)
    return written
