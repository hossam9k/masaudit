# SPDX-License-Identifier: Apache-2.0
"""Safe XML parsing with line numbers.

ElementTree loses line numbers, so we parse with expat directly and record the start line
of every element. Documents that declare a DTD or entities are refused (no entity tricks).
"""

from __future__ import annotations

import re
import xml.parsers.expat
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

from masaudit import safety

ANDROID_NS = "http://schemas.android.com/apk/res/android"
TOOLS_NS = "http://schemas.android.com/tools"
_SEP = "}"


@dataclass
class Element:
    tag: str                                  # local name, e.g. "application"
    attrs: Dict[str, str]                     # "android:exported", "tools:node", or plain names
    line: int
    children: List["Element"] = field(default_factory=list)
    parent: Optional["Element"] = None
    text: str = ""
    end_line: int = 0                         # line of the end tag (or of `/>`); 0 if unknown
    # Only on the root: every XML comment as (first line, last line, text, alone on its line), so a
    # finding can quote the rationale written next to a Lint `tools:ignore`.
    comments: List[Tuple[int, int, str, bool]] = field(default_factory=list)

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return self.attrs.get(name, default)

    def iter(self, tag: Optional[str] = None) -> Iterator["Element"]:
        if tag is None or self.tag == tag:
            yield self
        for c in self.children:
            yield from c.iter(tag)

    def find(self, tag: str) -> Optional["Element"]:
        return next((e for e in self.iter(tag) if e is not self), None)


_PREFIX = {ANDROID_NS: "android", TOOLS_NS: "tools"}


def parse(text: str) -> Optional[Element]:
    """Parse XML text. Returns the root element, or None if invalid or it declares entities."""
    if safety.reject_xml_entities(text):
        return None
    parser = xml.parsers.expat.ParserCreate(namespace_separator=_SEP)
    stack: List[Element] = []
    root: List[Element] = []

    def name_of(qname: str) -> str:
        if _SEP in qname:
            ns, local = qname.split(_SEP, 1)
            prefix = _PREFIX.get(ns)
            return f"{prefix}:{local}" if prefix else local
        return qname

    def start(tag: str, attrs: Dict[str, str]) -> None:
        local = tag.split(_SEP, 1)[-1]        # element names: local name only
        el = Element(tag=local,
                     attrs={name_of(k): v for k, v in attrs.items()},
                     line=parser.CurrentLineNumber)
        if stack:
            el.parent = stack[-1]
            stack[-1].children.append(el)
        else:
            root.append(el)
        stack.append(el)

    def end(_tag: str) -> None:
        stack.pop().end_line = parser.CurrentLineNumber

    def chars(data: str) -> None:
        if stack:
            stack[-1].text += data

    comments: List[Tuple[int, int, str, bool]] = []
    text_lines: List[str] = []

    def comment(data: str) -> None:
        if not text_lines:
            text_lines.extend(text.splitlines() or [""])
        start_line = parser.CurrentLineNumber
        line = text_lines[start_line - 1] if 0 < start_line <= len(text_lines) else ""
        alone = not line[:parser.CurrentColumnNumber].strip()
        comments.append((start_line, start_line + data.count("\n"), data, alone))

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    parser.CommentHandler = comment
    try:
        parser.Parse(text, True)
    except xml.parsers.expat.ExpatError:
        return None
    if not root:
        return None
    root[0].comments = comments
    return root[0]


def is_true(value: Optional[str]) -> bool:
    return (value or "").strip().lower() == "true"


# ---------------------------------------------------------------------------- Android Lint acknowledgements


def lint_ignored(el: Element, *issue_ids: str) -> Optional[Element]:
    """The element (el or an ancestor) whose `tools:ignore` names one of issue_ids or "all".

    Android Lint applies `tools:ignore` to an element and everything inside it.
    """
    wanted = {i.lower() for i in issue_ids} | {"all"}
    node: Optional[Element] = el
    while node is not None:
        ids = {s.strip().lower() for s in (node.get("tools:ignore") or "").split(",") if s.strip()}
        if ids & wanted:
            return node
        node = node.parent
    return None


_NOT_A_REASON = re.compile(r"(?i)copyright|licen[cs]e|SPDX|apache|\bGPL\b")


def comment_near(el: Element) -> str:
    """The XML comment written next to `el`: one on its own line ending in the 3 lines above it, or one
    that starts inside the element (a trailing comment, or one before its first child) before the next
    element. A comment after the element's end tag belongs to what follows. Empty if there is none."""
    root = el
    while root.parent is not None:
        root = root.parent
    if not root.comments:
        return ""
    lines = [e.line for e in root.iter()]
    later = [n for n in lines if n > el.line]
    next_line = min(later) if later else el.line + 1
    if el.end_line >= el.line:
        next_line = min(next_line, el.end_line + 1)
    best = ""
    best_gap = None
    for first, last, text, alone in root.comments:
        text = " ".join(text.split())
        if not text or len(text) > 300 or _NOT_A_REASON.search(text):
            continue
        if el.line - 3 <= last < el.line and alone:
            gap = el.line - last
        elif el.line <= first < next_line:
            gap = 0
        else:
            continue
        if best_gap is None or gap < best_gap:
            best, best_gap = text, gap
    return best


def ack_text(el: Element, *issue_ids: str) -> str:
    """'tools:ignore=X — <comment>' when Lint is told to ignore one of issue_ids here, else ''."""
    node = lint_ignored(el, *issue_ids)
    if node is None:
        return ""
    ids = [s.strip() for s in (node.get("tools:ignore") or "").split(",") if s.strip()]
    named = [i for i in ids if i.lower() in {x.lower() for x in issue_ids} | {"all"}]
    reason = comment_near(el) or (comment_near(node) if node is not el else "")
    text = "tools:ignore=" + ",".join(named)
    return f"{text} \u2014 {reason}" if reason else text
