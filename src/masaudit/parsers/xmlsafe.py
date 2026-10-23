# SPDX-License-Identifier: Apache-2.0
"""Safe XML parsing with line numbers.

ElementTree loses line numbers, so we parse with expat directly and record the start line
of every element. Documents that declare a DTD or entities are refused (no entity tricks).
"""

from __future__ import annotations

import xml.parsers.expat
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional

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
        stack.pop()

    def chars(data: str) -> None:
        if stack:
            stack[-1].text += data

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    try:
        parser.Parse(text, True)
    except xml.parsers.expat.ExpatError:
        return None
    return root[0] if root else None


def is_true(value: Optional[str]) -> bool:
    return (value or "").strip().lower() == "true"
